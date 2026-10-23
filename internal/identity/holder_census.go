package identity

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Descriptor-table holder census. Socket descriptors live in a task's file
// table, not in a process: workers that unshared CLONE_FILES keep private
// tables (visible only under /proc/TGID/task/TID/fd), and an exited thread-group
// leader leaves its group's surviving tables only under task/.
//
// This census reports every table that holds a wanted socket, with every task
// proven to use that table. It decides nothing else: no collapse, no
// representative, no identity, no authority. KCMP_FILES proves only that tasks
// share a file table, not that they share credentials, namespaces or identity;
// callers must inspect every member and then call Recheck.
//
// Cost: one kcmp per live task per distinct table already seen in its group
// (649 groups / 3,288 tasks on the reference host), plus one readlink per
// descriptor of each distinct table. Without kcmp (EPERM/ENOSYS) a group falls
// back to reading every task's table; holders are then Proven=false and tasks
// sharing one table appear as separate holders, so ambiguity is preserved.
// Every visible group is scanned; there is no early stop once sockets are found.

// Recheck validates a snapshot; it does not establish continuous ownership. A
// descriptor passed later (SCM_RIGHTS) without a visible topology change is not
// observed, so callers must not present a holder as a continuous owner.

// HolderMember is one task using a holder table, pinned by its start ticks.
type HolderMember struct {
	TID   int    `json:"tid"`
	Start string `json:"start_ticks"`
}

// Holder is one file table holding Socket ("socket:[inode]").
type Holder struct {
	TGID         int            `json:"thread_group_pid"`
	GroupStart   string         `json:"thread_group_start_ticks"`
	LeaderExited bool           `json:"leader_exited"`
	Proven       bool           `json:"table_sharing_proven"`
	Members      []HolderMember `json:"members"`
	Socket       string         `json:"socket"`
	FDPath       string         `json:"fd_path"`
}

type HolderCensus struct {
	Holders  []Holder
	Complete bool
	Issues   []string
	// Inaccessible counts thread groups whose /proc group, task or descriptor
	// entries were actually unreadable (not exits, limits or changes).
	Inaccessible int
	// SocketIssues names matched sockets omitted from Holders and why
	// (holder_limit, a failed post-scan recheck, or a failure after a match).
	// A socket absent here and from Holders had no observed holder.
	SocketIssues map[string][]string
	src          holderProc
	wanted       map[string]bool
	lim          holderLimits
	deadline     time.Time
	budget       *holderBudget
	groups       map[int]*holderGroup // every scanned group, with or without holders
}

type holderLimits struct {
	Groups, TasksPerGroup, Tasks, FDs, HoldersPerSocket, ClassesPerGroup int
	Time                                                                 time.Duration
}

var defaultHolderLimits = holderLimits{Groups: 8192, TasksPerGroup: 4096, Tasks: 16384, FDs: 131072, HoldersPerSocket: 32, ClassesPerGroup: 64, Time: 2 * time.Second}

// holderProc is the /proc surface; tests substitute a model of it.
type holderProc struct {
	groups    func() ([]int, error)
	tasks     func(tgid, max int) ([]int, error)
	stat      func(tgid, tid int) (start string, zombie bool, err error)
	fds       func(tgid, tid int, visit func(path, target string) bool) error
	readlink  func(path string) (string, error)
	sameFiles func(a, b int) (bool, error)
	now       func() time.Time
	deadline  time.Time // fixed at census start; bounds Recheck as well
}

func (p holderProc) late() bool { return !p.deadline.IsZero() && p.now().After(p.deadline) }

type holderTask struct {
	start  string
	zombie bool
	rep    int // class representative TID; 0 for zombies
}
type holderGroup struct {
	start        string
	leaderExited bool
	proven       bool
	tasks        map[int]holderTask
	paths        map[string]string // matched fd path -> socket
}

var errHolderGone = errors.New("task exited")

func holderGone(err error) bool {
	return errors.Is(err, errHolderGone) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// CensusHolders scans every visible thread group in this PID namespace.
func CensusHolders(wanted map[string]bool) HolderCensus {
	return procHolders().census(wanted, defaultHolderLimits)
}

// holderBudget charges full-table scans across initial scans, topology rescans
// and the one complete retry. Rechecks/identity reads also share its deadline.
type holderBudget struct {
	deadline   time.Time
	tasks, fds int
}

func (p holderProc) census(wanted map[string]bool, lim holderLimits) HolderCensus {
	return p.censusBudget(wanted, lim, &holderBudget{deadline: p.now().Add(lim.Time)})
}

func (p holderProc) censusBudget(wanted map[string]bool, lim holderLimits, budget *holderBudget) HolderCensus {
	p.deadline = budget.deadline
	c := HolderCensus{Complete: true, SocketIssues: map[string][]string{}, src: p, wanted: wanted, lim: lim, deadline: p.deadline, budget: budget, groups: map[int]*holderGroup{}}
	omitted := func(socket, code string) {
		if !slices.Contains(c.SocketIssues[socket], code) {
			c.SocketIssues[socket] = append(c.SocketIssues[socket], code)
		}
	}
	issue := func(code string) {
		c.Complete = false
		if !slices.Contains(c.Issues, code) {
			c.Issues = append(c.Issues, code)
		}
	}
	groups, err := p.groups()
	if err != nil {
		issue("group_list_unreadable")
		return c
	}
	if len(groups) > lim.Groups {
		issue("group_limit")
		return c
	}
	perSocket := map[string]int{}
	for _, tgid := range groups {
		if p.late() {
			issue("time_limit")
			break
		}
		g, code := p.scanStableGroup(tgid, wanted, lim, &budget.tasks, &budget.fds)
		stopAll := code == "stop" || code == "time_limit" // census-wide budget exhausted
		if code == "stop" {
			code = map[bool]string{true: "fd_limit", false: "task_limit"}[budget.fds >= lim.FDs]
		}
		if code != "" {
			issue(code)
			switch code {
			case "group_unreadable", "task_list_unreadable", "task_unreadable", "fd_table_unreadable":
				c.Inaccessible++
			}
			if g != nil {
				for _, socket := range g.paths {
					omitted(socket, code)
				}
			}
			if stopAll {
				break
			}
			continue
		}
		if g == nil {
			continue
		}
		c.groups[tgid] = g
		if len(g.paths) == 0 {
			continue
		}
		for _, h := range g.holders(tgid) {
			if perSocket[h.Socket]++; perSocket[h.Socket] > lim.HoldersPerSocket {
				issue("holder_limit")
				omitted(h.Socket, "holder_limit")
				continue
			}
			c.Holders = append(c.Holders, h)
		}
	}
	if p.late() {
		issue("time_limit")
	}
	slices.SortFunc(c.Holders, func(a, b Holder) int {
		if a.TGID != b.TGID {
			return a.TGID - b.TGID
		}
		if a.Members[0].TID != b.Members[0].TID {
			return a.Members[0].TID - b.Members[0].TID
		}
		return strings.Compare(a.Socket, b.Socket)
	})
	return c
}

// scanGroup returns nil, "" for a group that exited before inspection, or a
// bounded issue code. "stop" means a census-wide budget was exhausted.
func (p holderProc) scanGroup(tgid int, wanted map[string]bool, lim holderLimits, total, fdCount *int) (*holderGroup, string) {
	start, zombie, err := p.stat(tgid, tgid)
	if holderGone(err) {
		return nil, ""
	}
	if err != nil {
		return nil, "group_unreadable"
	}
	tids, err := p.tasks(tgid, lim.TasksPerGroup)
	if holderGone(err) {
		return nil, ""
	}
	if err != nil {
		return nil, "task_list_unreadable"
	}
	if len(tids) > lim.TasksPerGroup {
		return nil, "task_limit"
	}
	if *total += len(tids); *total > lim.Tasks {
		return nil, "stop"
	}
	g := &holderGroup{start: start, leaderExited: zombie, proven: true, tasks: map[int]holderTask{}, paths: map[string]string{}}
	// Leader first: its table is class 0 while it is alive.
	slices.SortFunc(tids, func(a, b int) int {
		if a == b {
			return 0
		}
		if a == tgid || b == tgid {
			return map[bool]int{true: -1, false: 1}[a == tgid]
		}
		return a - b
	})
	var live []int
	for _, tid := range tids {
		if p.late() {
			return nil, "time_limit"
		}
		s, z, err := p.stat(tgid, tid)
		if holderGone(err) {
			return nil, "membership_changed"
		}
		if err != nil {
			return nil, "task_unreadable"
		}
		if tid == tgid && z != zombie {
			return nil, "group_changed"
		}
		g.tasks[tid] = holderTask{start: s, zombie: z}
		if !z {
			live = append(live, tid)
		}
	}
	if !zombie && !slices.Contains(live, tgid) {
		return nil, "group_changed"
	}
	var reps []int
	for _, tid := range live {
		rep := 0
		if g.proven {
			for _, r := range reps {
				if p.late() {
					return nil, "time_limit"
				}
				same, err := p.sameFiles(r, tid)
				if holderGone(err) {
					return nil, "membership_changed"
				}
				if err != nil {
					g.proven = false // capability unavailable: every task is its own table
					break
				}
				if same {
					rep = r
					break
				}
			}
		}
		if !g.proven {
			reps = live
			for _, t := range live {
				task := g.tasks[t]
				task.rep = t
				g.tasks[t] = task
			}
			break
		}
		if rep == 0 {
			if len(reps) == lim.ClassesPerGroup {
				return nil, "class_limit"
			}
			reps = append(reps, tid)
			rep = tid
		}
		task := g.tasks[tid]
		task.rep = rep
		g.tasks[tid] = task
	}
	// The unproven fallback reads every live task's table; only the task and
	// descriptor budgets bound it.
	for _, rep := range reps {
		stopped, late := false, false
		err := p.fds(tgid, rep, func(path, target string) bool {
			if *fdCount++; *fdCount > lim.FDs {
				stopped = true
				return false
			}
			if *fdCount%256 == 0 && p.late() {
				late = true
				return false
			}
			if wanted[target] {
				g.paths[path] = target
			}
			return true
		})
		// Return the partial group so already matched sockets can be named.
		if late || p.late() {
			return g, "time_limit"
		}
		if stopped {
			return g, "stop"
		}
		if holderGone(err) {
			return g, "membership_changed"
		}
		if err != nil {
			return g, "fd_table_unreadable"
		}
	}
	return g, ""
}

// holders lists one Holder per (table, socket); members are every live task
// recorded as using that table, sorted by TID.
func (g *holderGroup) holders(tgid int) []Holder {
	var out []Holder
	seen := map[string]bool{}
	for path, socket := range g.paths {
		rep, err := strconv.Atoi(strings.Split(strings.TrimPrefix(path, fmt.Sprintf("/proc/%d/task/", tgid)), "/")[0])
		key := fmt.Sprint(rep, socket)
		if err != nil || seen[key] {
			continue
		}
		seen[key] = true
		h := Holder{TGID: tgid, GroupStart: g.start, LeaderExited: g.leaderExited, Proven: g.proven, Socket: socket, FDPath: path}
		for tid, t := range g.tasks {
			if !t.zombie && t.rep == rep {
				h.Members = append(h.Members, HolderMember{tid, t.start})
			}
		}
		slices.SortFunc(h.Members, func(a, b HolderMember) int { return a.TID - b.TID })
		out = append(out, h)
	}
	return out
}

// Recheck re-validates the census after the caller inspected members, within
// the census's fixed deadline. Groups with holders must be unchanged: group
// generation and leader state, exact task set and start times, proven table
// classes and every matched descriptor link. Groups that had no holder, and
// groups that appeared since, are rescanned when their topology differs; a
// rescan that finds a wanted socket or cannot complete refuses. Unrelated thread
// churn therefore does not refuse, but an unshare-and-acquire does. Descriptors
// passed later without a visible topology change remain a snapshot boundary.
func (c HolderCensus) Recheck() error {
	d := c.RecheckDetail()
	if d.Err != nil {
		return d.Err
	}
	groups := make([]int, 0, len(d.Groups))
	for group := range d.Groups {
		groups = append(groups, group)
	}
	slices.Sort(groups)
	if len(groups) > 0 {
		return errors.New(d.Groups[groups[0]])
	}
	if len(d.Appeared) > 0 {
		return errors.New("holder_appeared")
	}
	return nil
}

func (p holderProc) recheckGroup(tgid int, g *holderGroup) error {
	if err := p.sameTopology(tgid, g); err != nil {
		return err
	}
	checked := 0
	for path, socket := range g.paths {
		if checked%256 == 0 && p.late() {
			return errors.New("time_limit")
		}
		checked++
		target, err := p.readlink(path)
		if err != nil && !holderGone(err) {
			return errors.New("descriptor_unreadable")
		}
		if err != nil || target != socket {
			return errors.New("descriptor_changed")
		}
	}
	if p.late() {
		return errors.New("time_limit")
	}
	return nil
}

func (p holderProc) sameTopology(tgid int, g *holderGroup) error {
	start, zombie, err := p.stat(tgid, tgid)
	if err != nil && !holderGone(err) {
		return errors.New("group_unreadable")
	}
	if err != nil || start != g.start || zombie != g.leaderExited {
		return errors.New("group_changed")
	}
	tids, err := p.tasks(tgid, len(g.tasks))
	if err != nil && !holderGone(err) {
		return errors.New("task_list_unreadable")
	}
	if err != nil || len(tids) != len(g.tasks) {
		return errors.New("membership_changed")
	}
	for _, tid := range tids {
		if p.late() {
			return errors.New("time_limit")
		}
		old, ok := g.tasks[tid]
		if !ok {
			return errors.New("membership_changed")
		}
		s, z, err := p.stat(tgid, tid)
		if err != nil && !holderGone(err) {
			return errors.New("task_unreadable")
		}
		if err != nil || s != old.start || z != old.zombie {
			return errors.New("membership_changed")
		}
		if g.proven && !z && old.rep != tid {
			same, err := p.sameFiles(old.rep, tid)
			if err != nil && !holderGone(err) {
				return errors.New("table_unreadable")
			}
			if err != nil || !same {
				return errors.New("table_changed")
			}
		}
	}
	if g.proven {
		// Representatives must still be distinct tables (a split never merges,
		// but a replaced task could reuse a representative's TID).
		var reps []int
		for _, t := range g.tasks {
			if !t.zombie && !slices.Contains(reps, t.rep) {
				reps = append(reps, t.rep)
			}
		}
		for i := range reps {
			for j := i + 1; j < len(reps); j++ {
				if p.late() {
					return errors.New("time_limit")
				}
				same, err := p.sameFiles(reps[i], reps[j])
				if err != nil && !holderGone(err) {
					return errors.New("table_unreadable")
				}
				if err != nil || same {
					return errors.New("table_changed")
				}
			}
		}
	}
	return nil
}

// readFDTable visits every listed descriptor, including one that closed while
// listing (target ""), so the caller's descriptor budget and deadline count
// every attempt; a vanished entry never matches a wanted socket.
func readFDTable(base string, readlink func(string) (string, error), visit func(path, target string) bool) error {
	d, err := os.Open(base)
	if err != nil {
		return err
	}
	defer d.Close()
	for {
		entries, err := d.ReadDir(256)
		for _, e := range entries {
			path := base + "/" + e.Name()
			target, linkErr := readlink(path)
			if linkErr != nil && !os.IsNotExist(linkErr) {
				return linkErr
			}
			if !visit(path, target) {
				return nil
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func procHolders() holderProc {
	return holderProc{
		groups: func() ([]int, error) {
			entries, err := os.ReadDir("/proc")
			if err != nil {
				return nil, err
			}
			var out []int
			for _, e := range entries {
				if pid, err := strconv.Atoi(e.Name()); err == nil {
					out = append(out, pid)
				}
			}
			return out, nil
		},
		tasks: func(tgid, max int) ([]int, error) {
			f, err := os.Open(fmt.Sprintf("/proc/%d/task", tgid))
			if err != nil {
				return nil, err
			}
			defer f.Close()
			var out []int
			for len(out) <= max {
				entries, err := f.ReadDir(256)
				for _, e := range entries {
					if tid, err := strconv.Atoi(e.Name()); err == nil {
						out = append(out, tid)
					}
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, err
				}
			}
			return out, nil
		},
		stat: func(tgid, tid int) (string, bool, error) {
			b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/stat", tgid, tid))
			if err != nil {
				return "", false, err
			}
			s := string(b)
			i := strings.LastIndex(s, ") ")
			if i < 0 {
				return "", false, fmt.Errorf("task stat unavailable")
			}
			f := strings.Fields(s[i+2:])
			if len(f) < 20 {
				return "", false, fmt.Errorf("short task stat")
			}
			return f[19], f[0] == "Z", nil
		},
		fds: func(tgid, tid int, visit func(path, target string) bool) error {
			return readFDTable(fmt.Sprintf("/proc/%d/task/%d/fd", tgid, tid), os.Readlink, visit)
		},
		readlink: os.Readlink,
		sameFiles: func(a, b int) (bool, error) {
			r, _, errno := unix.Syscall6(unix.SYS_KCMP, uintptr(a), uintptr(b), 2 /* KCMP_FILES */, 0, 0, 0)
			if errno != 0 {
				return false, errno
			}
			return r == 0, nil
		},
		now: time.Now,
	}
}
