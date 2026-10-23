package identity

import (
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A model of /proc thread groups and their file tables; kcmp compares table ids.
type censusTask struct {
	start  string
	zombie bool
	table  int
}
type censusProc struct {
	groups  map[int]map[int]*censusTask
	tables  map[int]map[int]string
	kcmpErr error
	statErr map[int]error
	fdErr   map[int]error
	onFDs   func(tgid, tid int) // after the table was visited
	hidden  map[int]bool        // tasks omitted from task listings
	now     time.Time
	step    time.Duration
	// operation counts for the cost model
	kcmps, links, stats int
}

func (f *censusProc) task(tid int) *censusTask {
	for _, g := range f.groups {
		if t := g[tid]; t != nil {
			return t
		}
	}
	return nil
}
func (f *censusProc) proc() holderProc {
	return holderProc{
		groups: func() ([]int, error) {
			var out []int
			for tgid := range f.groups {
				out = append(out, tgid)
			}
			slices.Sort(out)
			return out, nil
		},
		tasks: func(tgid, max int) ([]int, error) {
			g, ok := f.groups[tgid]
			if !ok {
				return nil, fs.ErrNotExist
			}
			var out []int
			for tid := range g {
				if !f.hidden[tid] {
					out = append(out, tid)
				}
			}
			slices.Sort(out)
			return out, nil
		},
		stat: func(tgid, tid int) (string, bool, error) {
			f.stats++
			if err := f.statErr[tid]; err != nil {
				return "", false, err
			}
			t := f.groups[tgid][tid]
			if t == nil {
				return "", false, fs.ErrNotExist
			}
			return t.start, t.zombie, nil
		},
		fds: func(tgid, tid int, visit func(path, target string) bool) error {
			if err := f.fdErr[tid]; err != nil {
				return err
			}
			t := f.groups[tgid][tid]
			if t == nil {
				return fs.ErrNotExist
			}
			var fds []int
			for fd := range f.tables[t.table] {
				fds = append(fds, fd)
			}
			slices.Sort(fds)
			for _, fd := range fds {
				f.links++
				if !visit(fmt.Sprintf("/proc/%d/task/%d/fd/%d", tgid, tid, fd), f.tables[t.table][fd]) {
					return nil
				}
			}
			if f.onFDs != nil {
				f.onFDs(tgid, tid)
			}
			return nil
		},
		readlink: func(path string) (string, error) {
			var tgid, tid, fd int
			if _, err := fmt.Sscanf(path, "/proc/%d/task/%d/fd/%d", &tgid, &tid, &fd); err != nil {
				return "", err
			}
			t := f.groups[tgid][tid]
			if t == nil {
				return "", fs.ErrNotExist
			}
			target, ok := f.tables[t.table][fd]
			if !ok {
				return "", fs.ErrNotExist
			}
			return target, nil
		},
		sameFiles: func(a, b int) (bool, error) {
			f.kcmps++
			if f.kcmpErr != nil {
				return false, f.kcmpErr
			}
			ta, tb := f.task(a), f.task(b)
			if ta == nil || tb == nil {
				return false, syscall.ESRCH
			}
			return ta.table == tb.table, nil
		},
		now: func() time.Time { f.now = f.now.Add(f.step); return f.now },
	}
}

const s1, s2, s3 = "socket:[101]", "socket:[102]", "socket:[103]"

var censusWanted = map[string]bool{s1: true, s2: true, s3: true}

// Groups: 10 live leader sharing with two workers; 20 exited leader, shared
// workers; 30 exited leader, split tables both holding; 40 live leader whose
// private-table worker holds (D04); 50 one table shared by members whose
// credentials could differ (module must report both); 60 unrelated.
func holderFixture() *censusProc {
	return &censusProc{
		groups: map[int]map[int]*censusTask{
			10: {10: {"1000", false, 1}, 11: {"1001", false, 1}, 12: {"1002", false, 1}},
			20: {20: {"2000", true, 0}, 21: {"2001", false, 2}, 22: {"2002", false, 2}},
			30: {30: {"3000", true, 0}, 31: {"3001", false, 3}, 32: {"3002", false, 4}},
			40: {40: {"4000", false, 5}, 41: {"4001", false, 6}},
			50: {50: {"5000", false, 7}, 51: {"5001", false, 7}},
			60: {60: {"6000", false, 8}},
		},
		tables: map[int]map[int]string{
			1: {3: s1, 4: "pipe:[9]"}, 2: {5: s1}, 3: {6: s2}, 4: {6: s2},
			5: {3: "anon_inode:[eventfd]"}, 6: {7: s2}, 7: {3: s3}, 8: {3: "socket:[999]"},
		},
		statErr: map[int]error{}, fdErr: map[int]error{}, hidden: map[int]bool{}, now: time.Unix(0, 0),
	}
}

func holderMembers(h Holder) string {
	var out []string
	for _, m := range h.Members {
		out = append(out, fmt.Sprintf("%d@%s", m.TID, m.Start))
	}
	return strings.Join(out, ",")
}
func holderSummary(c HolderCensus) []string {
	var out []string
	for _, h := range c.Holders {
		out = append(out, fmt.Sprintf("%d %s exited=%v proven=%v [%s] %s", h.TGID, h.Socket, h.LeaderExited, h.Proven, holderMembers(h), h.GroupStart))
	}
	return out
}

func TestHolderCensusReportsEveryTableAndMember(t *testing.T) {
	f := holderFixture()
	c := f.proc().census(censusWanted, defaultHolderLimits)
	want := []string{
		"10 socket:[101] exited=false proven=true [10@1000,11@1001,12@1002] 1000",
		"20 socket:[101] exited=true proven=true [21@2001,22@2002] 2000",
		"30 socket:[102] exited=true proven=true [31@3001] 3000",
		"30 socket:[102] exited=true proven=true [32@3002] 3000",
		"40 socket:[102] exited=false proven=true [41@4001] 4000",
		"50 socket:[103] exited=false proven=true [50@5000,51@5001] 5000",
	}
	if !c.Complete || len(c.Issues) != 0 || !slices.Equal(holderSummary(c), want) {
		t.Fatalf("complete=%v issues=%v\n%s", c.Complete, c.Issues, strings.Join(holderSummary(c), "\n"))
	}
	if err := c.Recheck(); err != nil {
		t.Fatal(err)
	}
}

func TestHolderCensusWithoutKcmpKeepsAmbiguity(t *testing.T) {
	for _, errno := range []error{syscall.EPERM, syscall.ENOSYS} {
		f := holderFixture()
		f.kcmpErr = errno
		c := f.proc().census(censusWanted, defaultHolderLimits)
		var group10 []string
		for _, h := range c.Holders {
			if h.Proven {
				t.Fatalf("%v: sharing claimed without kcmp: %+v", errno, h)
			}
			if h.TGID == 10 {
				group10 = append(group10, holderMembers(h))
			}
		}
		// Every task's table is read; one shared table appears as three holders.
		if !c.Complete || !slices.Equal(group10, []string{"10@1000", "11@1001", "12@1002"}) || len(c.Holders) != 10 {
			t.Fatalf("%v: %v %v\n%s", errno, c.Complete, c.Issues, strings.Join(holderSummary(c), "\n"))
		}
		if err := c.Recheck(); err != nil {
			t.Fatal(errno, err)
		}
	}
}

func TestHolderCensusIncompleteNeverGuesses(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*censusProc, *holderLimits)
	}{
		{"kcmp target exited", "membership_changed", func(f *censusProc, _ *holderLimits) { f.kcmpErr = syscall.ESRCH }},
		{"fd table unreadable", "fd_table_unreadable", func(f *censusProc, _ *holderLimits) { f.fdErr[41] = syscall.EACCES }},
		{"leader table unreadable while worker readable", "fd_table_unreadable", func(f *censusProc, _ *holderLimits) { f.fdErr[10] = syscall.EACCES }},
		{"task stat unreadable", "task_unreadable", func(f *censusProc, _ *holderLimits) { f.statErr[31] = syscall.EACCES }},
		{"live leader missing from task list", "group_changed", func(f *censusProc, _ *holderLimits) { f.hidden[40] = true }},
		{"tasks per group", "task_limit", func(_ *censusProc, l *holderLimits) { l.TasksPerGroup = 2 }},
		{"total tasks", "task_limit", func(_ *censusProc, l *holderLimits) { l.Tasks = 4 }},
		{"descriptors", "fd_limit", func(_ *censusProc, l *holderLimits) { l.FDs = 1 }},
		{"classes per group", "class_limit", func(_ *censusProc, l *holderLimits) { l.ClassesPerGroup = 1 }},
		{"holders per socket", "holder_limit", func(_ *censusProc, l *holderLimits) { l.HoldersPerSocket = 1 }},
		{"time", "time_limit", func(f *censusProc, _ *holderLimits) { f.step = time.Second }},
		{"deadline inside a group scan", "time_limit", func(f *censusProc, l *holderLimits) {
			f.step = time.Millisecond
			l.Time = 5 * time.Millisecond
		}},
		{"groups", "group_limit", func(_ *censusProc, l *holderLimits) { l.Groups = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := holderFixture()
			lim := defaultHolderLimits
			tc.mutate(f, &lim)
			c := f.proc().census(censusWanted, lim)
			if c.Complete || !slices.Contains(c.Issues, tc.code) {
				t.Fatalf("complete=%v issues=%v", c.Complete, c.Issues)
			}
			if c.Recheck() == nil {
				t.Fatal("incomplete census rechecked as valid")
			}
		})
	}
}

func TestHolderCensusRecheckAfterInspection(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*censusProc)
	}{
		{"holder worker unshares", "table_changed", func(f *censusProc) {
			f.tables[11] = map[int]string{3: s1}
			f.groups[10][12].table = 11
		}},
		{"holder group gains a thread", "membership_changed", func(f *censusProc) { f.groups[10][13] = &censusTask{"1003", false, 1} }},
		{"holder TID reused", "membership_changed", func(f *censusProc) { f.groups[20][21].start = "9999" }},
		{"leader exits", "group_changed", func(f *censusProc) { f.groups[10][10].zombie = true }},
		{"group replaced", "group_changed", func(f *censusProc) { f.groups[40][40].start = "9999" }},
		{"descriptor changed", "descriptor_changed", func(f *censusProc) { f.tables[6][7] = "socket:[555]" }},
		{"non-holder unshares and acquires", "holder_appeared", func(f *censusProc) {
			f.groups[60][61] = &censusTask{"6001", false, 12}
			f.tables[12] = map[int]string{4: s1}
		}},
		{"new group holds wanted socket", "holder_appeared", func(f *censusProc) {
			f.groups[70] = map[int]*censusTask{70: {"7000", false, 13}}
			f.tables[13] = map[int]string{3: s2}
		}},
		{"changed group unreadable", "fd_table_unreadable", func(f *censusProc) {
			f.groups[60][61] = &censusTask{"6001", false, 14}
			f.tables[14] = map[int]string{}
			f.fdErr[61] = syscall.EACCES
		}},
		{"deadline", "time_limit", func(f *censusProc) { f.now = f.now.Add(time.Hour) }},
		{"deadline passes partway through recheck", "time_limit", func(f *censusProc) { f.step = 100 * time.Millisecond }},
		{"unrelated churn", "", func(f *censusProc) {
			f.groups[60][61] = &censusTask{"6001", false, 8}
			f.groups[71] = map[int]*censusTask{71: {"7100", false, 15}}
			f.tables[15] = map[int]string{3: "socket:[777]"}
		}},
		{"non-holder group exits", "", func(f *censusProc) { delete(f.groups, 60) }},
		{"transient unrelated churn stabilizes on bounded rescan", "", func(f *censusProc) {
			f.groups[60][61] = &censusTask{"6001", false, 8}
			f.onFDs = func(tgid, tid int) {
				if tgid == 60 {
					f.groups[60][62] = &censusTask{"6002", false, 8}
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := holderFixture()
			c := f.proc().census(censusWanted, defaultHolderLimits)
			if !c.Complete {
				t.Fatal(c.Issues)
			}
			tc.mutate(f)
			err := c.Recheck()
			if tc.code == "" && err != nil || tc.code != "" && (err == nil || err.Error() != tc.code) {
				t.Fatalf("want %q got %v", tc.code, err)
			}
		})
	}
}

// A topology change during the scan itself refuses the affected group.
func TestHolderCensusChangeDuringScan(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*censusProc)
	}{
		{"unshare after classification", "table_changed", func(f *censusProc) {
			f.tables[11] = map[int]string{3: s1}
			f.groups[10][12].table = 11
		}},
		{"new thread", "membership_changed", func(f *censusProc) { f.groups[10][13] = &censusTask{"1003", false, 1} }},
		{"descriptor closed", "descriptor_changed", func(f *censusProc) { delete(f.tables[1], 3) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := holderFixture()
			done := false
			f.onFDs = func(tgid, tid int) {
				if tgid == 10 && !done {
					done = true
					tc.mutate(f)
				}
			}
			c := f.proc().census(censusWanted, defaultHolderLimits)
			if c.Complete || !slices.Contains(c.Issues, tc.code) {
				t.Fatalf("complete=%v issues=%v", c.Complete, c.Issues)
			}
			for _, h := range c.Holders {
				if h.TGID == 10 {
					t.Fatal("changed group still reported", h)
				}
			}
		})
	}
}

// syntheticHost models the reference host: 650 thread groups, 3,300 tasks (228
// multithreaded groups), about 20k descriptors; every tenth multithreaded
// group has one worker with a private table. One wanted socket exists.
func syntheticHost() *censusProc {
	f := &censusProc{groups: map[int]map[int]*censusTask{}, tables: map[int]map[int]string{}, statErr: map[int]error{}, fdErr: map[int]error{}, hidden: map[int]bool{}, now: time.Unix(0, 0)}
	table, tid := 0, 100000
	newTable := func() int {
		table++
		f.tables[table] = map[int]string{}
		for fd := 0; fd < 30; fd++ {
			f.tables[table][fd] = fmt.Sprintf("pipe:[%d]", table*100+fd)
		}
		return table
	}
	for g := 1; g <= 650; g++ {
		tgid := g * 10
		tables := []int{newTable()}
		f.groups[tgid] = map[int]*censusTask{tgid: {fmt.Sprint(tgid), false, tables[0]}}
		threads := 0
		if g <= 228 {
			threads = 11
			if g <= 142 {
				threads = 12
			}
		}
		for i := 0; i < threads; i++ {
			tid++
			t := tables[0]
			if g%10 == 0 && i == 0 {
				t = newTable()
			}
			f.groups[tgid][tid] = &censusTask{fmt.Sprint(tid), false, t}
		}
	}
	f.tables[1][99] = s1
	return f
}

func benchmarkHolderCensus(b *testing.B, kcmpErr error) {
	f := syntheticHost()
	f.kcmpErr = kcmpErr
	p := f.proc()
	lim := defaultHolderLimits
	lim.Time = time.Hour
	var c HolderCensus
	for i := 0; i < b.N; i++ {
		f.kcmps, f.links, f.stats = 0, 0, 0
		c = p.census(map[string]bool{s1: true}, lim)
	}
	if !c.Complete || len(c.Holders) == 0 {
		b.Fatal(c.Issues)
	}
	b.ReportMetric(float64(f.kcmps), "kcmp/op")
	b.ReportMetric(float64(f.links), "readlink/op")
	b.ReportMetric(float64(f.stats), "stat/op")
	f.kcmps, f.links, f.stats = 0, 0, 0
	if err := c.Recheck(); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(f.kcmps), "recheck-kcmp")
	b.ReportMetric(float64(f.links), "recheck-readlink")
	b.ReportMetric(float64(f.stats), "recheck-stat")
}

// Module logic cost at host size with a model of /proc; real syscall cost is
// measured separately by TestHolderCensusSyscallCost.
func BenchmarkHolderCensusSyntheticHost(b *testing.B)     { benchmarkHolderCensus(b, nil) }
func BenchmarkHolderCensusSyntheticFallback(b *testing.B) { benchmarkHolderCensus(b, syscall.EPERM) }

// Opt-in: times the real primitives against this test process only (its own
// threads and descriptors), never a host scan.
func TestHolderCensusSyscallCost(t *testing.T) {
	if os.Getenv("FLOWGATE_HOLDER_COST") == "" {
		t.Skip("set FLOWGATE_HOLDER_COST=1")
	}
	p := procHolders()
	pid := os.Getpid()
	tids, err := p.tasks(pid, 4096)
	if err != nil || len(tids) < 2 {
		t.Fatal(tids, err)
	}
	const n = 20000
	timeIt := func(name string, op func(i int) error) {
		began := time.Now()
		for i := 0; i < n; i++ {
			if err := op(i); err != nil {
				t.Fatal(name, err)
			}
		}
		t.Logf("%s: %v/op", name, time.Since(began)/n)
	}
	timeIt("kcmp", func(i int) error { _, err := p.sameFiles(tids[0], tids[1+i%(len(tids)-1)]); return err })
	timeIt("task stat", func(i int) error { _, _, err := p.stat(pid, tids[i%len(tids)]); return err })
	timeIt("readlink", func(int) error { _, err := p.readlink(fmt.Sprintf("/proc/%d/task/%d/fd/1", pid, pid)); return err })
	timeIt("task list", func(int) error { _, err := p.tasks(pid, 4096); return err })
}

// Descriptors that vanish while listing still consume the budget and deadline.
func TestHolderCensusVanishedDescriptorsAreCounted(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 600; i++ {
		os.WriteFile(fmt.Sprintf("%s/%d", dir, i), nil, 0600)
	}
	visits := 0
	err := readFDTable(dir, func(string) (string, error) { return "", fs.ErrNotExist }, func(path, target string) bool {
		if target != "" {
			t.Fatal("vanished descriptor reported a target")
		}
		visits++
		return visits < 300
	})
	if err != nil || visits != 300 {
		t.Fatalf("visits=%d err=%v", visits, err)
	}
	if err := readFDTable(dir, func(string) (string, error) { return "", syscall.EACCES }, func(string, string) bool { return true }); err == nil {
		t.Fatal("unreadable descriptor hidden")
	}
}

// Activity needs truthful scoping: only actually unreadable groups count as
// inaccessible, and matched sockets that were omitted are named per socket.
func TestHolderCensusInaccessibleAndSocketIssues(t *testing.T) {
	f := holderFixture()
	f.fdErr[41] = syscall.EACCES  // group 40: unreadable private table
	f.statErr[31] = syscall.EPERM // group 30: unreadable task
	lim := defaultHolderLimits
	lim.HoldersPerSocket = 1 // s1 is held in groups 10 and 20
	c := f.proc().census(censusWanted, lim)
	if c.Complete || c.Inaccessible != 2 {
		t.Fatalf("complete=%v inaccessible=%d issues=%v", c.Complete, c.Inaccessible, c.Issues)
	}
	if !slices.Equal(c.SocketIssues[s1], []string{"holder_limit"}) || len(c.SocketIssues[s3]) != 0 {
		t.Fatalf("socket issues %v", c.SocketIssues)
	}
	// s3 (group 50) is unaffected and still reported; s2's holders were in the
	// unreadable groups, so it is neither reported nor falsely attributed.
	var sockets []string
	for _, h := range c.Holders {
		sockets = append(sockets, h.Socket)
	}
	if !slices.Contains(sockets, s3) || slices.Contains(sockets, s2) {
		t.Fatal(sockets)
	}

	// A failed post-scan recheck names the matched socket.
	f = holderFixture()
	done := false
	f.onFDs = func(tgid, tid int) {
		if tgid == 50 && !done {
			done = true
			delete(f.tables[7], 3)
		}
	}
	c = f.proc().census(censusWanted, defaultHolderLimits)
	if c.Inaccessible != 0 || !slices.Equal(c.SocketIssues[s3], []string{"descriptor_changed"}) {
		t.Fatalf("inaccessible=%d issues=%v", c.Inaccessible, c.SocketIssues)
	}
}

func TestHolderCensusDetailedFailureScopeAndChurn(t *testing.T) {
	f := holderFixture()
	c := f.proc().census(censusWanted, defaultHolderLimits)
	if !c.Complete {
		t.Fatal(c.Issues)
	}
	// Group10's holder membership changes; other holder groups remain valid.
	f.groups[10][13] = &censusTask{"1003", false, 1}
	d := c.RecheckDetail()
	if d.Err != nil || len(d.Groups) != 1 || d.Groups[10] == "" {
		t.Fatalf("failure leaked across groups: %+v", d)
	}
	// A new task in a distinct, nonholding table can be proven irrelevant by a
	// complete fresh scan. It is never added to the inspected holder set.
	f = holderFixture()
	c = f.proc().census(censusWanted, defaultHolderLimits)
	f.groups[10][13] = &censusTask{"1003", false, 99}
	f.tables[99] = map[int]string{7: "socket:[999]"}
	if d = c.RecheckDetail(); d.Err != nil || len(d.Groups) != 0 || len(d.Appeared) != 0 {
		t.Fatalf("nonholder churn refused: %+v", d)
	}
	f.tables[99][7] = s1
	if d = c.RecheckDetail(); d.Err != nil || d.Groups[10] == "" || !slices.Contains(d.Appeared, s1) {
		t.Fatalf("new holder omitted: %+v", d)
	}
}

func TestHolderCensusTransientUnrelatedExitDuringInitialScan(t *testing.T) {
	f := holderFixture()
	p := f.proc()
	original := p.stat
	done := false
	p.stat = func(tgid, tid int) (string, bool, error) {
		if tgid == 60 && tid == 61 && !done {
			done = true
			delete(f.groups[60], 61)
			return "", false, fs.ErrNotExist
		}
		return original(tgid, tid)
	}
	// A listed nonholding task disappears before inspection. The one fresh
	// retry must still inspect every surviving table of the same group generation.
	f.groups[60][61] = &censusTask{"6001", false, 8}
	c := p.census(censusWanted, defaultHolderLimits)
	if !c.Complete || !done {
		t.Fatalf("transient exit: complete=%v issues=%v", c.Complete, c.Issues)
	}
	if err := c.Recheck(); err != nil {
		t.Fatal(err)
	}
}

func TestHolderCensusRescanPreservesGenerationAndBounds(t *testing.T) {
	f := holderFixture()
	p := f.proc()
	original := p.stat
	once := false
	p.stat = func(tgid, tid int) (string, bool, error) {
		if tgid == 60 && tid == 61 && !once {
			once = true
			f.groups[60][60].start = "replacement"
			return "", false, fs.ErrNotExist
		}
		return original(tgid, tid)
	}
	f.groups[60][61] = &censusTask{"6001", false, 8}
	c := p.census(censusWanted, defaultHolderLimits)
	if c.Complete || !slices.Contains(c.Issues, "group_changed") {
		t.Fatalf("replacement accepted: %+v", c.Issues)
	}
}

func TestHolderCensusVanishedUnrelatedGroupDuringInitialScan(t *testing.T) {
	f := holderFixture()
	p := f.proc()
	original := p.fds
	p.fds = func(tgid, tid int, visit func(string, string) bool) error {
		err := original(tgid, tid, visit)
		if tgid == 60 {
			delete(f.groups, 60)
		}
		return err
	}
	c := p.census(censusWanted, defaultHolderLimits)
	if !c.Complete {
		t.Fatalf("unrelated exited group: %v", c.Issues)
	}
	if err := c.Recheck(); err != nil {
		t.Fatal(err)
	}
	// A disappearing group that already matched a target is never silently skipped.
	f = holderFixture()
	p = f.proc()
	original = p.fds
	p.fds = func(tgid, tid int, visit func(string, string) bool) error {
		err := original(tgid, tid, visit)
		if tgid == 10 {
			delete(f.groups, 10)
		}
		return err
	}
	c = p.census(censusWanted, defaultHolderLimits)
	if c.Complete || !slices.Contains(c.Issues, "group_changed") {
		t.Fatalf("targeted group exit not explicit: %v", c.Issues)
	}
}

func TestHolderCensusDeadlineDuringDescriptorRecheck(t *testing.T) {
	f := holderFixture()
	for fd := 1000; fd < 2000; fd++ {
		f.tables[1][fd] = s1
	}
	c := f.proc().census(censusWanted, defaultHolderLimits)
	if !c.Complete {
		t.Fatal(c.Issues)
	}
	p := c.src
	original := p.readlink
	reads := 0
	p.readlink = func(path string) (string, error) {
		reads++
		if reads == 10 {
			f.now = f.now.Add(time.Hour)
		}
		return original(path)
	}
	err := p.recheckGroup(10, c.groups[10])
	if err == nil || err.Error() != "time_limit" || reads > 256 {
		t.Fatalf("deadline not checked during FD loop: reads=%d err=%v", reads, err)
	}
}
