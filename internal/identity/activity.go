package identity

// Observation-only census. Unlike Resolve, a partial census still exposes sockets
// and visible descriptor holders; it never grants an application permission.
import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ActivityProcess struct {
	BootID      string      `json:"boot_id,omitempty"`
	NetNS       string      `json:"netns,omitempty"`
	MountNS     string      `json:"mountns,omitempty"`
	PIDNS       string      `json:"pidns,omitempty"`
	ThreadGroup int         `json:"thread_group_pid,omitempty"`
	ID          string      `json:"id"`
	PID         int         `json:"pid"`
	Start       string      `json:"start_ticks"`
	UID         uint32      `json:"uid"`
	Executable  string      `json:"executable"`
	Application Application `json:"application"`
}
type ActivityRow struct {
	NetworkScope NetworkScope `json:"network_scope"`
	Initiation   Initiation   `json:"initiation"`
	// Display-only association; never consulted by Resolve or policy. Owners remain complete.
	DisplayApplication *Application `json:"display_application,omitempty"`
	OwnershipCategory  string       `json:"ownership_category"`
	ID                 string       `json:"id"`
	Ownership          string       `json:"ownership"`
	Traffic            Traffic      `json:"traffic"`
	Socket             Socket       `json:"socket"`
	Owners             []string     `json:"owners"`
	State              string       `json:"state"`
	Direction          string       `json:"direction"`
	Evidence           string       `json:"evidence"`
}
type ActivitySnapshot struct {
	UDP             *UDPSnapshot               `json:"udp,omitempty"`
	Sequence        uint64                     `json:"sequence"`
	Started         time.Time                  `json:"started"`
	Collected       time.Time                  `json:"collected"`
	DurationMS      int64                      `json:"duration_ms"`
	Complete        bool                       `json:"complete"`
	Issues          []string                   `json:"issues"`
	Error           string                     `json:"error,omitempty"`
	Rows            []ActivityRow              `json:"rows"`
	Processes       map[string]ActivityProcess `json:"processes"`
	Inaccessible    int                        `json:"inaccessible_processes"`
	OwnershipCounts map[string]int             `json:"ownership_counts"`
}
type cachedActivityProcess struct {
	process Process
	checked time.Time
}
type ActivityCollector struct {
	Zones       NetworkZones
	initiations map[string]initiationSample
	UDP         func() UDPSnapshot
	cache       map[int]cachedActivityProcess
	sequence    uint64
	traffic     map[string]trafficSample
}

func SocketState(s Socket) string {
	if s.Protocol == "udp" {
		if s.Remote.Port() != 0 && !s.Remote.Addr().IsUnspecified() {
			return "Connected UDP socket"
		}
		return "Bound/unconnected UDP socket"
	}
	states := map[uint8]string{1: "Established", 2: "Connecting (SYN sent)", 3: "SYN received", 4: "FIN wait 1", 5: "FIN wait 2", 6: "Time wait", 7: "Closed", 8: "Close wait", 9: "Last ACK", 10: "Listening", 11: "Closing", 12: "New SYN received"}
	if name, ok := states[s.State]; ok {
		return name
	}
	return fmt.Sprintf("Linux state %d", s.State)
}
func (c *ActivityCollector) inspect(pid int, now time.Time) (Process, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	start, _, err := processStat(base)
	if err != nil {
		return Process{}, err
	}
	old, ok := c.cache[pid]
	st, statErr := os.Stat(base)
	sameUID := statErr == nil && st.Sys().(*syscall.Stat_t).Uid == old.process.UID
	if ok && sameUID && old.process.NetNS == link(base+"/ns/net") && old.process.MountNS == link(base+"/ns/mnt") && old.process.Start == start && old.process.Executable == link(base+"/exe") && old.process.ExecutableRevision == stamp(base+"/exe") && now.Sub(old.checked) < 5*time.Second {
		return old.process, nil
	}
	p, err := Inspect(pid)
	if err == nil {
		// Detach retained values from bounded but potentially large proc buffers.
		// Oversized metadata is unidentified, never silently shortened into an identity.
		for _, field := range []*string{&p.Executable, &p.ExecutableRevision, &p.Start, &p.Cgroup, &p.NetNS, &p.MountNS, &p.Application.Key, &p.Application.Name, &p.Application.Executable, &p.Application.Revision, &p.Application.Runtime, &p.Application.Prefix, &p.Application.SteamAppID} {
			if len(*field) > 4096 {
				err = fmt.Errorf("process metadata field exceeds observation limit")
				break
			}
			*field = strings.Clone(*field)
		}
	}
	if err == nil {
		c.cache[pid] = cachedActivityProcess{p, now}
	} else {
		delete(c.cache, pid)
	}
	return p, err
}
func (c *ActivityCollector) Collect() ActivitySnapshot {
	c.sequence++
	out := ActivitySnapshot{Sequence: c.sequence, Started: time.Now(), Complete: true, Rows: []ActivityRow{}, Processes: map[string]ActivityProcess{}}
	finish := func() ActivitySnapshot {
		if c.UDP != nil {
			u := c.UDP()
			out.UDP = &u
		}
		for i := range out.Rows {
			out.Rows[i].NetworkScope = c.Zones.SocketScope(out.Rows[i].Socket)
		}
		c.directions(&out, out.Started)
		c.measure(&out, out.Started)
		if out.UDP != nil {
			out.UDP.Rows = nil
		} // expose health, not a duplicate cookie map
		out.Collected = time.Now()
		out.DurationMS = time.Since(out.Started).Milliseconds()
		return out
	}
	if c.cache == nil {
		c.cache = map[int]cachedActivityProcess{}
	}
	sockets, err := SocketsLimited(2048)
	if err != nil {
		out.Complete = false
		out.Issues = append(out.Issues, err.Error())
		if len(sockets) == 0 {
			out.Error = err.Error()
			return finish()
		}
	}
	sort.Slice(sockets, func(i, j int) bool { return sockets[i].Cookie < sockets[j].Cookie })
	wanted := map[string][]int{}
	for _, s := range sockets {
		id := activitySocketID(s)
		out.Rows = append(out.Rows, ActivityRow{ID: id, Socket: s, Owners: []string{}, State: SocketState(s), Direction: "Unknown", Ownership: "Unknown owner", Evidence: "Unknown owner: no descriptor holder found in this snapshot"})
		if s.Inode != 0 {
			key := fmt.Sprintf("socket:[%d]", s.Inode)
			wanted[key] = append(wanted[key], len(out.Rows)-1)
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		out.Error = err.Error()
		out.Complete = false
		out.Rows = nil
		return finish()
	}
	seen := map[int]bool{}
	fdCount := 0
	unreadableFDs := 0
	processCount := 0
	type target struct {
		pid, group int
		groupStart string
	}
	targets := []target{}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e == nil {
			if len(targets) == 8192 {
				out.Complete = false
				out.Issues = append(out.Issues, "Process census limit reached")
				break
			}
			targets = append(targets, target{pid: pid})
		}
	}
	for cursor := 0; cursor < len(targets); cursor++ {
		t := targets[cursor]
		pid := t.pid
		processCount++
		if processCount > 8192 || fdCount >= 131072 || time.Since(out.Started) > 2*time.Second {
			out.Complete = false
			out.Issues = append(out.Issues, "Process/descriptor/time census limit reached")
			break
		}
		base := fmt.Sprintf("/proc/%d", pid)
		if t.group != 0 {
			base = fmt.Sprintf("/proc/%d/task/%d", t.group, pid)
			groupStart, _, e := processStat(fmt.Sprintf("/proc/%d", t.group))
			if e != nil || groupStart != t.groupStart {
				out.Complete = false
				continue
			}
		}
		// A departed leader leaves /proc/TGID/fd empty and exe unavailable while
		// live workers still hold sockets. Enumerate only this evidenced case, not
		// every thread on the host. Use each worker's own start-time identity.
		if t.group == 0 && activityLeaderExited(base) {
			leaderStart, _, _ := processStat(base)
			f, e := os.Open(base + "/task")
			if e == nil {
				tasks, readErr := f.ReadDir(257)
				f.Close()
				if len(tasks) > 256 || (readErr != nil && readErr != io.EOF) {
					out.Complete = false
					out.Issues = append(out.Issues, "Exited-leader worker census incomplete")
				}
				for n, task := range tasks {
					if n >= 256 || len(targets) >= 8192 {
						out.Complete = false
						break
					}
					tid, e := strconv.Atoi(task.Name())
					if e == nil && tid != pid {
						targets = append(targets, target{pid: tid, group: pid, groupStart: leaderStart})
					}
				}
			} else {
				out.Complete = false
				out.Issues = append(out.Issues, "Exited-leader task directory inaccessible")
			}
			continue
		}
		// Open directories incrementally; do not allocate an arbitrary FD list.
		dir, err := os.Open(base + "/fd")
		if err != nil {
			if _, e := os.Stat(base); !os.IsNotExist(e) {
				out.Inaccessible++
			}
			continue
		}
		start, _, statErr := processStat(base)
		owned := map[int]string{}
		for fdCount < 131072 && time.Since(out.Started) < 2*time.Second {
			fds, e := dir.ReadDir(256)
			for _, fd := range fds {
				fdCount++
				target, linkErr := os.Readlink(base + "/fd/" + fd.Name())
				if linkErr != nil && !os.IsNotExist(linkErr) {
					unreadableFDs++
					out.Complete = false
				}
				for _, index := range wanted[target] {
					owned[index] = base + "/fd/" + fd.Name()
				}
			}
			if e != nil {
				if e != io.EOF && !os.IsNotExist(e) {
					out.Complete = false
					unreadableFDs++
				}
				break
			}
		}
		dir.Close()
		if fdCount >= 131072 || time.Since(out.Started) >= 2*time.Second {
			out.Complete = false
		}
		if len(owned) == 0 {
			continue
		}
		p, e := c.inspect(pid, out.Started)
		end, _, endErr := processStat(base)
		if t.group != 0 {
			groupStart, _, e := processStat(fmt.Sprintf("/proc/%d", t.group))
			if e != nil || groupStart != t.groupStart {
				endErr = fmt.Errorf("thread group generation changed")
			}
		}
		if statErr != nil || e != nil || endErr != nil || start != end || p.Start != start {
			out.Complete = false
			for index := range owned {
				row := &out.Rows[index]
				_, processErr := os.Stat(base)
				if (statErr == nil && endErr == nil && start != end) || os.IsNotExist(processErr) {
					row.Ownership = "Owner changed during inspection"
					row.Evidence = "Descriptor holder was observed, but process start/exit checks changed; no PID identity retained"
				} else if _, linkErr := os.Readlink(base + "/exe"); os.IsPermission(linkErr) {
					row.Ownership = "Owner inaccessible"
					row.Evidence = "Descriptor holder observed; executable access denied for this process"
				} else {
					row.Ownership = "Owner metadata unavailable"
					row.Evidence = "Descriptor holder observed; process identity could not be validated"
				}
			}
			continue
		}
		if len(out.Processes) >= 2048 {
			out.Complete = false
			out.Issues = append(out.Issues, "Process row limit reached")
			break
		}
		seen[pid] = true
		id := fmt.Sprintf("%d:%s", p.PID, p.Start)
		out.Processes[id] = ActivityProcess{BootID: p.BootID, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, ID: id, PID: p.PID, Start: p.Start, UID: p.UID, Executable: p.Executable, Application: p.Application, ThreadGroup: t.group}
		for index, path := range owned {
			row := &out.Rows[index]
			// Process inspection can race close/dup/FD reuse. Recheck the actual FD,
			// never authorize by a remembered inode or PID. This is still a snapshot.
			if !activityDescriptorMatches(path, row.Socket.Inode) {
				out.Complete = false
				row.Ownership = "Owner changed during inspection"
				row.Evidence = "Descriptor closed or changed after enumeration; no current association retained"
				continue
			}
			if len(row.Owners) >= 32 {
				out.Complete = false
				row.Evidence = "More than 32 visible holders; owner list truncated"
				continue
			}
			row.Owners = append(row.Owners, id)
		}
	}
	for pid := range c.cache {
		if !seen[pid] {
			delete(c.cache, pid)
		}
	}
	if unreadableFDs > 0 {
		out.Issues = append(out.Issues, fmt.Sprintf("%d descriptor reads inaccessible or interrupted", unreadableFDs))
	}
	if out.Inaccessible > 0 {
		out.Complete = false
		out.Issues = append(out.Issues, fmt.Sprintf("%d process descriptor directories inaccessible", out.Inaccessible))
	}
	for i := range out.Rows {
		row := &out.Rows[i]
		sort.Strings(row.Owners)
		if len(row.Owners) == 0 {
			if row.Socket.Inode == 0 {
				row.Ownership = "No userspace socket inode"
				row.Evidence = "Kernel diagnostic returned inode zero; no descriptor association is available (e.g. TCP TIME_WAIT)"
			} else if row.Ownership == "Unknown owner" && out.Inaccessible > 0 {
				row.Evidence += "; census includes inaccessible process directories, but this socket's owner cannot be identified"
			}
			if row.Socket.Inode != 0 {
				out.Complete = false
			}
			continue
		}
		if strings.Contains(row.Evidence, "truncated") {
			continue
		}
		if row.Ownership != "Unknown owner" {
			row.Evidence += "; additional visible holders listed, but ownership is incomplete"
			continue
		}
		row.Ownership = "Visible descriptor holder"
		row.Evidence = "Visible /proc descriptor holder; PID/start and executable revision checked. Snapshot is not atomic; unseen holders may exist."
		if len(row.Owners) > 1 {
			row.Ownership = "Shared socket"
			row.Evidence = "Shared socket: multiple visible descriptor holders; counted once, no exclusive application association"
		}
		for _, id := range row.Owners {
			if p := out.Processes[id]; p.ThreadGroup != 0 {
				row.Evidence += fmt.Sprintf(" Live worker TID %d in thread group %d after leader exit.", p.PID, p.ThreadGroup)
			}
		}
	}
	out.OwnershipCounts = map[string]int{}
	for i := range out.Rows {
		row := &out.Rows[i]
		row.OwnershipCategory = activityOwnershipCategory(*row)
		out.OwnershipCounts[row.OwnershipCategory]++
		row.DisplayApplication = activityDisplayApplication(*row, out.Processes)
		if row.DisplayApplication != nil && len(row.Owners) > 1 {
			row.Evidence += "; all observed holders share one native application key/revision/UID (display only; not exclusive authority)"
		}
		if len(row.Owners) == 0 && row.Socket.Inode != 0 && row.Socket.UID != uint32(os.Getuid()) {
			row.Evidence += "; socket creation UID differs from observer UID (not proof of current ownership)"
		}
	}
	if !out.Complete && len(out.Issues) == 0 {
		out.Issues = append(out.Issues, "Some sockets have no visible owner or processes changed during collection")
	}
	return finish()
}

// UDP endpoints may change through connect/disconnect while the socket survives.
func activitySocketID(s Socket) string {
	if s.Protocol == "udp" {
		return fmt.Sprintf("%s:%d:%s:%d:%s", s.NetNS, s.Family, s.Protocol, s.Inode, s.Cookie)
	}
	return fmt.Sprintf("%s:%d:%s:%d:%s:%s:%s", s.NetNS, s.Family, s.Protocol, s.Inode, s.Cookie, s.Local, s.Remote)
}
