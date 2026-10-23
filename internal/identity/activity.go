package identity

// Observation-only census. Unlike Resolve, a partial census still exposes sockets
// and visible descriptor holders; it never grants an application permission.
import (
	"fmt"
	"os"
	"sort"
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
	// Display-only launch provenance (captured at first sight, cached per PID+start).
	Provenance *Provenance `json:"provenance,omitempty"`
	// The running executable's own stamp (for an Electron app: the runtime's;
	// application.revision is the bundle's). Pins process-instance rules.
	ExecutableRevision string `json:"executable_revision,omitempty"`
}
type RuntimeApplication struct {
	Application Application   `json:"application"`
	UID         uint32        `json:"uid"`
	Evidence    TableEvidence `json:"evidence"`
}
type ActivityRow struct {
	// Per-socket snapshot witness; never a permission key. A process may also
	// hold other sockets through only its leader table.
	HolderWitness      string              `json:"holder_witness,omitempty"`
	RuntimeApplication *RuntimeApplication `json:"runtime_application,omitempty"`
	NetworkScope       NetworkScope        `json:"network_scope"`
	Initiation         Initiation          `json:"initiation"`
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
	TCPInitiation   *InitiationEvents          `json:"tcp_initiation,omitempty"`
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
	InitiationEvents func([]Socket) InitiationEvents
	Zones            NetworkZones
	initiations      map[string]initiationSample
	UDP              func() UDPSnapshot
	cache            map[int]cachedActivityProcess
	sequence         uint64
	traffic          map[string]trafficSample
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
		p.Provenance = CaptureProvenance(p)
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
		if c.InitiationEvents != nil {
			sockets := make([]Socket, 0, len(out.Rows))
			for _, r := range out.Rows {
				sockets = append(sockets, r.Socket)
			}
			ApplyInitiationEvents(&out, c.InitiationEvents(sockets))
		}
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
	seen := map[int]bool{}
	if len(wanted) > 0 {
		inodes := map[string]bool{}
		for key := range wanted {
			inodes[key] = true
		}
		census, resolved := resolveHolderIdentities(inodes,
			func(pid int) (Process, error) { return c.inspect(pid, out.Started) },
			func() { c.cache = map[int]cachedActivityProcess{} })
		if !resolved.Complete {
			out.Complete = false
			out.Issues = append(out.Issues, resolved.Issues...)
		}
		out.Inaccessible += census.Inaccessible
		for socket := range resolved.SocketIssues {
			for _, index := range wanted[socket] {
				out.Rows[index].Ownership = "Owner metadata unavailable"
				out.Rows[index].Evidence = "A visible holder could not be fully inspected or changed during collection; the listed owner set is incomplete"
			}
		}
		for socket, owners := range resolved.Owners {
			for _, p := range owners {
				if len(out.Processes) >= 2048 && !seen[p.PID] {
					out.Complete = false
					out.Issues = append(out.Issues, "Process row limit reached")
					continue
				}
				seen[p.PID] = true
				id := fmt.Sprintf("%d:%s", p.PID, p.Start)
				group := 0
				if p.ThreadGroup != p.PID {
					group = p.ThreadGroup
				}
				out.Processes[id] = ActivityProcess{BootID: p.BootID, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, ID: id, PID: p.PID, Start: p.Start, UID: p.UID, Executable: p.Executable, Application: p.Application, ThreadGroup: group, Provenance: p.Provenance, ExecutableRevision: p.ExecutableRevision}
				for _, index := range wanted[socket] {
					row := &out.Rows[index]
					if len(row.Owners) >= 32 {
						out.Complete = false
						row.Evidence = "More than 32 visible holders; owner list truncated"
						continue
					}
					row.Owners = append(row.Owners, id)
					if p.HolderWitness != "" {
						row.HolderWitness = p.HolderWitness
					}
				}
			}
		}
	}
	for pid := range c.cache {
		if !seen[pid] {
			delete(c.cache, pid)
		}
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
				row.Evidence += fmt.Sprintf(" Worker descriptor observed at TID %d in thread group %d.", p.PID, p.ThreadGroup)
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
