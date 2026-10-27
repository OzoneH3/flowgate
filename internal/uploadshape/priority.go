package uploadshape

import (
	"flowgate/internal/identity"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const priorityLimit = 128

// PriorityProgress reports hint work, never complete coverage or authority.
type PriorityProgress struct {
	Version    uint64 `json:"version"`
	Inodes     int    `json:"hint_inodes"`
	Pending    int    `json:"pending_rows"`
	Attempts   int    `json:"attempts"`
	Incomplete bool   `json:"incomplete"`
	Reason     string `json:"reason,omitempty"`
	Millis     int64  `json:"hint_duration_ms"`
	Completed  bool   `json:"completed"`
}

type priorityHints struct {
	inodes map[uint32]bool
	view   PriorityProgress
}

// nativePriorityHints is deliberately only a cheap narrowing hint. In particular
// exe paths do not prove native identity, UID continuity or descriptor ownership.
// Every chosen socket still goes through ResolveBatch and the controller proof.
func nativePriorityHints(caps []Cap) priorityHints {
	start := time.Now()
	h := priorityHints{inodes: map[uint32]bool{}}
	wanted := map[string]bool{}
	for _, c := range caps {
		wanted[c.key()] = true
	}
	finish := func(reason string) priorityHints {
		h.view.Inodes = len(h.inodes)
		h.view.Millis = time.Since(start).Milliseconds()
		h.view.Incomplete = reason != ""
		h.view.Reason = reason
		return h
	}
	d, err := os.Open("/proc")
	if err != nil {
		return finish("process_observation_unavailable")
	}
	defer d.Close()
	processes, fds := 0, 0
	for {
		entries, err := d.ReadDir(64)
		for _, e := range entries {
			if time.Since(start) >= 250*time.Millisecond {
				return finish("hint_time_budget")
			}
			if _, er := strconv.Atoi(e.Name()); er != nil {
				continue
			}
			processes++
			if processes > 4096 {
				return finish("process_hint_capacity")
			}
			base := "/proc/" + e.Name()
			st, er := os.Stat(base)
			if er != nil {
				if !os.IsNotExist(er) {
					h.view.Reason = "process_observation_incomplete"
				}
				continue
			}
			uid := st.Sys().(*syscall.Stat_t).Uid
			exe, er := os.Readlink(base + "/exe")
			if er != nil {
				if !os.IsNotExist(er) {
					h.view.Reason = "process_observation_incomplete"
				}
				continue
			}
			key := identity.ApplicationKey(uid, identity.Application{Kind: "native", Executable: exe})
			if !wanted[strconv.FormatUint(uint64(uid), 10)+":"+key] {
				continue
			}
			fd, er := os.Open(base + "/fd")
			if er != nil {
				h.view.Incomplete = true
				h.view.Reason = "descriptor_observation_unavailable"
				continue
			}
			for {
				rows, re := fd.ReadDir(64)
				for _, row := range rows {
					if time.Since(start) >= 250*time.Millisecond {
						fd.Close()
						return finish("hint_time_budget")
					}
					fds++
					if fds > 16384 {
						fd.Close()
						return finish("descriptor_hint_capacity")
					}
					link, er := os.Readlink(base + "/fd/" + row.Name())
					if er != nil {
						if !os.IsNotExist(er) {
							h.view.Reason = "descriptor_observation_unavailable"
						}
						continue
					}
					if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
						n, er := strconv.ParseUint(link[8:len(link)-1], 10, 32)
						if er == nil && n != 0 {
							if len(h.inodes) >= priorityLimit && !h.inodes[uint32(n)] {
								fd.Close()
								return finish("inode_hint_capacity")
							}
							h.inodes[uint32(n)] = true
						}
					}
				}
				if re != nil {
					if re != io.EOF {
						h.view.Reason = "descriptor_observation_unavailable"
					}
					break
				}
			}
			fd.Close()
		}
		if err != nil {
			if err != io.EOF {
				return finish("process_observation_incomplete")
			}
			break
		}
	}
	return finish(h.view.Reason)
}

type priorityQueue struct {
	hints    priorityHints
	rows     []identity.Socket
	selected bool
}

func (p *priorityQueue) selectRows(d *discoverySnapshot) {
	if p.selected || d.view.Generation == 0 {
		return
	}
	p.selected = true
	matched := map[uint32]bool{}
	for _, s := range d.rows {
		if p.hints.inodes[s.Inode] && !matched[s.Inode] {
			matched[s.Inode] = true
			p.rows = append(p.rows, s)
			if len(p.rows) == priorityLimit {
				break
			}
		}
	}
	if len(p.rows) < len(p.hints.inodes) {
		p.hints.view.Incomplete = true
		p.hints.view.Reason = "snapshot_not_present"
	}
	p.hints.view.Pending = len(p.rows)
	p.hints.view.Completed = len(p.rows) == 0
}
func (p *priorityQueue) next() (identity.Socket, bool) {
	if len(p.rows) == 0 {
		return identity.Socket{}, false
	}
	s := p.rows[0]
	p.rows = p.rows[1:]
	p.hints.view.Pending = len(p.rows)
	p.hints.view.Attempts++
	p.hints.view.Completed = len(p.rows) == 0
	return s, true
}
func (m *Manager) publishPriority(p *priorityQueue) {
	m.mu.Lock()
	m.snap.Priority = p.hints.view
	m.mu.Unlock()
}
