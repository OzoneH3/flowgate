package identity

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"
)

// AnnotateActivity batches all sockets of a broker, rather than repeatedly
// spending the refresh budget on the same first eight sockets. No association
// survives between snapshots. Admission still uses its independent census.
func (m *WineObservers) AnnotateActivity(s *ActivitySnapshot) {
	if !s.Complete {
		return
	}
	groups := map[string][]int{}
	for i, r := range s.Rows {
		if r.Socket.Protocol != "tcp" || (r.Socket.State != 1 && r.Socket.State != 2) {
			continue
		}
		for _, id := range r.Owners {
			p := s.Processes[id]
			if p.UID == m.options.UID && filepath.Base(p.Executable) == "wineserver" {
				groups[id] = append(groups[id], i)
			}
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// Rotate whole broker groups if the refresh budget cannot cover all of them.
	if len(keys) > 0 {
		n := int(s.Sequence % uint64(len(keys)))
		keys = append(keys[n:], keys[:n]...)
	}
	start := time.Now()
	for _, key := range keys {
		if time.Since(start) > time.Second {
			break
		}
		indices := groups[key]
		p := s.Processes[key]
		sessionKey := fmt.Sprintf("%d:%s:%s:%s", p.PID, p.Start, p.ExecutableRevision, p.Application.Prefix)
		m.mu.Lock()
		record := m.sessions[sessionKey]
		m.mu.Unlock()
		if record == nil {
			// Discovery/setup remains subject to the normal pinned-broker validation.
			row := s.Rows[indices[0]]
			m.TryResolve(Flow{NetNS: row.Socket.NetNS, Protocol: "tcp", Direction: "outgoing", Local: row.Socket.Local, Remote: row.Socket.Remote})
		}
		select {
		case m.census <- struct{}{}:
		default:
			continue
		}
		m.mu.Lock()
		record = m.sessions[sessionKey]
		if record == nil || record.closed || m.closed {
			m.mu.Unlock()
			<-m.census
			continue
		}
		select {
		case <-record.ready:
		default:
			m.mu.Unlock()
			<-m.census
			continue
		}
		record.pins++
		m.mu.Unlock()
		var result map[int]*RuntimeApplication
		if record.table != nil {
			result = record.table.activityBatch(s, indices, &record.broker)
		}
		retired := m.unpin(record)
		<-m.census
		if !retired {
			for i, a := range result {
				s.Rows[i].RuntimeApplication = a
			}
		}
	}
}

// A fresh runtime census on either side of a fresh, complete kernel FD census
// amortizes the expensive work across every socket in this broker (<=2048
// activity rows). Socket cookies and complete owner identities must also match
// the displayed snapshot and the final kernel socket census.
func (w *WineTable) activityBatch(s *ActivitySnapshot, indices []int, broker *Process) map[int]*RuntimeApplication {
	if !w.mu.TryLock() {
		return nil
	}
	defer w.mu.Unlock()
	if w.session == nil || !w.session.current() || !w.sameServer(broker) {
		return nil
	}
	first := map[int]tableSnapshot{}
	second := map[int]tableSnapshot{}
	for _, i := range indices {
		family := 4
		if s.Rows[i].Socket.Family == 10 {
			family = 6
		}
		if _, ok := first[family]; !ok {
			v, e := w.snapshotFamily("tcp", family)
			if e != nil {
				return nil
			}
			first[family] = v
		}
	}
	c := ActivityCollector{}
	fresh := c.Collect()
	if !fresh.Complete {
		return nil
	}
	for family := range first {
		v, e := w.snapshotFamily("tcp", family)
		if e != nil {
			return nil
		}
		second[family] = v
	}
	sockets, e := SocketsLimited(2048)
	if e != nil || !w.session.current() || !w.sameServer(broker) {
		return nil
	}
	// Image mapping evidence is shared only within this single fresh census.
	images := map[string]bool{}
	visible := func(b *Process, path, revision string) bool {
		key := path + "|" + revision
		if v, ok := images[key]; ok {
			return v
		}
		v := w.imageRevisionVisible(b, path, revision)
		images[key] = v
		return v
	}
	return w.annotateCensus(s, &fresh, sockets, indices, broker, first, second, visible)
}

func activityAttribution(s *ActivitySnapshot, r ActivityRow) Attribution {
	a := Attribution{Status: "unidentified", VisibilityComplete: s.Complete && len(r.Owners) > 0, Sockets: []Socket{r.Socket}}
	for _, id := range r.Owners {
		p, ok := s.Processes[id]
		if !ok {
			a.VisibilityComplete = false
			continue
		}
		a.Owners = append(a.Owners, Process{BootID: p.BootID, PIDNS: p.PIDNS, ThreadGroup: p.ThreadGroup, PID: p.PID, Start: p.Start, UID: p.UID, NetNS: p.NetNS, MountNS: p.MountNS, Executable: p.Executable, ExecutableRevision: p.ExecutableRevision, Application: p.Application, Provenance: p.Provenance})
	}
	return a
}

func (w *WineTable) annotateCensus(s, fresh *ActivitySnapshot, sockets []Socket, indices []int, broker *Process, first, second map[int]tableSnapshot, visible func(*Process, string, string) bool) map[int]*RuntimeApplication {
	result := map[int]*RuntimeApplication{}
	current := map[string]ActivityRow{}
	for _, r := range fresh.Rows {
		current[r.ID] = r
	}
	for _, i := range indices {
		row := s.Rows[i]
		now, ok := current[row.ID]
		if !ok {
			continue
		}
		a, again := activityAttribution(s, row), activityAttribution(fresh, now)
		f := Flow{NetNS: row.Socket.NetNS, Protocol: "tcp", Direction: "outgoing", Local: row.Socket.Local, Remote: row.Socket.Remote}
		if row.Socket.NetNS != broker.NetNS || !a.VisibilityComplete || !again.VisibilityComplete || !sameBrokerGeneration(*broker, a.Owners) || !sameBrokerGeneration(*broker, again.Owners) || broker.Application.Prefix != w.prefix {
			continue
		}
		if fingerprint(a.Owners, a.Sockets) != fingerprint(again.Owners, again.Sockets) || fingerprint(nil, receivers(sockets, f)) != fingerprint(nil, a.Sockets) {
			continue
		}
		valid := true
		for _, p := range again.Owners {
			if p.PID != broker.PID && (p.Application.Kind != "wine" || p.Application.Prefix != w.prefix || p.UID != broker.UID) {
				valid = false
			}
		}
		if !valid {
			continue
		}
		family := 4
		if row.Socket.Family == 10 {
			family = 6
		}
		if family == 6 && f.Local.Addr().Is4() && (row.Socket.V6Only == nil || *row.Socket.V6Only) {
			continue
		}
		before, ok1 := first[family]
		after, ok2 := second[family]
		if !ok1 || !ok2 {
			continue
		}
		rows, e := selectTableRows(before, f)
		if e != nil {
			continue
		}
		got := w.finishCensus(f, a, again, broker, before, after, rows, visible)
		if got.Status == "corroborated-runtime-table" && got.Application != nil && got.Table != nil {
			result[i] = &RuntimeApplication{Application: *got.Application, UID: got.Table.UID, Evidence: *got.Table}
		}
	}
	return result
}
