package identity

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"
)

// A protocol/family pair names one independent runtime owner table.
type activityTableKey struct {
	protocol string
	family   int
}

func activityTable(s Socket) activityTableKey {
	family := 4
	if s.Family == 10 {
		family = 6
	}
	return activityTableKey{s.Protocol, family}
}

// AnnotateActivity batches all sockets of a broker, rather than repeatedly
// spending the refresh budget on the same first eight sockets. No association
// is used as permission evidence. Admission still uses its independent census.
func (m *WineObservers) AnnotateActivity(s *ActivitySnapshot) {
	m.annotateActivityFresh(s)
	m.retainWineActivityAnnotations(s, time.Now())
}

func (m *WineObservers) annotateActivityFresh(s *ActivitySnapshot) {
	if !s.Complete || m.admissionDemand.Load() != 0 {
		return
	}
	groups := map[string][]int{}
	for i, r := range s.Rows {
		if r.Socket.Protocol != "udp" && (r.Socket.Protocol != "tcp" || (r.Socket.State != 1 && r.Socket.State != 2)) {
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
		if time.Since(start) > time.Second || m.admissionDemand.Load() != 0 {
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
			m.TryResolve(Flow{NetNS: row.Socket.NetNS, Protocol: row.Socket.Protocol, Direction: "outgoing", Local: row.Socket.Local, Remote: row.Socket.Remote})
		}
		if !m.tryActivityCensus() {
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
			result = record.table.activityBatch(s, indices, &record.broker, func() bool {
				return m.admissionDemand.Load() == 0
			})
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
func (w *WineTable) activityBatch(s *ActivitySnapshot, indices []int, broker *Process, proceed func() bool) map[int]*RuntimeApplication {
	if !proceed() || !w.mu.TryLock() {
		return nil
	}
	locked := true
	defer func() {
		if locked {
			w.mu.Unlock()
		}
	}()
	generation := w.generation
	if w.dead || w.lost.Load() || w.session == nil || !w.session.current() || w.helperPeersCounted(broker, true) != 1 {
		return nil
	}
	first := map[activityTableKey]tableSnapshot{}
	second := map[activityTableKey]tableSnapshot{}
	for _, i := range indices {
		if !proceed() {
			return nil
		}
		key := activityTable(s.Rows[i].Socket)
		if _, ok := first[key]; !ok {
			v, e := w.snapshotFamily(key.protocol, key.family)
			if e != nil {
				return nil
			}
			first[key] = v
		}
	}
	c := ActivityCollector{}
	fresh, acquired := w.activityCollect(c.Collect, proceed)
	locked = acquired
	if !acquired {
		return nil
	}
	if !fresh.Complete || w.dead || w.lost.Load() || w.generation != generation || w.session == nil || !w.session.current() || w.helperPeersCounted(broker, true) != 1 {
		return nil
	}
	for key := range first {
		if !proceed() {
			return nil
		}
		v, e := w.snapshotFamily(key.protocol, key.family)
		if e != nil {
			return nil
		}
		second[key] = v
	}
	if !proceed() {
		return nil
	}
	sockets, e := SocketsLimited(2048)
	if e != nil || !w.session.current() || w.helperPeersCounted(broker, true) != 1 {
		return nil
	}
	// Discovery is shared across distinct image requests in this fresh pass.
	// All three helper barriers above and every per-socket check below remain.
	var images map[wineImageKey]bool
	visible := func(b *Process, path, revision string) bool {
		if !proceed() {
			return false
		}
		if images == nil {
			images = w.activityImagesVisible(b, w.activityImageKeys(s, indices, second, proceed), proceed)
			if images == nil {
				images = map[wineImageKey]bool{}
			}
		}
		return images[wineImageKey{path, revision}]
	}
	result := w.annotateCensus(s, &fresh, sockets, indices, broker, first, second, visible)
	if !proceed() {
		return nil
	}
	return result
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

func (w *WineTable) annotateCensus(s, fresh *ActivitySnapshot, sockets []Socket, indices []int, broker *Process, first, second map[activityTableKey]tableSnapshot, visible func(*Process, string, string) bool) map[int]*RuntimeApplication {
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
		f := Flow{NetNS: row.Socket.NetNS, Protocol: row.Socket.Protocol, Direction: "outgoing", Local: row.Socket.Local, Remote: row.Socket.Remote}
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
		key := activityTable(row.Socket)
		if key.family == 6 && f.Local.Addr().Is4() && (row.Socket.V6Only == nil || *row.Socket.V6Only) {
			continue
		}
		before, ok1 := first[key]
		after, ok2 := second[key]
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

// tryActivityCensus never waits and rechecks demand after taking a slot. A new
// admission arriving after this check may wait for this one in-flight batch.
func (m *WineObservers) tryActivityCensus() bool {
	if m.admissionDemand.Load() != 0 {
		return false
	}
	select {
	case m.census <- struct{}{}:
	default:
		return false
	}
	if m.admissionDemand.Load() != 0 {
		<-m.census
		return false
	}
	return true
}

// activityCollect is entered with mu held. The expensive kernel process/FD
// scan needs no helper state. Release the lock so admission can use the helper;
// never queue behind admission to resume presentation. The caller must check
// its pinned generation and session again when acquired is true.
func (w *WineTable) activityCollect(collect func() ActivitySnapshot, proceed func() bool) (fresh ActivitySnapshot, acquired bool) {
	generation := w.generation
	w.mu.Unlock()
	fresh = collect()
	if !proceed() || !w.mu.TryLock() {
		return fresh, false
	}
	if !proceed() || w.dead || w.lost.Load() || w.generation != generation {
		w.mu.Unlock()
		return fresh, false
	}
	return fresh, true
}
