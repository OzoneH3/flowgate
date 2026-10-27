package uploadshape

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"flowgate/internal/identity"
)

func censusRows(n int) []identity.Socket {
	var out []identity.Socket
	for i := 0; i < n; i++ {
		out = append(out, identity.Socket{Protocol: "tcp", Inode: uint32(100 + i), Cookie: fmt.Sprintf("%016x", 0x1000+i), UID: 0,
			Local: netip.MustParseAddrPort(fmt.Sprintf("10.79.0.1:%d", 40000+i)), Remote: netip.MustParseAddrPort("10.79.0.2:43003"), NetNS: identity.NetNS()})
	}
	return out
}

// One shared resolution per tick, at most eight ROWS visited per tick (skipped
// rows count), and the batch receives only the rows that survive cheap filters.
func TestDiscoveryVisitsEightRowsAndResolvesOnceSharedPerTick(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(20)
	rows[1].UID = 1000 // filtered by UID, still a visited row
	rows[2].Inode = 0  // filtered as unusable, still a visited row
	var mu sync.Mutex
	var batches [][]identity.Flow
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		mu.Lock()
		batches = append(batches, fl)
		mu.Unlock()
		return make([]identity.Attribution, len(fl)) // unidentified: no bind
	}
	m.resolve = func(identity.Flow) identity.Attribution {
		t.Error("per-flow Resolve must not be used by discovery")
		return identity.Attribution{}
	}
	defer m.Close()
	m.Configure(1, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}})
	until(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(batches) >= 2 })
	mu.Lock()
	first := batches[0]
	mu.Unlock()
	if len(first) != 8 { // Ten rows visited: two filtered, eight candidates
		t.Fatalf("expected 8 candidates after cheap filtering, got %d", len(first))
	}
	d := m.Snapshot().Discovery
	if d.CensusAttempts != 1 || d.CensusPasses != 1 || d.RowsVisited < 16 || d.SharedResolutions < 2 || d.FlowsResolved < 12 || d.SkippedUID < 1 || d.SkippedUnusable < 1 || d.BindRequests != 0 || d.EligibleCandidates != 0 {
		t.Fatalf("activity metrics not accounted: %+v", d)
	}
	if g := m.Snapshot().Gaps["discovery_full_resolutions"]; g != 0 {
		t.Fatal("activity metrics must not appear in known_gaps")
	}
}

// A row-limit (or any) census error yields no discovery work from partial rows.
func TestDiscoveryRowLimitErrorUsesNoPartialRows(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	m.sockets = func() ([]identity.Socket, error) { return censusRows(3), fmt.Errorf("socket row limit reached") }
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		t.Error("partial census must not be resolved")
		return nil
	}
	defer m.Close()
	m.Configure(1, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}})
	until(t, func() bool { return m.Snapshot().Gaps["discovery_failed"] >= 2 })
	if d := m.Snapshot().Discovery; d.CensusPasses != 0 || d.FlowsResolved != 0 || d.CensusErrors < 2 || d.CensusAttempts < 2 {
		t.Fatalf("failed census must count as attempt+error, never as a pass: %+v", d)
	}
}

// A cap change that lands while the shared census runs invalidates that batch:
// nothing is bound from it and it is counted as stale, never as current work.
func TestDiscoveryConfigRaceDiscardsBatch(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(2)
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		once.Do(func() { entered <- struct{}{}; <-release })
		out := make([]identity.Attribution, len(fl))
		for i := range out { // a fully eligible native owner for every candidate
			out[i] = identity.Attribution{VisibilityComplete: true, Status: "directly-associated", Application: &identity.Application{Kind: "native", Key: "a"},
				Owners: []identity.Process{{PID: 7, ThreadGroup: 7, UID: 0, Application: identity.Application{Kind: "native", Key: "a"}}}, Sockets: []identity.Socket{{Cookie: rows[i%len(rows)].Cookie}}}
		}
		return out
	}
	defer m.Close()
	m.Configure(1, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}})
	<-entered
	if _, err := m.Configure(2, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "b", BitsPerSecond: 4_000_000}}}); err != nil {
		t.Fatal(err)
	}
	close(release)
	until(t, func() bool { return m.Snapshot().Discovery.StaleBatches >= 1 })
	f.mu.Lock()
	var binds int
	for _, c := range f.calls {
		if c == "bind" {
			binds++
		}
	}
	f.mu.Unlock()
	if binds != 0 {
		t.Fatalf("stale batch produced %d bind requests", binds)
	}
	_ = time.Second
}

// An eligible but uncapped candidate is counted as eligible, never as a bind
// request: no controller RPC is issued for it.
func TestDiscoveryUncappedEligibleIsNotABindRequest(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(1)
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		out := make([]identity.Attribution, len(fl))
		for i := range out {
			out[i] = identity.Attribution{VisibilityComplete: true, Status: "directly-associated", Application: &identity.Application{Kind: "native", Key: "uncapped"},
				Owners: []identity.Process{{PID: 9, ThreadGroup: 9, UID: 0, Application: identity.Application{Kind: "native", Key: "uncapped"}}}, Sockets: []identity.Socket{{Cookie: rows[0].Cookie}}}
		}
		return out
	}
	defer m.Close()
	m.Configure(1, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}})
	until(t, func() bool { return m.Snapshot().Discovery.EligibleCandidates >= 2 })
	d := m.Snapshot().Discovery
	if d.BindRequests != 0 {
		t.Fatalf("uncapped eligible candidate issued bind RPCs: %+v", d)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == "bind" {
			t.Fatal("controller bind RPC issued for an uncapped application")
		}
	}
}
