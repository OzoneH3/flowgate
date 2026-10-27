package uploadshape

import (
	"flowgate/internal/identity"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestRetainedDiscoveryProgressAndIncompleteRecovery(t *testing.T) {
	var d discoverySnapshot
	d.reset()
	rows := censusRows(4096)
	if e := d.load(rows, nil, time.Now()); e != nil {
		t.Fatal(e)
	}
	// Mutating/reordering the provider's next dump cannot change this generation.
	first := rows[0].Cookie
	rows[0] = rows[4095]
	for i := 0; i < 4096; i++ {
		s, ok := d.next()
		if !ok {
			t.Fatalf("lost tail at %d", i)
		}
		if i == 0 && s.Cookie != first {
			t.Fatal("snapshot aliased provider")
		}
	}
	if d.view.Pending != 0 || d.view.Cursor != 4096 || d.view.LastCompleted.IsZero() {
		t.Fatal(d.view)
	}
	if e := d.load(rows[:10], fmt.Errorf("interrupted dump"), time.Now()); e == nil {
		t.Fatal("partial accepted")
	}
	if _, ok := d.next(); ok || !d.view.Incomplete {
		t.Fatal("partial prefix retained")
	}
	if e := d.load(censusRows(4097), nil, time.Now()); e == nil || !d.view.Overloaded {
		t.Fatal("overload not reported")
	}
	if e := d.load(rows[:3], nil, time.Now()); e != nil || d.view.Overloaded || d.view.Pending != 3 {
		t.Fatal("recovery", d.view)
	}
}

func TestDiscoveryCapEditsDoNotRestartCursor(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(24)
	calls := 0
	m.sockets = func() ([]identity.Socket, error) { calls++; return rows, nil }
	visited := make(chan int, 8)
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		visited <- int(fl[0].Local.Port())
		return make([]identity.Attribution, len(fl))
	}
	defer m.Close()
	cfg := Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}}
	m.Configure(1, cfg)
	for i := 0; i < 3; i++ {
		select {
		case port := <-visited:
			if port != 40000+8*i {
				t.Fatalf("prefix restarted: turn%d port%d", i, port)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no discovery progress")
		}
		if i < 2 {
			s := m.Snapshot()
			cfg.Caps[0].BitsPerSecond++
			if _, e := m.Configure(s.Version, cfg); e != nil {
				t.Fatal(e)
			}
		}
	}
	// Access census count after worker shutdown, avoiding a test-only data race.
	m.Close()
	if calls != 1 {
		t.Fatalf("redumped before completing generation: %d", calls)
	}
}

func TestDiscoveryRetryBackoffIsBoundedAndResettable(t *testing.T) {
	var d discoverySnapshot
	d.reset()
	for i := 0; i < 10; i++ {
		e := d.load(nil, identity.ErrSocketCensusCapacity, time.Now())
		if e == nil || !d.view.Overloaded || d.retryDelay > 30*time.Second || d.retryDelay < time.Second || d.view.NextRetry.IsZero() {
			t.Fatal(d.view)
		}
	}
	if d.retryDelay != 30*time.Second {
		t.Fatal(d.retryDelay)
	}
	d.clearRetry()
	if !d.view.NextRetry.IsZero() {
		t.Fatal("cap edit does not retry")
	}
	if e := d.load(censusRows(2), nil, time.Now()); e != nil || d.view.Incomplete || d.retryDelay != 0 {
		t.Fatal(d.view)
	}
}

// A retained hint at the tail gets service, but a newly resolved generation at
// its tuple must never inherit the hint's binding, even with the same app key.
func TestDiscoveryTailReplacementCookieRefused(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(1025)
	for i := 0; i < 1024; i++ {
		rows[i].Remote = netip.AddrPort{}
	}
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		if len(fl) != 1 || fl[0].Local != rows[1024].Local {
			t.Errorf("unexpected tail selection: %+v", fl)
		}
		return []identity.Attribution{{VisibilityComplete: true, Status: "directly-associated", Application: &identity.Application{Kind: "native", Key: "a"}, Owners: []identity.Process{{PID: 7, ThreadGroup: 7, UID: 0, Application: identity.Application{Kind: "native", Key: "a"}}}, Sockets: []identity.Socket{{Cookie: "replacement"}}}}
	}
	defer m.Close()
	m.Configure(1, Config{Enabled: true, Caps: []Cap{{UID: 0, Application: "a", BitsPerSecond: 4_000_000}}})
	until(t, func() bool { return m.Snapshot().Gaps["discovery_generation_changed"] > 0 })
	s := m.Snapshot()
	if s.Discovery.RowsVisited != 1025 || s.DiscoverySnapshot.Generation != 1 || s.Discovery.BindRequests != 0 {
		t.Fatal(s.Discovery, s.DiscoverySnapshot)
	}
	m.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, op := range f.calls {
		if op == "bind" {
			t.Fatal("replacement bound from stale hint")
		}
	}
}
