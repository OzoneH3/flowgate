package identity

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCensus stands in for one runtime session: a held mutex models a running
// census, and gate (when set) pauses it until released.
type fakeCensus struct {
	app   Application
	mu    sync.Mutex
	gate  chan struct{}
	entry chan struct{}
}

func (c *fakeCensus) resolve(f Flow, wait bool) (Attribution, bool) {
	if wait {
		c.mu.Lock()
	} else if !c.mu.TryLock() {
		return Attribution{}, false
	}
	defer c.mu.Unlock()
	if c.entry != nil {
		c.entry <- struct{}{}
	}
	if c.gate != nil {
		<-c.gate
	}
	app := c.app
	return Attribution{Status: "corroborated-runtime-table", Application: &app}, true
}

type censusFixture struct {
	m       *WineObservers
	byPfx   map[string]*fakeCensus
	setups  atomic.Int32
	setupGo chan struct{} // when set, setup waits for it
}

func newCensusFixture(t *testing.T) *censusFixture {
	x := &censusFixture{byPfx: map[string]*fakeCensus{}}
	for _, name := range []string{"alpha", "beta"} {
		prefix := "/prefixes/" + name
		x.byPfx[prefix] = &fakeCensus{app: Application{Kind: "wine", Name: name + ".exe", Key: "key-" + name, Revision: "rev-" + name, Prefix: prefix}}
	}
	x.m = &WineObservers{options: WineObserverOptions{UID: uint32(os.Getuid())}, sessions: map[string]*observedWine{}, census: make(chan struct{}, WineCensusLimit)}
	x.m.setupSession = func(record *observedWine, broker *Process, bin string) {
		defer close(record.ready)
		x.setups.Add(1)
		if x.setupGo != nil {
			<-x.setupGo
		}
		record.resolve = x.byPfx[broker.Application.Prefix].resolve
	}
	return x
}

func (x *censusFixture) broker(t *testing.T, name string) *Process {
	start, _, err := processStat(fmt.Sprintf("/proc/%d", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	return &Process{PID: os.Getpid(), Start: start, ExecutableRevision: "wineserver-rev", Application: Application{Prefix: "/prefixes/" + name}}
}

func (x *censusFixture) resolve(t *testing.T, name string, wait bool) (Attribution, bool) {
	return x.m.sessionResolve(Flow{Protocol: "udp", Direction: "outgoing"}, Attribution{}, x.broker(t, name), "/bin", wait)
}

func returnsWithin(t *testing.T, what string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

func TestWineCensusTryNeverWaitsForSlotsSetupOrBusyTable(t *testing.T) {
	x := newCensusFixture(t)
	alpha, beta := x.byPfx["/prefixes/alpha"], x.byPfx["/prefixes/beta"]
	// Warm both sessions.
	for _, n := range []string{"alpha", "beta"} {
		if a, ok := x.resolve(t, n, true); !ok || a.Application.Name != n+".exe" {
			t.Fatalf("%s warm-up: %+v %v", n, a, ok)
		}
	}
	// Two paused censuses hold every slot.
	alpha.gate, beta.gate = make(chan struct{}), make(chan struct{})
	alpha.entry, beta.entry = make(chan struct{}, 1), make(chan struct{}, 1)
	var wg sync.WaitGroup
	for _, n := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func(n string) { defer wg.Done(); x.resolve(t, n, true) }(n)
	}
	<-alpha.entry
	<-beta.entry
	for i := 0; i < 12; i++ { // more paused-census demand than queue workers
		returnsWithin(t, "try with slots exhausted", 100*time.Millisecond, func() {
			if a, ok := x.resolve(t, "alpha", false); ok || a.Application != nil {
				t.Errorf("busy try must report false without evidence: %+v %v", a, ok)
			}
		})
	}
	close(alpha.gate)
	close(beta.gate)
	wg.Wait()
	alpha.gate, beta.gate, alpha.entry, beta.entry = nil, nil, nil, nil

	// A slot is free but alpha's table is busy: alpha reports false, beta proceeds
	// with its own identity only.
	alpha.gate, alpha.entry = make(chan struct{}), make(chan struct{}, 1)
	go x.resolve(t, "alpha", true)
	<-alpha.entry
	returnsWithin(t, "try on busy session", 100*time.Millisecond, func() {
		if _, ok := x.resolve(t, "alpha", false); ok {
			t.Error("busy alpha table must report false")
		}
	})
	returnsWithin(t, "independent prefix", 100*time.Millisecond, func() {
		a, ok := x.resolve(t, "beta", false)
		if !ok || a.Application == nil || a.Application.Name != "beta.exe" || a.Application.Prefix != "/prefixes/beta" {
			t.Errorf("beta must resolve to beta only: %+v %v", a, ok)
		}
	})
	close(alpha.gate)
}

func TestWineCensusSessionSetupIsSingleAndTryDoesNotWaitForIt(t *testing.T) {
	x := newCensusFixture(t)
	x.setupGo = make(chan struct{})
	first := make(chan Attribution, 1)
	go func() { a, _ := x.resolve(t, "alpha", true); first <- a }()
	for x.setups.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	returnsWithin(t, "try during setup", 100*time.Millisecond, func() {
		if _, ok := x.resolve(t, "alpha", false); ok {
			t.Error("session under setup must report false")
		}
	})
	waiter := make(chan Attribution, 1)
	go func() { a, _ := x.resolve(t, "alpha", true); waiter <- a }()
	close(x.setupGo)
	for _, a := range []Attribution{<-first, <-waiter} {
		if a.Application == nil || a.Application.Name != "alpha.exe" {
			t.Fatalf("after setup: %+v", a)
		}
	}
	if n := x.setups.Load(); n != 1 {
		t.Fatalf("one broker generation started %d helpers", n)
	}
}

func TestWineCensusCloseDuringInFlightCensusReleasesAfterLastUser(t *testing.T) {
	x := newCensusFixture(t)
	alpha := x.byPfx["/prefixes/alpha"]
	x.resolve(t, "alpha", true)
	var record *observedWine
	for _, s := range x.m.sessions {
		record = s
	}
	alpha.gate, alpha.entry = make(chan struct{}), make(chan struct{}, 1)
	result := make(chan Attribution, 1)
	go func() { a, _ := x.resolve(t, "alpha", true); result <- a }()
	<-alpha.entry
	returnsWithin(t, "Close during census", time.Second, x.m.Close)
	x.m.mu.Lock()
	released := record.released
	x.m.mu.Unlock()
	if released {
		t.Fatal("session released while a census still used it")
	}
	close(alpha.gate)
	if a := <-result; a.Application != nil {
		t.Fatalf("census finishing after Close donated evidence: %+v", a)
	}
	x.m.mu.Lock()
	released = record.released
	x.m.mu.Unlock()
	if !released {
		t.Fatal("retired session not released by its last user")
	}
	if a, ok := x.resolve(t, "alpha", true); !ok || a.Application != nil || a.Reason != "Wine owner observer: stopped" {
		t.Fatalf("stopped observer must stay explicit: %+v %v", a, ok)
	}
}

func TestWineCensusPrunesExitedBrokerGenerations(t *testing.T) {
	x := newCensusFixture(t)
	dead := x.broker(t, "alpha")
	dead.Start = "0" // a generation that is no longer running
	x.m.sessionResolve(Flow{}, Attribution{}, dead, "/bin", true)
	var old *observedWine
	for _, s := range x.m.sessions {
		old = s
	}
	if a, ok := x.resolve(t, "beta", true); !ok || a.Application.Name != "beta.exe" {
		t.Fatalf("beta: %+v", a)
	}
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if !old.released || len(x.m.sessions) != 1 {
		t.Fatalf("exited generation kept: released=%v sessions=%d", old.released, len(x.m.sessions))
	}
}

func TestWineCensusPrunedDuringCensusDonatesNoEvidence(t *testing.T) {
	x := newCensusFixture(t)
	alpha := x.byPfx["/prefixes/alpha"]
	x.resolve(t, "alpha", true)
	alpha.gate, alpha.entry = make(chan struct{}), make(chan struct{}, 1)
	result := make(chan Attribution, 1)
	go func() { a, _ := x.resolve(t, "alpha", true); result <- a }()
	<-alpha.entry
	x.m.mu.Lock()
	for k, s := range x.m.sessions {
		if s.broker.Application.Prefix == "/prefixes/alpha" {
			if got := x.m.retireLocked(k, s); got != nil {
				t.Error("in-use session handed to cleanup")
			}
		}
	}
	x.m.mu.Unlock()
	close(alpha.gate)
	if a := <-result; a.Application != nil || a.Reason != "Wine owner observer: session retired during census" {
		t.Fatalf("pruned generation donated evidence: %+v", a)
	}
	if a, ok := x.resolve(t, "beta", true); !ok || a.Application == nil || a.Application.Name != "beta.exe" {
		t.Fatalf("other prefix affected: %+v", a)
	}
}

func TestWineObserverLifecycleExitRenewsOnlyThatSession(t *testing.T) {
	x := newCensusFixture(t)
	for _, name := range []string{"alpha", "beta"} {
		x.resolve(t, name, true)
	}
	var old, other *observedWine
	for _, s := range x.m.sessions {
		if s.broker.Application.Prefix == "/prefixes/alpha" {
			old = s
		} else {
			other = s
		}
	}
	old.table = &WineTable{dead: true, reaped: make(chan struct{}), generation: "old"}
	old.table.lost.Store(true)
	close(old.table.reaped)
	a, ok := x.resolve(t, "alpha", true)
	if !ok || a.Application == nil || a.Application.Key != "key-alpha" {
		t.Fatal(a)
	}
	if x.setups.Load() != 3 || !old.closed || !old.released {
		t.Fatal("clean lifecycle did not retire and renew")
	}
	for _, s := range x.m.sessions {
		if s == old {
			t.Fatal("old evidence retained")
		}
	}
	if other.closed {
		t.Fatal("other prefix retired")
	}
	b, _ := x.resolve(t, "beta", true)
	if b.Application == nil || b.Application.Key != "key-beta" {
		t.Fatal("permissions crossed prefix")
	}
	x.m.Close()
}
