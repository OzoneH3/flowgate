package daemon

import (
	"sync"
	"testing"
	"time"

	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

func wineApp(name, prefix string, start string) identity.Attribution {
	app := identity.Application{Kind: "wine", Name: name, Key: "key-" + name, Revision: "rev-" + name, Prefix: prefix}
	return identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000, Start: start}}, Fingerprint: "fp-" + name}
}

func TestDecisionResolvesOutsideLock(t *testing.T) {
	e, f, a, _ := fixture()
	v := e.Observe(f, "udp")
	entered, release := slowResolver(e, f, *a)
	done := make(chan error, 1)
	go func() { _, _, err := e.DecideSettled(v.ID, "allow", "once", 0, 1000, false); done <- err }()
	<-entered
	within(t, "List during decision", func() { e.List(1000, false) })
	other, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	within(t, "independent packet during decision", func() { e.Observe(other, "udp") })
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := e.Observe(f, "udp").State; got != "allowed" {
		t.Fatalf("decision lost: %s", got)
	}
}

func TestRuleChangeSettlesOutsideLockWithoutCrossApplicationTransfer(t *testing.T) {
	e, _, _, _ := fixture()
	alpha := wineApp("alpha.exe", "/prefixes/alpha", "10")
	beta := wineApp("beta.exe", "/prefixes/beta", "11")
	fa, _ := identity.ParseFlow("udp", "outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	fb, _ := identity.ParseFlow("udp", "outgoing", "172.30.42.123:40001", "198.51.100.1:7770")
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	slow := false
	e.Resolve = func(f identity.Flow) identity.Attribution {
		if slow && f.Key() == fa.Key() {
			entered <- struct{}{}
			<-release
		}
		if f.Key() == fa.Key() {
			return alpha
		}
		return beta
	}
	va, vb := e.Observe(fa, "udp"), e.Observe(fb, "udp")
	if va.State != "awaiting-decision" || vb.State != "awaiting-decision" {
		t.Fatal(va.State, vb.State)
	}
	slow = true
	allowAlpha := policy.Rule{ID: "a", Action: "allow", Filter: policy.Filter{Application: alpha.Application.Key, Revision: alpha.Application.Revision, UID: 1000, Protocol: "udp", Direction: "outgoing"}}
	done := make(chan error, 1)
	go func() { done <- e.SetRules([]policy.Rule{allowAlpha}) }()
	<-entered
	within(t, "List during rule change", func() { e.List(1000, false) })
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, v := range e.List(1000, false) {
		states[v.ID] = v.State
	}
	if states[va.ID] != "allowed" {
		t.Fatalf("alpha request not settled by its rule: %q", states[va.ID])
	}
	if states[vb.ID] != "awaiting-decision" {
		t.Fatalf("beta (other prefix) inherited alpha's rule: %q", states[vb.ID])
	}
}

func TestZoneRevisionChangeDefersSettleOutOfCallerLock(t *testing.T) {
	e, f, a, _ := fixture()
	v := e.Observe(f, "udp")
	entered, release := slowResolver(e, f, *a)
	zones := e.Zones
	zones.Revision = "changed"
	e.ZoneSource = func() identity.NetworkZones { return zones }
	other, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	// The packet noticing the revision must not re-attribute the pending request.
	within(t, "packet that observes a zone change", func() { e.Observe(other, "udp") })
	select {
	case <-entered: // deferred settle is resolving the pending request outside the lock
	case <-time.After(2 * time.Second):
		t.Fatal("deferred settle never ran")
	}
	within(t, "List during deferred settle", func() { e.List(1000, false) })
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for e.settleIdle() == false && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for _, row := range e.List(1000, false) {
		if row.ID == v.ID && row.State != "awaiting-decision" {
			t.Fatalf("unmatched pending request changed state: %s", row.State)
		}
	}
}

func TestMissingOrForeignRequestCausesNoOwnershipCensus(t *testing.T) {
	e, f, a, _ := fixture()
	other, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	e.Observe(f, "udp")
	v := e.Observe(other, "udp")
	calls := 0
	e.Resolve = func(identity.Flow) identity.Attribution { calls++; return *a }
	for _, try := range []struct {
		id  string
		uid uint32
	}{{"missing", 1000}, {v.ID, 1001}} {
		if _, _, err := e.DecideSettled(try.id, "allow", "application", 0, try.uid, false); err == nil {
			t.Fatalf("%+v accepted", try)
		}
		if _, err := e.PreviewDecision(e.Generation, try.id, "allow", "application", "any", e.Zones.Revision, try.uid, false); err == nil {
			t.Fatalf("%+v preview accepted", try)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid/foreign request ran %d ownership censuses", calls)
	}
}

func TestRequestReplacedDuringPrefetchIsNotEndedOrDecided(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	target := e.Observe(f, "udp")
	otherFlow, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	pending := e.Observe(otherFlow, "udp")
	replacement := *a
	replacement.Fingerprint = "replacement-socket"
	gate, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.Resolve = func(fl identity.Flow) identity.Attribution {
		if fl.Key() == otherFlow.Key() {
			once.Do(func() { close(entered) })
			<-gate
		}
		if fl.Key() == f.Key() {
			return replacement
		}
		return *a
	}
	done := make(chan error, 1)
	go func() { _, _, err := e.DecideSettled(target.ID, "allow", "application", 0, 1000, false); done <- err }()
	<-entered
	// The target's socket is replaced (new evidence => new request on the same tuple)
	// and an unrelated request arrives while the batch is being resolved.
	var fresh Event
	within(t, "replacement during prefetch", func() { fresh = e.Observe(f, "udp") })
	late, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:82", "127.0.0.1:9002")
	arrived := e.Observe(late, "udp")
	close(gate)
	if err := <-done; err == nil {
		t.Fatal("decision applied to a replaced request")
	}
	states := map[string]string{}
	for _, row := range e.List(1000, false) {
		states[row.ID] = row.State
	}
	for name, id := range map[string]string{"replacement": fresh.ID, "arrived": arrived.ID, "pending": pending.ID} {
		if states[id] != "awaiting-decision" {
			t.Fatalf("%s request ended or decided by another request's evidence: %q", name, states[id])
		}
	}
}

func TestAgedPrefetchIsDeferredNotEnded(t *testing.T) {
	e, _, _, now := fixture()
	e.Timeout = time.Minute
	alpha := wineApp("alpha.exe", "/prefixes/alpha", "10")
	beta := wineApp("beta.exe", "/prefixes/beta", "11")
	fa, _ := identity.ParseFlow("udp", "outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	fb, _ := identity.ParseFlow("udp", "outgoing", "172.30.42.123:40001", "198.51.100.1:7770")
	slowBeta := false
	e.Resolve = func(fl identity.Flow) identity.Attribution {
		if fl.Key() == fb.Key() {
			if slowBeta {
				*now = now.Add(3 * time.Second) // beta's census outlives prefetchMaxAge
			}
			return beta
		}
		return alpha
	}
	va, vb := e.Observe(fa, "udp"), e.Observe(fb, "udp")
	slowBeta = true
	if _, _, err := e.DecideSettled(va.ID, "allow", "application", 0, 1000, false); err != nil {
		t.Fatalf("fresh target must still decide: %v", err)
	}
	for _, row := range e.List(1000, false) {
		if row.ID == vb.ID && (row.State != "awaiting-decision" || row.Revalidation != nil) {
			t.Fatalf("aged evidence ended or changed beta: %s %+v", row.State, row.Revalidation)
		}
		if row.ID == va.ID && row.State != "allowed" {
			t.Fatalf("alpha: %s", row.State)
		}
	}
}
