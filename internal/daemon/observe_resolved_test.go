package daemon

import (
	"testing"
	"time"

	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

// slowResolver holds attribution of one flow until released; other flows resolve at once.
func slowResolver(e *Engine, slow identity.Flow, a identity.Attribution) (entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	e.Resolve = func(f identity.Flow) identity.Attribution {
		if f.Key() == slow.Key() {
			close(entered)
			<-release
		}
		return a
	}
	return entered, release
}

func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s waited for an unrelated ownership resolution", what)
	}
}

func TestSlowAttributionDoesNotHoldInteractionOrIndependentFlows(t *testing.T) {
	e, f, a, _ := fixture()
	entered, release := slowResolver(e, f, *a)
	result := make(chan Event, 1)
	go func() { result <- e.Observe(f, "udp") }()
	<-entered

	within(t, "List", func() { e.List(1000, false) })
	other, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	within(t, "independent flow", func() {
		if v := e.Observe(other, "udp"); v.State != "awaiting-decision" {
			t.Errorf("independent flow: %s", v.State)
		}
	})
	// A Block stored while the slow flow is being attributed decides that flow.
	block := policy.Rule{ID: "b", Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}
	within(t, "rule mutation", func() {
		if err := e.SetRules([]policy.Rule{block}); err != nil {
			t.Error(err)
		}
	})
	close(release)
	if v := <-result; v.State != "blocked" {
		t.Fatalf("policy changed during attribution was not applied: %s", v.State)
	}
}

func TestObserveResolvedUsesSuppliedAttributionOnly(t *testing.T) {
	e, f, a, _ := fixture()
	e.Resolve = func(identity.Flow) identity.Attribution {
		t.Fatal("ObserveResolved must not resolve again")
		return identity.Attribution{}
	}
	allow := policy.Rule{ID: "r", Action: "allow", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}
	if err := e.SetRules([]policy.Rule{allow}); err != nil {
		t.Fatal(err)
	}
	if v := e.ObserveResolved(f, "udp", *a); v.State != "allowed" {
		t.Fatalf("supplied attribution: %s", v.State)
	}
	// Another application's evidence never inherits the rule.
	other := identity.Application{Key: "other", Revision: "rev"}
	b := identity.Attribution{Application: &other, Owners: []identity.Process{{UID: 1000, Start: "11"}}, Fingerprint: "two"}
	if v := e.ObserveResolved(f, "udp", b); v.State == "allowed" {
		t.Fatal("rule transferred to a different application")
	}
}

func TestRetainedStateResolvesOutsideLockAndHonoursBlockMadeMeanwhile(t *testing.T) {
	for _, block := range []bool{false, true} {
		e, f, a, _ := fixture()
		v := e.Observe(f, "udp")
		if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil {
			t.Fatal(err)
		}
		entered, release := slowResolver(e, f, *a)
		result := make(chan string, 1)
		go func() { result <- e.RetainedState(v.ID, a.Fingerprint) }()
		<-entered
		within(t, "List during retained recheck", func() { e.List(1000, false) })
		if block {
			rule := policy.Rule{ID: "b", Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}
			within(t, "rule mutation during retained recheck", func() {
				if err := e.SetRules([]policy.Rule{rule}); err != nil {
					t.Error(err)
				}
			})
		}
		close(release)
		want := "allow"
		if block {
			want = "drop"
		}
		if got := <-result; got != want {
			t.Fatalf("block=%v: retained verdict %q, want %q", block, got, want)
		}
	}
}

func TestTryObserveBusyCreatesNoEventAndSpendsNoPromptBudget(t *testing.T) {
	e, f, a, _ := fixture()
	busy := true
	e.TryResolve = func(identity.Flow) (identity.Attribution, bool) {
		if busy {
			return identity.Attribution{}, false
		}
		return *a, true
	}
	for i := 0; i < 50; i++ {
		if v, ok := e.TryObserve(f, string(rune('a'+i%26))); ok || v.ID != "" {
			t.Fatalf("busy census produced an event: %+v %v", v, ok)
		}
	}
	if n := len(e.List(1000, true)); n != 0 {
		t.Fatalf("busy results left %d events", n)
	}
	if e.liveEventsLocked() != 0 || e.created != 0 {
		t.Fatalf("busy results spent prompt budget: live=%d created=%d", e.liveEventsLocked(), e.created)
	}
	busy = false
	if v, ok := e.TryObserve(f, "udp"); !ok || v.State != "awaiting-decision" {
		t.Fatalf("later census must decide normally: %+v %v", v, ok)
	}
}
