package daemon

import (
	"encoding/json"
	"flowgate/internal/socketgrant"
	"testing"
	"time"
)

func TestSocketAuthorizationZonePublicationRejectsOldTicket(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	old := s.store.Begin()
	next := e.Zones
	next.Revision = "new-zone-revision"
	committed := false
	err := e.PublishNetworkZones(next, func() {
		committed = true
		if m.epoch == 1 {
			t.Fatal("snapshot published before revocation")
		}
	})
	if err != nil || !committed || e.Zones.Revision != next.Revision {
		t.Fatalf("publication: %v", err)
	}
	e.finishSocketAuthorizationLocked(s, f, old, a)
	if len(m.values) != 0 {
		t.Fatal("pre-zone ticket published")
	}
}

func TestSocketAuthorizationZoneFailureStillCommits(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	var deadline uint64
	for _, v := range m.values {
		deadline = v.Deadline
	}
	m.fail = true
	next := e.Zones
	next.Revision = "changed-despite-gate-failure"
	committed := false
	if e.PublishNetworkZones(next, func() { committed = true }) == nil {
		t.Fatal("failure hidden")
	}
	if !committed || e.Zones.Revision != next.Revision || !s.disabled || s.failure == nil {
		t.Fatal("zone rolled back or accelerator still active")
	}
	// grantModel.fail rejects only Epoch writes: Put remains successful.
	// Remove the old model entry so an attempted fresh publication is visible.
	oldValues := m.values
	m.values = map[socketgrant.Key]socketgrant.Value{}
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if len(m.values) != 0 {
		t.Fatal("fresh ticket published after failed zone revocation")
	}
	for _, v := range oldValues {
		if v.Deadline != deadline {
			t.Fatal("failure extended grant")
		}
	}
	if deadline == 0 || socketgrant.Window.Milliseconds() != 250 {
		t.Fatal("invalid hard deadline")
	}
}

func TestSocketZoneFailureRemainsVisibleAfterNextPublication(t *testing.T) {
	e, s, _, _, m := wineGrantFixture(t)
	m.fail = true
	next := e.Zones
	next.Revision = "failure"
	if e.PublishNetworkZones(next, func() {}) == nil {
		t.Fatal("expected revocation error")
	}
	m.fail = false
	next.Revision = "later-network"
	_ = e.PublishNetworkZones(next, func() {})
	if !s.disabled || e.SocketAuthorizationFailure() == nil {
		t.Fatal("later snapshot hid disabled accelerator")
	}
}

func TestPublishedSocketStatusIndependentOfPolicyLock(t *testing.T) {
	e, s, _, _, _ := wineGrantFixture(t)
	s.disabled = true
	if err := e.listReads.publish(e); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		status := e.PublishedSocketAuthorizationStatus()
		failure := e.PublishedSocketAuthorizationFailure()
		status["disabled"] = false
		again := e.PublishedSocketAuthorizationStatus()
		done <- failure != nil && again["disabled"] == true
	}()
	select {
	case ok := <-done:
		e.mu.Unlock()
		if !ok {
			t.Fatal("published failure missing or mutable snapshot shared")
		}
	case <-time.After(time.Second):
		e.mu.Unlock()
		t.Fatal("presentation getter waited on policy lock")
	}
}

func TestPublishedSocketStatusExcludesDiagnosticPayload(t *testing.T) {
	e, _, _, _, _ := wineGrantFixture(t)
	if err := e.listReads.publish(e); err != nil {
		t.Fatal(err)
	}
	status := e.PublishedSocketAuthorizationStatus()
	for _, key := range []string{"flows", "renewal_timeline", "renewal_observer", "gc_pause_history"} {
		if _, exists := status[key]; exists {
			t.Fatalf("hot snapshot contains %s", key)
		}
	}
	data, err := json.Marshal(status)
	if err != nil || len(data) > 2048 {
		t.Fatalf("unbounded status: bytes=%d err=%v", len(data), err)
	}
}

func BenchmarkSocketStatusPublication(b *testing.B) {
	e, _, _, _, _ := wineGrantFixture(b)
	for b.Loop() {
		if err := e.listReads.publish(e); err != nil {
			b.Fatal(err)
		}
	}
}
