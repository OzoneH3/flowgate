package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestProcessEditCensusUnlocksAndRejectsConcurrentPolicyChange(t *testing.T) {
	e, _, _, _ := fixture()
	entered, release := make(chan struct{}), make(chan struct{})
	e.Activity = func() identity.ActivitySnapshot {
		close(entered)
		<-release
		return identity.ActivitySnapshot{}
	}
	done := make(chan error, 1)
	go func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		done <- e.verifyProcessEditLocked(identity.Instance{PID: 1, Start: "1"})
	}()
	<-entered
	within(t, "policy edit during process census", func() {
		e.mu.Lock()
		e.rules = append(e.rules, policy.Rule{ID: "concurrent"})
		e.mu.Unlock()
	})
	close(release)
	if err := <-done; err == nil || err.Error() != "Policy or network changed during process verification; retry" {
		t.Fatalf("expected conflict after concurrent change, got %v", err)
	}
}

func TestPeerServiceCensusOutsideLockAndEvidenceNeverTransfers(t *testing.T) {
	e, f, a, now := fixture()
	f.Direction = "outgoing"
	rule := policy.Rule{ID: "service", Action: "allow", Filter: policy.Filter{
		Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "outgoing",
		RemoteAddress: f.Remote.Addr().String(), RemotePort: f.Remote.Port(),
		PeerService: policy.PeerService{Application: "service", Revision: "rev", UID: 1000},
	}}
	e.rules = []policy.Rule{rule}
	peer := *a
	app := identity.Application{Key: "service", Revision: "rev"}
	peer.Application, peer.VisibilityComplete = &app, true
	reverse := f
	reverse.Direction, reverse.Local, reverse.Remote = "incoming", f.Remote, f.Local
	entered, release := slowResolver(e, reverse, peer)
	done := make(chan Event, 1)
	go func() { done <- e.ObserveResolved(f, "first", *a) }()
	<-entered
	within(t, "list during peer census", func() { e.List(1000, false) })
	close(release)
	if v := <-done; v.State != "allowed" {
		t.Fatalf("verified peer rejected: %+v", v)
	}
	// No evidence from the previous packet may survive into another operation.
	e.mu.Lock()
	action, _, _ := e.evaluateLocked(e.rules, f, *a, *now)
	e.mu.Unlock()
	if action == "allow" {
		t.Fatal("peer evidence leaked across operations")
	}
	// Evidence that aged out while the lock was unavailable cannot authorize.
	set := e.resolvePeers(f)
	*now = now.Add(prefetchMaxAge + time.Nanosecond)
	e.mu.Lock()
	e.peerPrefetched = set
	action, _, _ = e.evaluateLocked(e.rules, f, *a, *now)
	e.peerPrefetched = nil
	e.mu.Unlock()
	if action == "allow" {
		t.Fatal("stale peer evidence authorized traffic")
	}
	// Another executable owning the server socket does not inherit permission.
	peer.Application = &identity.Application{Key: "other", Revision: "rev"}
	e.Resolve = func(identity.Flow) identity.Attribution { return peer }
	if v := e.ObserveResolved(f, "other", *a); v.State == "allowed" {
		t.Fatal("other service inherited permission")
	}
}
