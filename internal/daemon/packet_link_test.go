package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestPacketLinkObservationSkipsOnlyProvenNonLocalPeerWork(t *testing.T) {
	saved := observeLoopbackDevice
	defer func() { observeLoopbackDevice = saved }()
	for _, state := range []struct {
		name          string
		device, known bool
		peers         int
	}{
		{"physical", false, true, 0},
		{"unknown", false, false, 1},
		{"loopback", true, true, 1},
	} {
		t.Run(state.name, func(t *testing.T) {
			e, f, a, _ := fixture()
			remote, _ := identity.ParseFlow("udp", "incoming", "192.0.2.1:40000", "198.51.100.1:40001")
			f.Local, f.Remote = remote.Local, remote.Remote
			f.Interface = 7
			queries, peers := 0, 0
			observeLoopbackDevice = func(identity.Flow) (bool, bool) { queries++; return state.device, state.known }
			e.LocalPeer = func(identity.Flow) *identity.LocalPeer { peers++; return nil }
			e.ObserveResolved(f, "udp-second", *a)
			if queries != 1 || peers != state.peers {
				t.Fatalf("link queries=%d peer calls=%d", queries, peers)
			}
			// Evidence is never shared across packets: a second packet makes its
			// own observation, including a device which changed after the first.
			observeLoopbackDevice = func(identity.Flow) (bool, bool) { queries++; return false, false }
			e.ObserveResolved(f, "udp", *a)
			if queries != 2 || peers != state.peers+1 {
				t.Fatal("packet observation persisted")
			}
		})
	}
}

func TestPacketLinkWaitDoesNotHoldPolicyLockAndNewRuleWins(t *testing.T) {
	saved := observeLoopbackDevice
	defer func() { observeLoopbackDevice = saved }()
	e, f, a, _ := fixture()
	e.LocalPeer = nil
	started, release := make(chan struct{}), make(chan struct{})
	observeLoopbackDevice = func(identity.Flow) (bool, bool) { close(started); <-release; return false, true }
	result := make(chan Event, 1)
	go func() { result <- e.ObserveResolved(f, "udp", *a) }()
	<-started
	published := make(chan error, 1)
	go func() {
		published <- e.SetRules([]policy.Rule{{ID: "new-deny", Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}})
	}()
	select {
	case err := <-published:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		<-result
		<-published
		t.Fatal("link wait held policy publication lock")
	}
	close(release)
	if got := <-result; got.State != "blocked" || got.Rule != "new-deny" {
		t.Fatal("stale policy after link observation", got.State, got.Rule)
	}
}
