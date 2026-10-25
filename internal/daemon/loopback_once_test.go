package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"reflect"
	"testing"
)

// The final packet decision makes its loopback-device observation inside policy
// evaluation under e.mu. The preliminary observation exists only to decide peer
// prefetching and must not run when the flow has no peer candidates.
func TestObserveResolvedLoopbackObservationOnlyForPeerCandidates(t *testing.T) {
	e, f, a, _ := fixture()
	calls := 0
	saved := loopbackFlow
	loopbackFlow = func(identity.Flow) bool { calls++; return false }
	defer func() { loopbackFlow = saved }()
	resolved := 0
	e.Resolve = func(identity.Flow) identity.Attribution { resolved++; return *a }

	v := e.ObserveResolved(f, "udp", *a)
	if v.State != "awaiting-decision" || calls != 0 || resolved != 0 {
		t.Fatalf("no peer candidates: state=%s preliminary loopback observations=%d peer resolves=%d", v.State, calls, resolved)
	}
	if e.peerPrefetched != nil {
		t.Fatal("prefetch set leaked past the decision")
	}
	if v.Flow.NetworkScope.State == "" {
		t.Fatal("flow was not classified")
	}

	// A peer-service rule matching this flow's remote makes it a candidate: the
	// preliminary observation runs exactly once and the peer is prefetched.
	e.rules = append(e.rules, policy.Rule{ID: "peer", Action: "allow", Filter: policy.Filter{Application: "svc", Revision: "r", UID: 1000, Protocol: "udp", Direction: "incoming", RemoteAddress: "127.0.0.1", RemotePort: 9000, PeerService: policy.PeerService{Application: "svc", Revision: "r", UID: 1000}}})
	calls, resolved = 0, 0
	e.ObserveResolved(f, "udp", *a)
	if calls != 1 || resolved != 1 {
		t.Fatalf("peer candidates: preliminary loopback observations=%d peer resolves=%d", calls, resolved)
	}
	// A forced preliminary "loopback" result only steers peer prefetch. The final
	// verdict comes from policy's own fresh observation (this fixture flow has
	// no loopback device), so it must not become the loopback default.
	loopbackFlow = func(identity.Flow) bool { calls++; return true }
	calls, resolved = 0, 0
	v = e.ObserveResolved(f, "udp", *a)
	if calls != 1 {
		t.Fatalf("preliminary observation count changed: %d", calls)
	}
	if v.Rule == policy.DefaultLoopback || (v.State == "allowed" && v.Attribution.Status == "localhost") {
		t.Fatalf("preliminary observation leaked into the verdict: %+v", v)
	}
}

// Classifying once per locked decision must not change the evaluation.
func TestEvaluateClassifiedLockedEqualsEvaluateLocked(t *testing.T) {
	e, f, a, now := fixture()
	e.rules = []policy.Rule{{ID: "r1", Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}}
	e.mu.Lock()
	defer e.mu.Unlock()
	wantAction, wantRule, wantIDs := e.evaluateLocked(e.rules, f, *a, *now)
	classified := f
	classified.NetworkScope = e.Zones.ClassifyFlow(f)
	gotAction, gotRule, gotIDs := e.evaluateClassifiedLocked(e.rules, classified, *a, *now)
	if wantAction != gotAction || wantRule != gotRule || !reflect.DeepEqual(wantIDs, gotIDs) {
		t.Fatalf("evaluation differs: %s/%s/%v vs %s/%s/%v", wantAction, wantRule, wantIDs, gotAction, gotRule, gotIDs)
	}
	if wantAction != "block" || wantRule != "r1" {
		t.Fatalf("fixture rule not applied: %s %s", wantAction, wantRule)
	}
}
