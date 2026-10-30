package daemon

import (
	"flowgate/internal/identity"
	"testing"
)

func TestSocketRouteWitnessAndOldCompletion(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	delete(s.flows, f.flow.Key())
	s.routeBound = true
	f.flow = identity.WithQueueOutputInterface(f.flow, 7)
	s.flows[s.flowKey(f.flow)] = f
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if len(m.values) != 1 {
		t.Fatal("verified route did not publish")
	}
	oldTicket := s.store.Begin()
	moved := identity.WithQueueOutputInterface(f.flow, 8)
	if !s.observeQueueRoute(moved) || len(m.values) != 0 || len(s.flows) != 0 || s.routeMoves != 1 {
		t.Fatal("old interface not retired")
	}
	e.finishSocketAuthorizationLocked(s, f, oldTicket, a)
	if len(m.values) != 0 {
		t.Fatal("old in-flight observation resurrected route")
	}
	display := identity.Flow{Direction: "outgoing", Interface: 8}
	if s.observeQueueRoute(display) {
		t.Fatal("display interface treated as queue evidence")
	}
	if f.flow.Key() != moved.Key() || s.flowKey(f.flow) == s.flowKey(moved) {
		t.Fatal("global flow key changed or interface scope missing")
	}
}
