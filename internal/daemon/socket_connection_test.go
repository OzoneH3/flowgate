package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"net/netip"
	"testing"
	"time"
)

func connectionFixture(t *testing.T) (*Engine, *socketAuthorization, *socketFlow, identity.Attribution, *grantModel) {
	e, s, f, a, m := wineGrantFixture(t)
	s.connectionScoped = true
	s.routeBound = true
	f.flow = identity.WithQueueOutputInterface(f.flow, 3)
	s.flows = map[string]*socketFlow{s.flowKey(f.flow): f}
	var err error
	s.store, err = socketgrant.NewConnection(m)
	if err != nil {
		t.Fatal(err)
	}
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if !f.haveKey || len(m.values) != 1 || m.values[f.key].Deadline != 0 {
		t.Fatal("initial grant missing")
	}
	return e, s, f, a, m
}
func TestConnectionInconclusiveNeverRemovesGrant(t *testing.T) {
	e, s, f, _, m := connectionFixture(t)
	for _, a := range []identity.Attribution{{}, {ReasonCode: identity.ReasonRuntimeOwnershipChanged}, {VisibilityComplete: false}, {ReasonCode: identity.ReasonNoSocketObserved}} {
		e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
		if !f.haveKey || len(m.values) != 1 {
			t.Fatal("inconclusive result revoked")
		}
	}
	if s.backgroundInconclusive != 4 {
		t.Fatal("missing diagnostic")
	}
}
func TestConnectionPositiveNewOwnerRevokesWithoutPermissionTransfer(t *testing.T) {
	for _, change := range []string{"exe", "prefix", "uid", "revision"} {
		t.Run(change, func(t *testing.T) {
			e, s, f, a, m := connectionFixture(t)
			switch change {
			case "exe":
				a.Application.Executable = "/synthetic/beta.exe"
			case "prefix":
				a.Application.Prefix = "/synthetic/prefix-two"
				a.Table.Prefix = a.Application.Prefix
			case "uid":
				a.Owners[0].UID = 1001
				a.Table.UID = 1001
			case "revision":
				a.Application.Revision = "new-revision"
			}
			a.Application.Key = identity.ApplicationKey(a.Owners[0].UID, *a.Application)
			e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
			if f.haveKey || len(m.values) != 0 || s.confirmedChanges != 1 {
				t.Fatal("confirmed change retained original grant")
			}
		})
	}
}
func TestConnectionClosureIsPositiveKernelEvidenceNotInactivity(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	f.lastPacket = 1
	s.socketSnapshot = func() ([]identity.Socket, error) { return a.Sockets, nil }
	e.sweepConnectionSockets(s)
	if !f.haveKey {
		t.Fatal("idle live socket expired")
	}
	s.socketSnapshot = func() ([]identity.Socket, error) { return nil, errors.New("inconclusive") }
	e.sweepConnectionSockets(s)
	if !f.haveKey {
		t.Fatal("failed dump expired")
	}
	s.socketSnapshot = func() ([]identity.Socket, error) { return nil, nil }
	e.sweepConnectionSockets(s)
	if f.haveKey || len(m.values) != 0 {
		t.Fatal("closed socket retained")
	}
}
func TestConnectionPolicyEditClearsAndInvalidatesInFlight(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	ticket := s.store.Begin()
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	e.finishSocketAuthorizationLocked(s, f, ticket, a)
	if len(s.flows) != 0 || len(m.values) != 0 {
		t.Fatal("policy-revoked flow restored")
	}
}
func TestConnectionTemporaryRuleHorizonAndNoRuleDecisionCannotSeed(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	if err := s.store.Forget(f.key); err != nil {
		t.Fatal(err)
	}
	f.haveKey = false
	e.rules[0].Expires = e.Now().Add(2 * time.Second)
	before := socketgrant.BootNow()
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	deadline := m.values[f.key].Deadline
	if !f.haveKey || deadline <= before+uint64(time.Second) || deadline > socketgrant.BootNow()+uint64(2*time.Second) {
		t.Fatal("temporary permission gained lifetime", deadline)
	}
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	f = &socketFlow{flow: f.flow}
	s.flows[s.flowKey(f.flow)] = f
	// Once/lease-only Allows have no configured app rule. They cannot seed a
	// connection grant even if their original attribution was fully verified.
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if f.haveKey || len(m.values) != 0 {
		t.Fatal("ruleless decision seeded lifetime authorization")
	}
}

func TestConnectionNinthTupleKeepsOrdinaryQueueFallback(t *testing.T) {
	e, s, first, a, m := connectionFixture(t)
	for i := 1; i <= 8; i++ {
		flow := first.flow
		flow.Remote = netip.AddrPortFrom(flow.Remote.Addr(), uint16(9000+i))
		f := &socketFlow{flow: flow}
		s.flows[s.flowKey(flow)] = f
		e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
		if (i < 8) != f.haveKey {
			t.Fatalf("tuple %d: authorized=%v", i+1, f.haveKey)
		}
	}
	if len(m.values) != 8 {
		t.Fatalf("per-application bound changed: %d", len(m.values))
	}
}
