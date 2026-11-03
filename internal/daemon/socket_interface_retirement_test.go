package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"testing"
)

type retiringGrantModel struct {
	*grantModel
	failRetire bool
}

func (m *retiringGrantModel) RetireInterface(uint32) error {
	if m.failRetire {
		return errors.New("injected retirement failure")
	}
	return nil
}
func TestSocketInterfaceRetirementKeepsSurvivingConnection(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	backend := &retiringGrantModel{grantModel: m}
	var err error
	s.store, err = socketgrant.NewConnection(backend)
	if err != nil {
		t.Fatal(err)
	}
	m.values = map[socketgrant.Key]socketgrant.Value{}
	f.haveKey = false
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	other := *f
	other.flow = identity.WithQueueOutputInterface(other.flow, 4)
	other.haveKey = false
	s.flows[s.flowKey(other.flow)] = &other
	e.finishSocketAuthorizationLocked(s, &other, s.store.Begin(), a)
	if !other.haveKey || len(m.values) != 2 {
		t.Fatal("fixture missing other connection")
	}
	saved := m.values[other.key]
	ticket := s.store.Begin()
	s.interfaceCoverage = &SocketInterfaceCoverage{Installed: []SocketInterface{{Index: 3, Name: "removed"}, {Index: 4, Name: "survivor"}}}
	if err = e.RetireSocketInterface(3, "deleted"); err != nil {
		t.Fatal(err)
	}
	if s.disabled || s.failure != nil || !other.haveKey || m.values[other.key] != saved || len(m.values) != 1 || len(s.flows) != 1 {
		t.Fatal("surviving connection disrupted")
	}
	e.finishSocketAuthorizationLocked(s, f, ticket, a)
	if len(m.values) != 1 || f.haveKey {
		t.Fatal("stale observation resurrected removed interface")
	}
	if len(s.interfaceCoverage.Installed) != 1 || s.interfaceCoverage.Installed[0].Index != 4 || len(s.interfaceCoverage.Retired) != 1 {
		t.Fatal("coverage not updated")
	}
	if s.observeQueueRoute(f.flow) {
		t.Fatal("retired route accepted")
	}
}
func TestSocketInterfaceRetirementFailureRevokesAll(t *testing.T) {
	e, s, _, _, m := connectionFixture(t)
	backend := &retiringGrantModel{grantModel: m, failRetire: true}
	var err error
	s.store, err = socketgrant.NewConnection(backend)
	if err != nil {
		t.Fatal(err)
	}
	m.values = map[socketgrant.Key]socketgrant.Value{}
	if e.RetireSocketInterface(3, "deleted") == nil || s.failure == nil || !s.disabled || len(m.values) != 0 {
		t.Fatal("unconfirmed retirement did not fail safe")
	}
}
