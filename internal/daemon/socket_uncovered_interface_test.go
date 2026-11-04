package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"golang.org/x/sys/unix"
	"testing"
)

type installedRouteModel struct {
	*grantModel
	uncoveredWrites int
}

func (m *installedRouteModel) Put(k socketgrant.Key, v socketgrant.Value) error {
	if k.Interface != 3 {
		m.uncoveredWrites++
		return unix.ENODEV
	}
	return m.grantModel.Put(k, v)
}
func TestSocketNewInterfaceStaysQueuedWithoutDisablingSurvivor(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	s.productionSession = true
	s.interfaceCoverage = &SocketInterfaceCoverage{Installed: []SocketInterface{{Index: 3, Name: "existing"}}}
	backend := &installedRouteModel{grantModel: m}
	var err error
	s.store, err = socketgrant.NewConnection(backend)
	if err != nil {
		t.Fatal(err)
	}
	m.values = map[socketgrant.Key]socketgrant.Value{}
	f.haveKey = false
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	before := m.values[f.key]
	// A newly connected link was not present in the activation-time gate set.
	newcomer := *f
	newcomer.flow = identity.WithQueueOutputInterface(f.flow, 7)
	newcomer.haveKey = false
	s.flows[s.flowKey(newcomer.flow)] = &newcomer
	e.finishSocketAuthorizationLocked(s, &newcomer, s.store.Begin(), a)
	if s.failure != nil || s.disabled || backend.uncoveredWrites != 0 {
		t.Fatal("new interface poisoned accelerator", s.failure, s.disabled, backend.uncoveredWrites)
	}
	if !f.haveKey || m.values[f.key] != before || len(m.values) != 1 {
		t.Fatal("survivor grant disrupted")
	}
	if s.flows[s.flowKey(newcomer.flow)] != nil {
		t.Fatal("uncovered flow kept as acceleration candidate")
	}
	if s.observeQueueRoute(newcomer.flow) {
		t.Fatal("uncovered queue route admitted")
	}
	// Refusal is acceleration-only: current explicit application policy still allows
	// the new path through the ordinary queue, with no invented permission.
	action, _, _ := e.evaluateClassifiedLocked(e.rules, newcomer.flow, a, e.Now())
	if action != "allow" {
		t.Fatal("ordinary policy changed", action)
	}
}

func TestSocketCoveredRouteStillReportsBackendWriteFailure(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	s.productionSession = true
	s.interfaceCoverage = &SocketInterfaceCoverage{Installed: []SocketInterface{{Index: 3}}}
	f.haveKey = false
	m.failPut = true
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if s.failure == nil {
		t.Fatal("covered map failure hidden")
	}
}
