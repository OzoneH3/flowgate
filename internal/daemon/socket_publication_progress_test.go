package daemon

import (
	"flowgate/internal/identity"
	"testing"
)

// Successful current proof is sufficient for a production lifetime grant. No
// queue fence, unrelated traffic, or later target packet may be required.
func TestProductionPublicationDoesNotRequireQueueQuietOrAnotherPacket(t *testing.T) {
	for attempt := 0; attempt < 64; attempt++ {
		e, s, f, a, m := connectionFixture(t)
		if err := s.store.Forget(f.key); err != nil {
			t.Fatal(err)
		}
		f.haveKey = false
		s.productionSession = true
		s.interfaceCoverage = &SocketInterfaceCoverage{Installed: []SocketInterface{{Index: 3}}}
		e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
		if !f.haveKey || len(m.values) != 1 || m.values[f.key].Deadline != 0 {
			t.Fatal("valid production proof failed to publish a lifetime grant")
		}
	}
}

func TestProductionUnrelatedAdmissionsDoNotHoldEstablishedGrant(t *testing.T) {
	e, s, established, a, m := connectionFixture(t)
	s.productionSession = true
	s.interfaceCoverage = &SocketInterfaceCoverage{Installed: []SocketInterface{{Index: 3}}}
	key := established.key
	value := m.values[key]
	for i := 0; i < 100; i++ {
		other := &socketFlow{flow: established.flow}
		other.flow.Direction = "incoming"
		s.flows[s.flowKey(other.flow)] = other
		e.finishSocketAuthorizationLocked(s, other, s.store.Begin(), identity.Attribution{})
		if !established.haveKey || m.values[key] != value {
			t.Fatal("unrelated queued admission changed an established lifetime grant")
		}
	}
	// Inconclusive background observations cannot revoke a verified connection.
	e.finishSocketAuthorizationLocked(s, established, s.store.Begin(), identity.Attribution{})
	if !established.haveKey || m.values[key] != value {
		t.Fatal("inconclusive observation interrupted established grant")
	}
	_ = a
}
