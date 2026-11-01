package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
)

func TestSocketHandoffWaitsForOwnVerdictsAndUnreadFence(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	s.store.Forget(f.key)
	f.haveKey = false
	s.productionSession = true
	sequence := uint32(2)
	h := e.StartSocketQueueHandoff(func() (uint32, bool) { return sequence, true })
	h.Received(1, f.flow)
	h.Received(2, f.flow)
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if f.haveKey || f.deferredGrant == nil || len(m.values) != 0 {
		t.Fatal("published before queue verdict")
	}
	h.Verdicted(1, true)
	if f.haveKey {
		t.Fatal("other pending verdict ignored")
	}
	sequence = 3 // kernel queued an unread packet
	h.Verdicted(2, true)
	if f.haveKey {
		t.Fatal("unread fence ignored")
	}
	h.Received(3, f.flow)
	h.Verdicted(3, true)
	if !f.haveKey || f.deferredGrant != nil || m.values[f.key].Deadline != 0 {
		t.Fatal("drained flow did not gain lifetime grant")
	}
	// An unrelated packet cannot remove or hold an established grant.
	other := f.flow
	other.Remote = f.flow.Local
	h.Received(4, other)
	if !f.haveKey || len(m.values) != 1 {
		t.Fatal("unrelated flow changed existing grant")
	}
}
func TestSocketHandoffCannotPublishOldPolicyOrFailedWrite(t *testing.T) {
	for _, mode := range []string{"edit", "deny", "failed", "missing-fence"} {
		t.Run(mode, func(t *testing.T) {
			e, s, f, a, m := connectionFixture(t)
			s.store.Forget(f.key)
			f.haveKey = false
			s.productionSession = true
			h := e.StartSocketQueueHandoff(func() (uint32, bool) { return 1, mode != "missing-fence" })
			h.Received(1, f.flow)
			e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
			if mode == "deny" {
				r := e.rules[0]
				r.Action = "block"
				if err := e.SetRules([]policy.Rule{r}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "edit" {
				if err := e.SetRules(nil); err != nil {
					t.Fatal(err)
				}
			}
			h.Verdicted(1, mode != "failed")
			if f.haveKey || len(m.values) != 0 {
				t.Fatal("invalid handoff published")
			}
		})
	}
}
func TestSocketHandoffNoFlowPermissionFromHighWater(t *testing.T) {
	e, s, f, a, m := connectionFixture(t)
	s.store.Forget(f.key)
	f.haveKey = false
	s.productionSession = true
	h := e.StartSocketQueueHandoff(func() (uint32, bool) { return 2, true })
	h.Received(1, f.flow)
	h.Received(2, identity.Flow{})
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if f.haveKey {
		t.Fatal("high water replaced pending verdict")
	}
	h.Verdicted(1, true)
	if !f.haveKey || len(m.values) != 1 {
		t.Fatal("completed exact flow not published")
	}
}
