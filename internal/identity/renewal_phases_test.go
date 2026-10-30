package identity

import "testing"

func TestRenewalPhaseLogBoundAndSnapshot(t *testing.T) {
	var log renewalPhaseLog
	for i := 0; i < renewalPhaseLimit+2; i++ {
		log.add(renewalPhase{Start: uint64(i), GroupSize: 1})
	}
	rows, lost := log.snapshot()
	if lost != 2 || len(rows) != renewalPhaseLimit || rows[0].Start != 2 {
		t.Fatal("ring bound/order")
	}
	rows[0].Start = 999
	fresh, _ := log.snapshot()
	if fresh[0].Start != 2 {
		t.Fatal("snapshot aliases evidence")
	}
}

func TestRenewalPhasePointerNotRetainedByDispatchCopy(t *testing.T) {
	p := &renewalPhase{Start: 1}
	a := copyWineInitial(Attribution{renewalPhase: p})
	if a.renewalPhase != nil {
		t.Fatal("dispatch copy retained mutable phase pointer")
	}
}

func TestRenewalPhaseNoSessionCompletionWithoutSlot(t *testing.T) {
	m := &WineObservers{census: make(chan struct{}, 1)}
	m.census <- struct{}{}
	p := &renewalPhase{}
	_, done := m.sessionResolvePriority(Flow{}, Attribution{renewalPhase: p}, nil, "", false, true)
	if done || p.SlotRequested == 0 || p.SlotAcquired != 0 || p.SessionDone != 0 {
		t.Fatal("refused acquisition reported completed session", p)
	}
}
