package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"testing"
	"time"
)

func TestSocketOrdinaryRiskIncludesDueLateness(t *testing.T) {
	now := time.Now()
	f := &socketFlow{runtime: true, haveKey: true, deadline: 1000 + uint64(130*time.Millisecond), next: now.Add(-25 * time.Millisecond)}
	f.noteRenewalDuration(90 * time.Millisecond)
	if !renewalAtRisk(f, now, 1000) {
		t.Fatal("late due renewal not protected")
	}
	f.next = now.Add(time.Second)
	if renewalAtRisk(f, now, 1000) {
		t.Fatal("not due")
	}
	f.busy = true
	f.verificationStarted = now.Add(-70 * time.Millisecond)
	if renewalAtRisk(f, now, 1000) {
		t.Fatal("running estimate failed to subtract elapsed")
	}
	f.deadline = 999
	if !renewalAtRisk(f, now, 1000) {
		t.Fatal("expired renewal not detected")
	}
	f.runtime = false
	if renewalAtRisk(f, now, 1000) {
		t.Fatal("native work affected")
	}
}
func TestSocketOrdinaryWaitCompletesWithoutConsumingEvidence(t *testing.T) {
	e, s, f, _, _ := wineGrantFixture(t)
	s.ordinaryYield = true
	f.runtime = true
	f.haveKey = true
	f.busy = true
	f.deadline = socketgrant.BootNow() + uint64(time.Millisecond)
	f.verificationStarted = time.Now()
	f.noteRenewalDuration(50 * time.Millisecond)
	f.observationDone = make(chan struct{})
	done := f.observationDone
	flow := identity.Flow{}
	finished := make(chan struct{})
	go func() { e.yieldSocketOrdinaryScan(s, flow); close(finished) }()
	// Taking the lock is possible during the wait. Closing is the only release
	// signal; no attribution is provided to the waiting ordinary scan.
	time.Sleep(5 * time.Millisecond)
	e.mu.Lock()
	close(done)
	f.observationDone = nil
	e.mu.Unlock()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("wait stuck")
	}
	if s.ordinaryYieldCount != 1 || s.ordinaryYieldCaps != 0 {
		t.Fatalf("counters: %d/%d", s.ordinaryYieldCount, s.ordinaryYieldCaps)
	}
}
func TestSocketOrdinaryWaitHardCapAndTrackedBypass(t *testing.T) {
	e, s, f, _, _ := wineGrantFixture(t)
	s.ordinaryYield = true
	f.runtime = true
	f.haveKey = true
	f.busy = true
	f.deadline = socketgrant.BootNow() + 1
	f.noteRenewalDuration(time.Millisecond)
	started := time.Now()
	e.yieldSocketOrdinaryScan(s, identity.Flow{})
	if time.Since(started) < socketOrdinaryYieldLimit || s.ordinaryYieldCaps != 1 {
		t.Fatal("no hard wait cap")
	}
	count := s.ordinaryYieldCount
	e.yieldSocketOrdinaryScan(s, f.flow)
	if s.ordinaryYieldCount != count {
		t.Fatal("tracked flow entered ordinary wait")
	}
}

func TestSocketInitialAdmissionTicketStartsAfterWait(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	delete(s.flows, f.flow.Key())
	s.ordinaryObserved = func(identity.Flow) (identity.Attribution, uint64) { t.Fatal("wrong resolver"); return a, 0 }
	var scan uint64
	s.ordinaryAdmission = func(_ identity.Flow, before func()) (identity.Attribution, uint64) {
		// The hook may wait; even with no at-risk peer, prove the ticket is taken
		// immediately at actual scan admission rather than at dispatch entry.
		time.Sleep(3 * time.Millisecond)
		before()
		scan = socketgrant.BootNow()
		return a, scan
	}
	if _, ok := e.resolveSocketInitialBatch(f.flow); !ok {
		t.Fatal("not resolved")
	}
	if len(m.values) != 1 {
		t.Fatal("fresh merge did not publish")
	}
	for _, v := range m.values {
		start := v.Deadline - uint64(socketgrant.Window)
		if start > scan || scan-start > uint64(2*time.Millisecond) {
			t.Fatal("ticket includes pre-scan wait")
		}
	}
}
func TestSocketInitialAdmissionPolicyEditAfterScanRefuses(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	delete(s.flows, f.flow.Key())
	s.ordinaryObserved = func(identity.Flow) (identity.Attribution, uint64) { return a, 0 }
	s.ordinaryAdmission = func(_ identity.Flow, before func()) (identity.Attribution, uint64) {
		before()
		scan := socketgrant.BootNow()
		e.mu.Lock()
		e.rules[0].Action = "block"
		if err := e.revokeSocketGrantsLocked(); err != nil {
			t.Fatal(err)
		}
		e.mu.Unlock()
		return a, scan
	}
	e.resolveSocketInitialBatch(f.flow)
	if len(m.values) != 0 {
		t.Fatal("edit during observation allowed")
	}
}
