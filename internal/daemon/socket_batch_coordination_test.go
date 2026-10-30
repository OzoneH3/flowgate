package daemon

import (
	"context"
	"flowgate/internal/identity"
	"testing"
	"time"
)

func awaitBatchClaim(t *testing.T, e *Engine, f *socketFlow) *socketBatchRequest {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		r := f.batchPending
		e.mu.Unlock()
		if r != nil {
			return r
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("batch never registered")
	return nil
}

func TestSocketBatchFollowupNeverConsumesInFlightObservation(t *testing.T) {
	e, s, f, a, _ := wineGrantFixture(t)
	s.batchCoordination = true
	s.resolve = func(identity.Flow) identity.Attribution { return a }
	s.wake = make(chan struct{}, 1)
	f.busy = true
	s.active = 1
	old := a
	old.Fingerprint = "old-before-freeze"
	got := make(chan identity.Attribution, 1)
	go func() {
		v, ok := e.resolveSocketBatch(f.flow)
		if !ok {
			got <- identity.Attribution{}
		} else {
			got <- v
		}
	}()
	r := awaitBatchClaim(t, e, f)
	e.mu.Lock()
	// Completing the old job must NOT satisfy the newly registered request.
	s.completeSocketBatchLocked(f, &old, true)
	f.busy = false
	s.active = 0
	if s.nextRenewal(time.Now(), 1) != f {
		t.Fatal("pending batch not immediately eligible")
	}
	select {
	case <-r.result:
		t.Fatal("old result reused")
	default:
	}
	// Simulate the scheduler's lock-protected next selection and new ticket.
	f.busy = true
	s.active = 1
	ticket := s.store.Begin()
	started := time.Now()
	s.startSocketBatchLocked(f, started)
	e.mu.Unlock()
	fresh := a
	fresh.Fingerprint = "fresh-after-freeze"
	s.resolve = func(identity.Flow) identity.Attribution { return fresh }
	e.resolveSocketRenewalGroup(context.Background(), s, []*socketFlow{f}, ticket, started)
	select {
	case v := <-got:
		if v.Fingerprint != fresh.Fingerprint {
			t.Fatal(v.Fingerprint)
		}
	case <-time.After(time.Second):
		t.Fatal("no follow-up result")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.batchPending != nil || f.batchRunning != nil || f.busy || s.active != 0 || s.batchDelivered != 1 {
		t.Fatal("claim/job leak")
	}
}

func TestSocketBatchRequestAfterBeginWaitsForFollowingScan(t *testing.T) {
	e, s, f, a, _ := wineGrantFixture(t)
	s.batchCoordination = true
	s.resolve = func(identity.Flow) identity.Attribution { return a }
	// First scan has already begun when the frozen batch registers.
	e.mu.Lock()
	s.startSocketBatchLocked(f, time.Now())
	f.busy = true
	s.active = 1
	e.mu.Unlock()
	got := make(chan bool, 1)
	go func() { _, ok := e.resolveSocketBatch(f.flow); got <- ok }()
	r := awaitBatchClaim(t, e, f)
	e.mu.Lock()
	s.completeSocketBatchLocked(f, &a, true)
	if f.batchPending != r {
		t.Fatal("late batch consumed")
	}
	select {
	case <-r.started:
		t.Fatal("late batch attached to old scan")
	default:
	}
	f.busy = false
	s.active = 0
	// It may attach only to another, newly starting scan.
	s.startSocketBatchLocked(f, time.Now())
	s.completeSocketBatchLocked(f, &a, true)
	e.mu.Unlock()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("fresh follow-up failed")
		}
	case <-time.After(time.Second):
		t.Fatal("no completion")
	}
}

func TestSocketBatchBoundedWaitAndSingleClaim(t *testing.T) {
	e, s, f, a, _ := wineGrantFixture(t)
	s.batchCoordination = true
	f.busy = true
	s.active = 1
	s.resolve = func(identity.Flow) identity.Attribution { return a }
	done := make(chan bool, 1)
	go func() { _, ok := e.resolveSocketBatch(f.flow); done <- ok }()
	awaitBatchClaim(t, e, f)
	if _, ok := e.resolveSocketBatch(f.flow); ok {
		t.Fatal("second pending claimant admitted")
	}
	select {
	case ok := <-done:
		if ok {
			t.Fatal("timed-out batch got observation")
		}
	case <-time.After(time.Second):
		t.Fatal("coordination wait unbounded")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.batchPending != nil || f.batchRunning != nil || !f.busy || s.active != 1 || s.batchTimeouts != 1 {
		t.Fatal("timeout changed running work or leaked claim")
	}
}

func TestSocketBatchPendingKeepsEDFAndGroupEligibility(t *testing.T) {
	s, a, b, now, boot := alignmentFixture()
	a.next = now.Add(time.Hour)
	a.batchPending = &socketBatchRequest{frozen: now.Add(-time.Millisecond)}
	a.busy = false
	b.busy = false
	b.next = now.Add(-time.Millisecond)
	a.deadline = boot + 200
	b.deadline = boot + 100
	if s.nextRenewal(now, boot) != b {
		t.Fatal("pending claimant bypassed earlier expiry")
	}
	a.next = now.Add(100 * time.Millisecond)
	if len(s.renewalGroup(b, now)) != 2 {
		t.Fatal("pending claimant prevented grouping")
	}
}

func TestSocketBatchCancellationReleasesClaim(t *testing.T) {
	e, s, f, a, _ := wineGrantFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.batchCoordination = true
	f.busy = true
	s.active = 1
	s.resolve = func(identity.Flow) identity.Attribution { return a }
	done := make(chan bool, 1)
	go func() { _, ok := e.resolveSocketBatch(f.flow); done <- ok }()
	awaitBatchClaim(t, e, f)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("cancelled batch succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.batchPending != nil {
		t.Fatal("claim leaked")
	}
}

func TestSocketBatchFreshFollowupPolicyAndIncomplete(t *testing.T) {
	for _, mode := range []string{"policy-edit", "incomplete", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			e, s, f, a, m := wineGrantFixture(t)
			s.batchCoordination = true
			s.resolve = func(identity.Flow) identity.Attribution { return a }
			f.busy = true
			s.active = 1
			done := make(chan bool, 1)
			go func() { _, ok := e.resolveSocketBatch(f.flow); done <- ok }()
			awaitBatchClaim(t, e, f)
			e.mu.Lock()
			f.busy = false
			s.active = 0
			ticket := s.store.Begin()
			started := time.Now()
			f.busy = true
			s.active = 1
			s.startSocketBatchLocked(f, started)
			if mode == "incomplete" {
				a.VisibilityComplete = false
			}
			if mode == "disabled" {
				s.disabled = true
			}
			e.mu.Unlock()
			if mode == "policy-edit" {
				if err := e.SetRules(nil); err != nil {
					t.Fatal(err)
				}
			}
			e.resolveSocketRenewalGroup(context.Background(), s, []*socketFlow{f}, ticket, started)
			select {
			case ok := <-done:
				if (mode == "disabled") == ok {
					t.Fatal("incorrect completion state", mode, ok)
				}
			case <-time.After(time.Second):
				t.Fatal("no completion")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if len(m.values) != 0 {
				t.Fatal("unsafe authorization published")
			}
			if f.batchRunning != nil || f.batchPending != nil || s.active != 0 {
				t.Fatal("leaked state")
			}
		})
	}
}

func TestSocketBatchMissingGroupEmitReleasesWaiter(t *testing.T) {
	e, s, f, _, _ := wineGrantFixture(t)
	r := &socketBatchRequest{result: make(chan *identity.Attribution, 1)}
	f.batchRunning = r
	f.busy = true
	s.active = 1
	other := &socketFlow{}
	s.resolveGroup = func([]identity.Flow, func(int, *identity.Attribution)) {}
	e.resolveSocketRenewalGroup(context.Background(), s, []*socketFlow{f, other}, s.store.Begin(), time.Now())
	select {
	case a := <-r.result:
		if a != nil {
			t.Fatal("invented result")
		}
	default:
		t.Fatal("missing emit stranded waiter")
	}
	if f.batchRunning != nil || f.busy || s.active != 0 || s.batchMissingEmit != 1 {
		t.Fatal("incomplete cleanup")
	}
}
