package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"flowgate/internal/identity"
)

// Once a prior revalidation has ended the request, its later lease operation
// still has to report the other prompts it settles in the acknowledgement.
func TestEndedLeaseAckIncludesFollowupSettlement(t *testing.T) {
	x, _, ended, queued := endedFixture(t)
	x.e.mu.Lock()
	for _, row := range x.e.events {
		if row.ID == ended.ID {
			row.State = "expired"
		}
	}
	x.e.mu.Unlock()
	_, settled, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "block", 0, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if stateOf(x.e, queued.ID) != "blocked" {
		t.Fatal("follow-up did not settle queued request")
	}
	if settledIDs(settled)[queued.ID].State != "blocked" {
		t.Fatalf("follow-up settled the request but omitted it from acknowledgement: %+v", settled)
	}
}

// midPrefetchArrival pauses the decision's ownership batch on an unrelated
// pending request, lets request R (same application and remote) arrive, then
// resumes. R was not selected by the batch, so only the in-operation follow-up
// can settle it before the acknowledgement is built.
func midPrefetchArrival(t *testing.T, decide func(e *Engine, target Event) []SettledRequest) (*Engine, Event, []SettledRequest) {
	t.Helper()
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	_, target := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "t")
	_, _ = x.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.7:53", "q")
	fr, _ := identity.ParseFlow("tcp", "outgoing", "10.0.0.1:40003", "192.0.2.1:443")
	ra := whileAttribution(p, "app", "rev", "/opt/app")
	ra.Fingerprint += "|10.0.0.1:40003>192.0.2.1:443"
	x.owners["10.0.0.1:40003>192.0.2.1:443"] = ra
	base := x.e.Resolve
	gate, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	x.e.Resolve = func(f identity.Flow) identity.Attribution {
		if f.Remote.String() == "192.0.2.7:53" {
			once.Do(func() { close(entered); <-gate })
		}
		return base(f)
	}
	done := make(chan []SettledRequest, 1)
	go func() { done <- decide(x.e, target) }()
	<-entered
	r := x.e.Observe(fr, "r")
	if r.State != "awaiting-decision" {
		t.Fatalf("arrival: %s", r.State)
	}
	close(gate)
	settled := <-done
	if got := stateOf(x.e, r.ID); got != "allowed" {
		t.Fatalf("remembered rule did not settle the arrival: %q", got)
	}
	return x.e, r, settled
}

func TestDecisionAckIncludesRequestArrivingDuringPrefetch(t *testing.T) {
	_, r, settled := midPrefetchArrival(t, func(e *Engine, target Event) []SettledRequest {
		_, settled, err := e.DecideSettled(target.ID, "allow", "application", 0, 1000, false)
		if err != nil {
			t.Error(err)
		}
		return settled
	})
	if settledIDs(settled)[r.ID].State != "allowed" {
		t.Fatalf("follow-up settlement missing from acknowledgement: %+v", settled)
	}
}

func TestReplayedReviewedDecisionReportsFollowupSettlement(t *testing.T) {
	var replay []SettledRequest
	_, r, settled := midPrefetchArrival(t, func(e *Engine, target Event) []SettledRequest {
		pv, err := e.PreviewDecision(e.Generation, target.ID, "allow", "application", "any", e.Zones.Revision, 1000, false)
		if err != nil {
			t.Error(err)
			return nil
		}
		_, _, replayed, first, err := e.DecideReviewedSettled(e.Generation, target.ID, "allow", "application", "any", e.Zones.Revision, pv.Token, 1000, false)
		if err != nil || replayed {
			t.Errorf("first commit: replayed=%v err=%v", replayed, err)
		}
		_, _, replayed, replay, err = e.DecideReviewedSettled(e.Generation, target.ID, "allow", "application", "any", e.Zones.Revision, pv.Token, 1000, false)
		if err != nil || !replayed {
			t.Errorf("replay: replayed=%v err=%v", replayed, err)
		}
		return first
	})
	if settledIDs(settled)[r.ID].State != "allowed" || settledIDs(replay)[r.ID].State != "allowed" {
		t.Fatalf("follow-up settlement missing: first=%+v replay=%+v", settled, replay)
	}
}

func TestReplayPastReceiptWaitReportsPendingNotPartialReceipt(t *testing.T) {
	saved := receiptWait
	receiptWait = 50 * time.Millisecond
	defer func() { receiptWait = saved }()
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	_, target := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "t")
	_, _ = x.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.7:53", "q")
	fr, _ := identity.ParseFlow("tcp", "outgoing", "10.0.0.1:40003", "192.0.2.1:443")
	ra := whileAttribution(p, "app", "rev", "/opt/app")
	ra.Fingerprint += "|10.0.0.1:40003>192.0.2.1:443"
	x.owners["10.0.0.1:40003>192.0.2.1:443"] = ra
	pv, err := x.e.PreviewDecision(x.e.Generation, target.ID, "allow", "application", "any", x.e.Zones.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	firstEntered, followEntered := make(chan struct{}), make(chan struct{})
	firstGate, followGate := make(chan struct{}), make(chan struct{})
	calls := 0
	var mu sync.Mutex
	base := x.e.Resolve
	x.e.Resolve = func(f identity.Flow) identity.Attribution {
		if f.Remote.String() == "192.0.2.7:53" {
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			switch n {
			case 1:
				close(firstEntered)
				<-firstGate
			case 2:
				close(followEntered)
				<-followGate
			}
		}
		return base(f)
	}
	decide := func() (bool, []SettledRequest, error) {
		_, _, replayed, settled, err := x.e.DecideReviewedSettled(x.e.Generation, target.ID, "allow", "application", "any", x.e.Zones.Revision, pv.Token, 1000, false)
		return replayed, settled, err
	}
	first := make(chan []SettledRequest, 1)
	go func() {
		_, s, err := decide()
		if err != nil {
			t.Error(err)
		}
		first <- s
	}()
	<-firstEntered
	arrival := x.e.Observe(fr, "r")
	close(firstGate)
	<-followEntered
	replayed, settled, err := decide() // first call is stalled in its follow-up
	if !replayed || err == nil || !strings.Contains(err.Error(), "do not resubmit") || settled != nil {
		t.Fatalf("stalled receipt must report pending, not a partial list: replayed=%v settled=%+v err=%v", replayed, settled, err)
	}
	close(followGate)
	if settledIDs(<-first)[arrival.ID].State != "allowed" {
		t.Fatal("first acknowledgement incomplete")
	}
	replayed, settled, err = decide()
	if err != nil || !replayed || settledIDs(settled)[arrival.ID].State != "allowed" {
		t.Fatalf("later replay must return the completed receipt: %v %+v %v", replayed, settled, err)
	}
}
