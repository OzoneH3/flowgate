package daemon

import (
	"flowgate/internal/identity"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentReplayWaitsForSettlementReceipt(t *testing.T) {
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
	var calls atomic.Int32
	base := x.e.Resolve
	x.e.Resolve = func(f identity.Flow) identity.Attribution {
		if f.Remote.String() == "192.0.2.7:53" {
			switch calls.Add(1) {
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
	type result struct {
		settled []SettledRequest
		replay  bool
		err     error
	}
	invoke := func(ch chan result) {
		_, _, replay, settled, err := x.e.DecideReviewedSettled(x.e.Generation, target.ID, "allow", "application", "any", x.e.Zones.Revision, pv.Token, 1000, false)
		ch <- result{settled, replay, err}
	}
	first, replay := make(chan result, 1), make(chan result, 1)
	go invoke(first)
	<-firstEntered
	arrival := x.e.Observe(fr, "r")
	close(firstGate)
	<-followEntered
	go invoke(replay)
	var early *result
	select {
	case r := <-replay:
		early = &r
	case <-time.After(100 * time.Millisecond):
	}
	close(followGate)
	a := <-first
	var b result
	if early != nil {
		b = *early
	} else {
		b = <-replay
	}
	if a.err != nil || b.err != nil || !b.replay {
		t.Fatalf("first=%+v replay=%+v", a, b)
	}
	if settledIDs(a.settled)[arrival.ID].State != "allowed" || settledIDs(b.settled)[arrival.ID].State != "allowed" {
		t.Fatalf("concurrent replay returned incomplete receipt: first=%+v replay=%+v", a.settled, b.settled)
	}
}
