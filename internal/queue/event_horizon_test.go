package queue

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"flowgate/internal/daemon"
	"flowgate/internal/queuehealth"
)

// A cached allowed event may be reused by Observe until just before its
// Deadline. That Deadline is the event cache lifetime, not a packet horizon:
// an allowed packet whose own deadline is still live must not be dropped as a
// deadline rejection because the reused event aged out before the verdict.
func TestAllowedPacketNotDroppedWhenReusedEventLifetimeEndsBeforeVerdict(t *testing.T) {
	var expired atomic.Uint64
	var sent []bool
	var rejections []queuehealth.Cause
	p := packetProcessor{ctx: context.Background(), expired: &expired, policyEpoch: func() uint64 { return 0 },
		record:     func(daemon.Event, string, error) {},
		diagnostic: func(c queuehealth.Cause) { rejections = append(rejections, c) },
		verdict: func(_ uint32, allow bool, _ func() bool) (bool, error) {
			sent = append(sent, allow)
			return allow, nil
		}}
	j := packetJob{id: 1, deadline: time.Now().Add(time.Minute)}
	p.finish(j, daemon.Event{State: "allowed", Deadline: time.Now().Add(-time.Millisecond)})
	if len(sent) != 1 || !sent[0] || expired.Load() != 0 || len(rejections) != 0 {
		t.Fatalf("allowed packet with a live packet deadline was dropped: sent=%v expired=%d rejections=%v", sent, expired.Load(), rejections)
	}
}

// The Ask (awaiting-decision) deadline remains authoritative: an expired pending
// decision is never retained or admitted.
func TestExpiredAwaitingDecisionStillDropped(t *testing.T) {
	var expired atomic.Uint64
	var sent []bool
	retained := false
	p := packetProcessor{ctx: context.Background(), expired: &expired, policyEpoch: func() uint64 { return 0 },
		record:     func(daemon.Event, string, error) {},
		diagnostic: func(queuehealth.Cause) {},
		retain:     func(uint32, int, daemon.Event) bool { retained = true; return true },
		verdict: func(_ uint32, allow bool, _ func() bool) (bool, error) {
			sent = append(sent, allow)
			return allow, nil
		}}
	p.finish(packetJob{id: 2, deadline: time.Now().Add(time.Minute)}, daemon.Event{State: "awaiting-decision", Deadline: time.Now().Add(-time.Millisecond)})
	if retained || len(sent) != 1 || sent[0] || expired.Load() != 1 {
		t.Fatalf("expired pending decision must be dropped, not retained: retained=%v sent=%v expired=%d", retained, sent, expired.Load())
	}
}

// An expired packet deadline still drops even an allowed event.
func TestExpiredPacketDeadlineStillDropsAllowed(t *testing.T) {
	var expired atomic.Uint64
	var sent []bool
	p := packetProcessor{ctx: context.Background(), expired: &expired, policyEpoch: func() uint64 { return 0 },
		record:     func(daemon.Event, string, error) {},
		diagnostic: func(queuehealth.Cause) {},
		verdict: func(_ uint32, allow bool, _ func() bool) (bool, error) {
			sent = append(sent, allow)
			return allow, nil
		}}
	p.finish(packetJob{id: 3, deadline: time.Now().Add(-time.Millisecond)}, daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)})
	if len(sent) != 1 || sent[0] || expired.Load() != 1 {
		t.Fatalf("expired packet deadline must drop: sent=%v expired=%d", sent, expired.Load())
	}
}

// Once and For-a-while admissions are 30-second flow leases: their Deadline is
// the permission horizon and still drops a packet verdicted after it.
func TestExpiredOnceAndWhileAdmissionsStillDrop(t *testing.T) {
	for _, rule := range []string{"once:x", "while:y"} {
		var expired atomic.Uint64
		var sent []bool
		p := packetProcessor{ctx: context.Background(), expired: &expired, policyEpoch: func() uint64 { return 0 },
			record:     func(daemon.Event, string, error) {},
			diagnostic: func(queuehealth.Cause) {},
			verdict: func(_ uint32, allow bool, valid func() bool) (bool, error) {
				sent = append(sent, allow)
				if valid() {
					t.Fatalf("%s: an expired lease must not permit a retried Allow", rule)
				}
				return allow, nil
			}}
		p.finish(packetJob{id: 4, deadline: time.Now().Add(time.Minute)}, daemon.Event{State: "allowed", Rule: rule, Deadline: time.Now().Add(-time.Millisecond)})
		if len(sent) != 1 || sent[0] || expired.Load() != 1 {
			t.Fatalf("%s: expired admission lease must drop: sent=%v expired=%d", rule, sent, expired.Load())
		}
	}
}
