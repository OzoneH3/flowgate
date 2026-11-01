package queue

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPBatchFreezesMembershipAndProtectsAllActivePackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	batches := make(chan []uint32, 8)
	w := newPacketBatchLanes(0, 0, func(p packetJob, _, _ bool) bool { batches <- []uint32{p.id}; return true }, func(js []packetJob, _, _ bool) bool {
		ids := []uint32{}
		for _, j := range js {
			ids = append(ids, j.id)
		}
		batches <- ids
		select {
		case <-release:
		case <-ctx.Done():
		}
		return true
	}, nil)
	defer func() { cancel(); w.stop() }()
	for i := uint32(1); i <= 2; i++ {
		if !w.submit(job(i, 8000)) {
			t.Fatal("submit")
		}
	}
	w.wg.Add(1)
	go w.run(0)
	select {
	case ids := <-batches:
		if !reflect.DeepEqual(ids, []uint32{1, 2}) {
			t.Fatal(ids)
		}
	case <-time.After(time.Second):
		t.Fatal("no batch")
	}
	w.mu.Lock()
	victim := w.displaceLocked(job(99, 9000), job(99, 9000).key(), 0)
	charged := w.count == 2 && w.bytes == 200 && w.activeBatch[job(1, 8000).key()] == 2
	w.mu.Unlock()
	if victim != nil || !charged {
		t.Fatal("active batch was displaceable or uncharged", victim, charged)
	}
	if !w.submit(job(3, 8000)) {
		t.Fatal("late submit")
	}
	close(release)
	select {
	case ids := <-batches:
		if !reflect.DeepEqual(ids, []uint32{3}) {
			t.Fatal("late arrival shared old check", ids)
		}
	case <-time.After(time.Second):
		t.Fatal("late arrival stuck")
	}
	waitWorkerState(t, w, func() bool { return w.count == 0 && w.bytes == 0 })
}

func TestUDPBatchSeparatesFlowsTokensAndTCP(t *testing.T) {
	batches := make(chan []uint32, 8)
	emit := func(js []packetJob, _, _ bool) bool {
		ids := []uint32{}
		for _, j := range js {
			ids = append(ids, j.id)
		}
		batches <- ids
		return true
	}
	w := newPacketBatchLanes(0, 0, func(j packetJob, a, b bool) bool { return emit([]packetJob{j}, a, b) }, emit, nil)
	defer w.stop()
	a, b, c, d, e := job(1, 8000), job(2, 8000), job(3, 8000), job(4, 8000), job(5, 8000)
	c.token = "different"
	d.flow.Remote = job(1, 9000).flow.Local
	e.flow.Protocol = "tcp"
	for _, j := range []packetJob{a, b, c, d, e} {
		if !w.submit(j) {
			t.Fatal("submit")
		}
	}
	w.wg.Add(1)
	go w.run(0)
	groups := map[uint32][]uint32{}
	for i := 0; i < 4; i++ {
		select {
		case ids := <-batches:
			groups[ids[0]] = ids
		case <-time.After(time.Second):
			t.Fatal("stalled")
		}
	}
	if !reflect.DeepEqual(groups, map[uint32][]uint32{1: {1, 2}, 3: {3}, 4: {4}, 5: {5}}) {
		t.Fatal(groups)
	}
}

func TestUDPBatchCensusTransferKeepsBoundsAndOrder(t *testing.T) {
	got := make(chan []uint32, 1)
	w := newPacketBatchLanes(0, 1, func(packetJob, bool, bool) bool { t.Error("unexpected single"); return true }, func(js []packetJob, stop, census bool) bool {
		if !census {
			return false
		}
		ids := []uint32{}
		for _, j := range js {
			ids = append(ids, j.id)
		}
		got <- ids
		return true
	}, func(packetJob, rejectionCause) { t.Error("unexpected reject") })
	defer w.stop()
	for i := uint32(1); i <= 16; i++ {
		if !w.submit(job(i, 8000)) {
			t.Fatal("submit")
		}
	}
	w.wg.Add(1)
	go w.run(0)
	select {
	case ids := <-got:
		if len(ids) != 16 || ids[0] != 1 || ids[15] != 16 {
			t.Fatal(ids)
		}
	case <-time.After(time.Second):
		t.Fatal("transfer stalled")
	}
	waitWorkerState(t, w, func() bool { return w.count == 0 && w.bytes == 0 && w.censusCount == 0 && w.censusBytes == 0 })
}

func TestUDPBatchPacketDeadlinesAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "busy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var expired atomic.Uint64
			sent := map[uint32]bool{}
			js := []packetJob{job(1, 8000), job(2, 8000)}
			p := packetProcessor{ctx: ctx, expired: &expired, record: func(daemon.Event, string, error) {}, verdict: func(id uint32, allow bool, _ func() bool) (bool, error) { sent[id] = allow; return allow, nil }, batchObserve: func(_ identity.Flow, _ string, n int, _ bool) (func() daemon.Event, bool) {
				if mode == "busy" {
					return nil, false
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "deadline" {
					js[1].deadline = time.Now().Add(-time.Second)
				}
				return func() daemon.Event { return daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)} }, true
			}}
			done := p.processBatch(js, false, false)
			if mode == "busy" {
				if done || len(sent) != 0 {
					t.Fatal("deferred batch had side effects")
				}
				return
			}
			if !done || len(sent) != 2 {
				t.Fatal("not exactly one verdict per packet", sent)
			}
			if mode == "cancel" && (sent[1] || sent[2]) {
				t.Fatal("cancelled allow")
			}
			if mode == "deadline" && (!sent[1] || sent[2]) {
				t.Fatal("deadline shared across batch", sent)
			}
		})
	}
}

func TestUDPBatchPolicyEditBetweenVerdictsAppliesToRemainingPackets(t *testing.T) {
	e := daemon.New(time.Minute)
	e.LocalPeer = nil
	app := identity.Application{Kind: "native", Key: "synthetic", Revision: "r1"}
	calls := 0
	e.Resolve = func(identity.Flow) identity.Attribution {
		calls++
		return identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000, Start: "1"}}, Fingerprint: "owner"}
	}
	rule := policy.Rule{ID: "app", Action: "allow", Filter: policy.Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Direction: "outgoing", Protocol: "udp"}}
	if err := e.SetRules([]policy.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	var expired atomic.Uint64
	verdicts := []bool{}
	p := packetProcessor{ctx: context.Background(), expired: &expired, batchObserve: e.PrepareUDPBatch, record: func(daemon.Event, string, error) {}, verdict: func(_ uint32, allow bool, _ func() bool) (bool, error) {
		verdicts = append(verdicts, allow)
		if len(verdicts) == 1 {
			rule.Action = "block"
			rule.Version++
			if err := e.SetRules([]policy.Rule{rule}); err != nil {
				t.Fatal(err)
			}
		}
		return allow, nil
	}}
	if !p.processBatch([]packetJob{job(1, 8000), job(2, 8000), job(3, 8000)}, false, true) {
		t.Fatal("deferred")
	}
	if calls != 1 || !reflect.DeepEqual(verdicts, []bool{true, false, false}) {
		t.Fatal(calls, verdicts)
	}
}
