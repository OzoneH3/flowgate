package queue

import (
	"flowgate/internal/daemon"
	"testing"
	"time"
)

func TestUDPCoalescingFreezesOnlyBeforeObservation(t *testing.T) {
	batches := make(chan []uint32, 4)
	release := make(chan struct{})
	emit := func(js []packetJob, _, _ bool) bool {
		var ids []uint32
		for _, j := range js {
			ids = append(ids, j.id)
		}
		batches <- ids
		<-release
		return true
	}
	w := newPacketBatchLanes(0, 0, func(j packetJob, a, b bool) bool { return emit([]packetJob{j}, a, b) }, emit, nil)
	w.coalesceWindow = 30 * time.Millisecond
	defer func() { close(release); w.stop() }()
	if !w.submit(job(1, 8000)) {
		t.Fatal("submit")
	}
	w.wg.Add(1)
	go w.run(0)
	waitWorkerState(t, w, func() bool { return w.active[job(1, 8000).key()] })
	for i := uint32(2); i <= daemon.MaxUDPObservationBatch; i++ {
		if !w.submit(job(i, 8000)) {
			t.Fatal("bounded burst rejected", i)
		}
	}
	select {
	case ids := <-batches:
		if len(ids) != daemon.MaxUDPObservationBatch || ids[0] != 1 || ids[len(ids)-1] != 16 {
			t.Fatal(ids)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced batch not observed")
	}
	if !w.submit(job(17, 8000)) {
		t.Fatal("later arrival")
	}
	w.mu.Lock()
	frozen := w.activeBatch[job(1, 8000).key()]
	w.mu.Unlock()
	if frozen != 16 {
		t.Fatal("later arrival entered frozen observation", frozen)
	}
	release <- struct{}{}
	select {
	case ids := <-batches:
		if len(ids) != 1 || ids[0] != 17 {
			t.Fatal("late arrival inherited observation", ids)
		}
	case <-time.After(time.Second):
		t.Fatal("later observation missing")
	}
}

func TestUDPCoalescingShutdownInterruptsWait(t *testing.T) {
	completed := make(chan bool, 1)
	w := newPacketBatchLanes(0, 0, func(_ packetJob, stop, _ bool) bool { completed <- stop; return true }, func([]packetJob, bool, bool) bool { return true }, nil)
	w.coalesceWindow = time.Hour
	w.submit(job(1, 8000))
	w.wg.Add(1)
	go w.run(0)
	waitWorkerState(t, w, func() bool { return w.active[job(1, 8000).key()] })
	done := make(chan struct{})
	go func() { w.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for coalescing timer")
	}
	if !<-completed {
		t.Fatal("shutdown not passed to processor")
	}
}

func TestUDPCoalescingPreservesDeadlineAndDoesNotDelayTCP(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			processed := make(chan packetJob, 1)
			w := newPacketBatchLanes(0, 0, func(j packetJob, _, _ bool) bool { processed <- j; return true }, func([]packetJob, bool, bool) bool { return true }, nil)
			w.coalesceWindow = time.Hour
			defer w.stop()
			j := job(1, 8000)
			j.flow.Protocol = protocol
			j.deadline = time.Now().Add(20 * time.Millisecond)
			if !w.submit(j) {
				t.Fatal("submit")
			}
			w.wg.Add(1)
			go w.run(0)
			select {
			case got := <-processed:
				if !got.deadline.Equal(j.deadline) {
					t.Fatal("deadline renewed")
				}
			case <-time.After(time.Second):
				t.Fatal("collection ignored deadline or delayed TCP")
			}
		})
	}
}
