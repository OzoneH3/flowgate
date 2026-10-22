package queue

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"sync/atomic"
	"testing"
	"time"
)

func fillAdmission(t *testing.T, w *packetWorkers) {
	t.Helper()
	for i := 0; i < MaxAttributionPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("fill", i)
		}
	}
}

func TestAdmissionWaitResumesWithoutIncreasingBounds(t *testing.T) {
	started := make(chan uint32, 100)
	release := make(chan struct{})
	w := newPacketWorkers(1, func(p packetJob, _ bool) {
		started <- p.id
		if p.id == 0 {
			<-release
		}
	})
	defer w.stop()
	fillAdmission(t, w)
	receiveID(t, started)
	result := make(chan bool, 1)
	go func() { result <- w.submitWait(context.Background(), job(100, 9000)) }()
	select {
	case <-result:
		t.Fatal("full budget was dropped immediately")
	case <-time.After(20 * time.Millisecond):
	}
	w.mu.Lock()
	count := w.count
	w.mu.Unlock()
	if count != MaxAttributionPackets {
		t.Fatal("budget changed", count)
	}
	close(release)
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("space not reused")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter stuck")
	}
	seen := map[uint32]int{}
	for len(seen) < MaxAttributionPackets {
		seen[receiveID(t, started)]++
	}
	if seen[100] != 1 {
		t.Fatal("waiting packet not processed exactly once", seen)
	}
}

func TestAdmissionWaitBoundedCancelledAndStopped(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel", "stop"} {
		t.Run(mode, func(t *testing.T) {
			w := newPacketWorkers(0, func(packetJob, bool) {})
			fillAdmission(t, w)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := job(100, 9000)
			p.deadline = time.Now().Add(30 * time.Millisecond)
			if mode == "cancel" {
				cancel()
			}
			if mode == "stop" {
				w.stop()
			}
			begin := time.Now()
			if w.submitWait(ctx, p) {
				t.Fatal("admitted without space")
			}
			if time.Since(begin) > time.Second {
				t.Fatal("unbounded wait")
			}
			w.mu.Lock()
			count := w.count
			w.mu.Unlock()
			if count != MaxAttributionPackets {
				t.Fatal(count)
			}
			w.stop()
		})
	}
}

func TestAdmissionWaitDoesNotStallForEndpointLimit(t *testing.T) {
	w := newPacketWorkers(0, func(packetJob, bool) {})
	defer w.stop()
	for i := 0; i < MaxAttributionPerEndpoint; i++ {
		if !w.submit(job(uint32(i), 8000)) {
			t.Fatal(i)
		}
	}
	begin := time.Now()
	if w.submitWait(context.Background(), job(100, 8000)) {
		t.Fatal("endpoint bound exceeded")
	}
	if time.Since(begin) > AdmissionWait/2 {
		t.Fatal("endpoint pressure blocked receive callback")
	}
	if !w.submitWait(context.Background(), job(101, 8001)) {
		t.Fatal("independent endpoint blocked")
	}
}

func TestReceiveOverflowIsReportedWithoutStoppingProtection(t *testing.T) {
	var count atomic.Uint64
	failed := false
	fail := func(error) { failed = true }
	if receiveError(fmt.Errorf("netlink: %w", unix.ENOBUFS), &count, fail) != 0 || count.Load() != 1 || failed {
		t.Fatal("overflow stopped receiver")
	}
	if receiveError(unix.EBADF, &count, fail) != -1 || !failed || count.Load() != 1 {
		t.Fatal("fatal receive error hidden")
	}
}

func TestAdmissionWaitInterruptsAnAlreadyWaitingCallback(t *testing.T) {
	for _, stop := range []bool{false, true} {
		w := newPacketWorkers(0, func(packetJob, bool) {})
		fillAdmission(t, w)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan bool, 1)
		go func() { result <- w.submitWait(ctx, job(100, 9000)) }()
		select {
		case <-result:
			t.Fatal("not waiting")
		case <-time.After(20 * time.Millisecond):
		}
		if stop {
			w.stop()
		} else {
			cancel()
		}
		select {
		case ok := <-result:
			if ok {
				t.Fatal("cancelled packet admitted")
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("shutdown waited for admission timeout")
		}
		cancel()
		w.stop()
	}
}
