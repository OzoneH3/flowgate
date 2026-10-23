package queue

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
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
	ctx := context.Background()
	if receiveError(ctx, fmt.Errorf("netlink: %w", unix.ENOBUFS), &count, fail) != 0 || count.Load() != 1 || failed {
		t.Fatal("overflow stopped receiver")
	}
	if receiveError(ctx, unix.EBADF, &count, fail) != -1 || !failed || count.Load() != 1 {
		t.Fatal("fatal receive error hidden")
	}
}

// A clean stop cancels the context; the library then interrupts Receive with a
// past read deadline. That timeout ends the loop without reporting a failure,
// which would otherwise retain the table fail-closed and refuse the next start.
func TestReceiveInterruptAfterStopIsNotAFailure(t *testing.T) {
	var count atomic.Uint64
	var reported []error
	fail := func(err error) { reported = append(reported, err) }
	ctx, cancel := context.WithCancel(context.Background())
	if receiveError(ctx, os.ErrDeadlineExceeded, &count, fail) != -1 || len(reported) != 1 {
		t.Fatal("receive timeout while running was not fatal")
	}
	cancel()
	for _, err := range []error{os.ErrDeadlineExceeded, unix.EBADF, fmt.Errorf("netlink: %w", unix.ENOBUFS)} {
		if receiveError(ctx, err, &count, fail) != -1 {
			t.Fatal("receive loop continued after stop", err)
		}
	}
	if len(reported) != 1 || count.Load() != 0 {
		t.Fatal("stop interruption reported as queue failure", reported, count.Load())
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

func TestEndpointBurstWaitEligibilityAndAccounting(t *testing.T) {
	for _, mode := range []string{"recent", "stale", "census", "budget"} {
		t.Run(mode, func(t *testing.T) {
			w := newPacketWorkers(0, func(packetJob, bool) {})
			defer w.stop()
			p := job(100, 8000)
			for i := 0; i < MaxAttributionPerEndpoint; i++ {
				if !w.submit(job(uint32(i), 8000)) {
					t.Fatal("fill")
				}
			}
			now := time.Now()
			w.recent[p.key()] = now
			w.burstWindow = now
			switch mode {
			case "stale":
				w.recent[p.key()] = now.Add(-2 * recentCompletionWindow)
			case "census":
				w.census[p.key()] = true
			case "budget":
				w.burstSpent = endpointStallBudget
			}
			before := w.burstSpent
			if w.submitWait(context.Background(), p) {
				t.Fatal("exceeded endpoint bound")
			}
			if mode == "recent" {
				if w.burstSpent < EndpointBurstWait {
					t.Fatal("wait not accounted", w.burstSpent)
				}
			} else if w.burstSpent != before {
				t.Fatal("ineligible endpoint waited", w.burstSpent)
			}
			if !w.submitWait(context.Background(), job(101, 8001)) {
				t.Fatal("unrelated endpoint refused")
			}
		})
	}
}

func TestEndpointStallBudgetWindow(t *testing.T) {
	w := newPacketWorkers(0, func(packetJob, bool) {})
	defer w.stop()
	now := time.Now()
	if got := w.endpointWaitBudgetLocked(now); got != endpointStallBudget {
		t.Fatal(got)
	}
	w.burstSpent = endpointStallBudget
	if got := w.endpointWaitBudgetLocked(now.Add(endpointStallWindow - time.Nanosecond)); got != 0 {
		t.Fatal(got)
	}
	if got := w.endpointWaitBudgetLocked(now.Add(endpointStallWindow)); got != endpointStallBudget {
		t.Fatal(got)
	}
}
