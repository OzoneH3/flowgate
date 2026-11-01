package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"flowgate/internal/daemon"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// scripted returns the given errors in order, then success, recording the
// verdict carried by every write attempt.
func scripted(errs ...error) (func(bool) error, *[]bool) {
	sent := []bool{}
	return func(allow bool) error {
		sent = append(sent, allow)
		if len(sent) <= len(errs) {
			return errs[len(sent)-1]
		}
		return nil
	}, &sent
}

func always(v bool) func() bool { return func() bool { return v } }

func TestVerdictWriteRetryRecoversFromDeadlineTimeouts(t *testing.T) {
	// The observed failure: "netlink send: i/o timeout" wrapping os.ErrDeadlineExceeded.
	opTimeout := &netlink.OpError{Op: "send", Err: os.ErrDeadlineExceeded}
	send, sent := scripted(opTimeout, fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded))
	retries := 0
	allowed, err := retryVerdictWrite(send, true, always(true), func() { retries++ })
	if err != nil || !allowed {
		t.Fatalf("timeouts followed by success must deliver the still-valid Allow: allowed=%v err=%v", allowed, err)
	}
	if fmt.Sprint(*sent) != "[true true true]" || retries != 2 {
		t.Fatalf("sent=%v retries=%d, want three identical Allow writes", *sent, retries)
	}
}

func TestVerdictWriteRetryDowngradesInvalidAllowToDrop(t *testing.T) {
	// Cancellation, a policy epoch change or an expired packet/temporary-rule
	// horizon during the retry window must never let the old Allow through.
	send, sent := scripted(os.ErrDeadlineExceeded)
	checks := 0
	allowed, err := retryVerdictWrite(send, true, func() bool { checks++; return false }, func() {})
	if err != nil || allowed {
		t.Fatalf("an invalidated Allow must be re-sent as Drop: allowed=%v err=%v", allowed, err)
	}
	if fmt.Sprint(*sent) != "[true false]" || checks != 1 {
		t.Fatalf("sent=%v checks=%d: validity must be consulted before the retry, not before the first write", *sent, checks)
	}
}

func TestVerdictWriteRetryNeverUpgradesDrop(t *testing.T) {
	send, sent := scripted(os.ErrDeadlineExceeded)
	allowed, err := retryVerdictWrite(send, false, always(true), func() {})
	if err != nil || allowed || fmt.Sprint(*sent) != "[false false]" {
		t.Fatalf("Drop must stay Drop: allowed=%v err=%v sent=%v", allowed, err, *sent)
	}
}

func TestVerdictWriteRetryIsBounded(t *testing.T) {
	timeouts := make([]error, 10)
	for i := range timeouts {
		timeouts[i] = os.ErrDeadlineExceeded
	}
	send, sent := scripted(timeouts...)
	retries := 0
	_, err := retryVerdictWrite(send, true, always(true), func() { retries++ })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("persistent timeout must reach the fail-closed path, got %v", err)
	}
	if len(*sent) != verdictWriteAttempts || retries != verdictWriteAttempts-1 {
		t.Fatalf("attempts=%d retries=%d, want %d/%d", len(*sent), retries, verdictWriteAttempts, verdictWriteAttempts-1)
	}
}

func TestVerdictWriteRetryNeverRetriesOtherErrors(t *testing.T) {
	for _, failure := range []error{unix.EBADF, unix.ENOENT, fmt.Errorf("netlink: %w", unix.ENOBUFS), errors.New("closed")} {
		send, sent := scripted(failure)
		retries := 0
		if _, err := retryVerdictWrite(send, true, always(true), func() { retries++ }); !errors.Is(err, failure) {
			t.Fatalf("%v: got %v", failure, err)
		}
		if len(*sent) != 1 || retries != 0 {
			t.Fatalf("%v: attempts=%d retries=%d, want 1/0", failure, len(*sent), retries)
		}
	}
}

func TestFinishPassesRetryValidityBoundToEpochDeadlineAndContext(t *testing.T) {
	var epoch uint64
	var captured func() bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var expired atomic.Uint64
	p := packetProcessor{ctx: ctx, expired: &expired, policyEpoch: func() uint64 { return epoch },
		record: func(daemon.Event, string, error) {},
		verdict: func(_ uint32, allow bool, valid func() bool) (bool, error) {
			captured = valid
			return allow, nil
		}}
	j := packetJob{id: 7, deadline: time.Now().Add(time.Minute)}
	p.finish(j, daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)})
	if captured == nil || !captured() {
		t.Fatal("a fresh allowed decision must permit an identical retry")
	}
	epoch++ // rule edit / policy reset
	if captured() {
		t.Fatal("a policy epoch change must invalidate the retried Allow")
	}
	epoch--
	p.finish(packetJob{id: 8, deadline: time.Now().Add(-time.Second)}, daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)})
	if captured() {
		t.Fatal("an expired packet deadline must invalidate the retried Allow")
	}
	p.finish(j, daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)})
	cancel()
	if captured() {
		t.Fatal("queue cancellation must invalidate the retried Allow")
	}
}
