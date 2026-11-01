package queue

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func scripted(errs ...error) (func() error, *int) {
	calls := 0
	return func() error {
		calls++
		if calls <= len(errs) {
			return errs[calls-1]
		}
		return nil
	}, &calls
}

func TestVerdictWriteRetryRecoversFromDeadlineTimeouts(t *testing.T) {
	// The observed failure: "netlink send: i/o timeout" wrapping os.ErrDeadlineExceeded.
	opTimeout := &netlink.OpError{Op: "send", Err: os.ErrDeadlineExceeded}
	send, calls := scripted(opTimeout, fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded))
	retries := 0
	if err := retryVerdictWrite(send, func() { retries++ }); err != nil {
		t.Fatalf("timeouts followed by success must succeed: %v", err)
	}
	if *calls != 3 || retries != 2 {
		t.Fatalf("calls=%d retries=%d, want 3/2", *calls, retries)
	}
}

func TestVerdictWriteRetryIsBounded(t *testing.T) {
	timeouts := make([]error, 10)
	for i := range timeouts {
		timeouts[i] = os.ErrDeadlineExceeded
	}
	send, calls := scripted(timeouts...)
	retries := 0
	err := retryVerdictWrite(send, func() { retries++ })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("persistent timeout must reach the fail-closed path, got %v", err)
	}
	if *calls != verdictWriteAttempts || retries != verdictWriteAttempts-1 {
		t.Fatalf("calls=%d retries=%d, want %d/%d", *calls, retries, verdictWriteAttempts, verdictWriteAttempts-1)
	}
}

func TestVerdictWriteRetryNeverRetriesOtherErrors(t *testing.T) {
	for _, failure := range []error{unix.EBADF, unix.ENOENT, fmt.Errorf("netlink: %w", unix.ENOBUFS), errors.New("closed")} {
		send, calls := scripted(failure)
		retries := 0
		if err := retryVerdictWrite(send, func() { retries++ }); !errors.Is(err, failure) {
			t.Fatalf("%v: got %v", failure, err)
		}
		if *calls != 1 || retries != 0 {
			t.Fatalf("%v: calls=%d retries=%d, want 1/0", failure, *calls, retries)
		}
	}
}
