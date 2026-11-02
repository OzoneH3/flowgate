package queue

import (
	"context"
	"flowgate/internal/queuehealth"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"os"
	"sync/atomic"
	"testing"
)

func TestMissingVerdictTargetRequiresKernelAckAndOwnedQueue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		owned bool
		want  int
	}{
		{"owned", &netlink.OpError{Op: "receive", Err: unix.ENOENT, Sequence: 3}, true, 0},
		{"missing-or-foreign", &netlink.OpError{Op: "receive", Err: unix.ENOENT, Sequence: 3}, false, -1},
		{"syscall", &netlink.OpError{Op: "receive", Err: os.NewSyscallError("recvmsg", unix.ENOENT)}, true, -1},
		{"sequence-unknown", &netlink.OpError{Op: "receive", Err: unix.ENOENT}, true, -1},
		{"wrong-op", &netlink.OpError{Op: "send", Err: unix.ENOENT, Sequence: 3}, true, -1},
		{"raw-errno", unix.ENOENT, true, -1},
		{"other-errno", &netlink.OpError{Op: "receive", Err: unix.ENODEV, Sequence: 3}, true, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var overflow atomic.Uint64
			failed := false
			causes := []queuehealth.Cause{}
			ret := receiveBoundQueueError(context.Background(), tc.err, &overflow, func(error) { failed = true }, func() bool { return tc.owned }, func(c queuehealth.Cause) { causes = append(causes, c) })
			if ret != tc.want || failed != (tc.want == -1) {
				t.Fatalf("ret=%d failed=%v", ret, failed)
			}
			if tc.want == 0 && (len(causes) != 1 || causes[0] != queuehealth.VerdictTargetGone) {
				t.Fatal(causes)
			}
			if tc.want == -1 && (len(causes) != 1 || causes[0] != queuehealth.ReceiveFailure) {
				t.Fatal(causes)
			}
		})
	}
}
func TestQueueOwnershipParsingFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		text string
		port uint32
		want bool
	}{
		{"191 6 0 2 65531 0 0 1 1\n", 6, true},
		{"191 7 0 2 65531 0 0 1 1\n", 6, false},
		{"192 6 0 2 65531 0 0 1 1\n", 6, false},
		{"191 6 0 2 65531 0 0 1 1\n191 6 0 2 65531 0 0 1 1\n", 6, false},
		{"191 6 invalid 2 65531 0 0 1 1", 6, false},
		{"191 6", 6, false}, {"", 6, false}, {"191 6 0 2 65531 0 0 1 1", 0, false},
	} {
		if got := queueBindingMatches(tc.text, 191, tc.port); got != tc.want {
			t.Fatalf("%q port%d got%v", tc.text, tc.port, got)
		}
	}
}
func TestMissingVerdictTargetBurstAndOverflow(t *testing.T) {
	var overflow atomic.Uint64
	proofs, counts := 0, 0
	ack := &netlink.OpError{Op: "receive", Err: unix.ENOENT, Sequence: 1}
	for i := 0; i < 100; i++ {
		if ret := receiveBoundQueueError(context.Background(), ack, &overflow, func(error) { t.Fatal("fatal") }, func() bool { proofs++; return true }, func(c queuehealth.Cause) {
			if c != queuehealth.VerdictTargetGone {
				t.Fatal(c)
			}
			counts++
		}); ret != 0 {
			t.Fatal(ret)
		}
	}
	if proofs != 100 || counts != 100 {
		t.Fatal(proofs, counts)
	}
	if receiveBoundQueueError(context.Background(), unix.ENOBUFS, &overflow, func(error) { t.Fatal("overflow fatal") }, func() bool { t.Fatal("unexpected ownership proof"); return false }, func(c queuehealth.Cause) {
		if c != queuehealth.NetlinkOverflow {
			t.Fatal(c)
		}
	}) != 0 || overflow.Load() != 1 {
		t.Fatal(overflow.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if receiveBoundQueueError(ctx, ack, &overflow, func(error) { t.Fatal("cancelled") }, func() bool { t.Fatal("proof after cancellation"); return false }, func(queuehealth.Cause) { t.Fatal("count after cancel") }) != -1 {
		t.Fatal("cancel return")
	}
}
