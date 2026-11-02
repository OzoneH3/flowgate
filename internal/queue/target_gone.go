package queue

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"flowgate/internal/queuehealth"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A verdict targets a packet, not a file. NETDEV_DOWN may flush that packet
// while its userspace policy job is still alive. The kernel then sends an
// asynchronous NLMSG_ERROR -ENOENT for the verdict. That is distinct from a
// transport syscall error or losing the queue binding. Config requests finish
// synchronously before the steady-state receive loop; it only sends verdicts.
func verdictTargetGone(err error) bool {
	var op *netlink.OpError
	return errors.As(err, &op) && op.Op == "receive" && op.Sequence != 0 && op.Err == unix.ENOENT
}

// Never continue on an errno alone. Obtain fresh proof that this very socket's
// port still owns this queue in this namespace; unknown/foreign/missing is fatal.
// This is only on the exceptional error path, never established-packet work.
func queueStillOwned(number uint16, port uint32) bool {
	if port == 0 {
		return false
	}
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	return err == nil && len(b) <= 1<<20 && queueBindingMatches(string(b), number, port)
}
func queueBindingMatches(text string, number uint16, port uint32) bool {
	if port == 0 {
		return false
	}
	found := false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 9 {
			return false
		}
		for _, column := range f {
			if _, err := strconv.ParseUint(column, 10, 64); err != nil {
				return false
			}
		}
		q, err := strconv.ParseUint(f[0], 10, 16)
		if err != nil {
			return false
		}
		owner, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			return false
		}
		if uint16(q) != number {
			continue
		}
		if found || uint32(owner) != port {
			return false
		}
		found = true
	}
	return found
}

func receiveBoundQueueError(ctx context.Context, err error, overflow *atomic.Uint64, fail func(error), stillOwned func() bool, report func(queuehealth.Cause)) int {
	if ctx.Err() != nil {
		return -1
	}
	if verdictTargetGone(err) && stillOwned != nil && stillOwned() {
		report(queuehealth.VerdictTargetGone)
		return 0 // Nothing is approved/replayed; the kernel already removed the packet.
	}
	if errors.Is(err, unix.ENOBUFS) {
		report(queuehealth.NetlinkOverflow)
	} else {
		report(queuehealth.ReceiveFailure)
	}
	return receiveError(ctx, err, overflow, fail)
}
