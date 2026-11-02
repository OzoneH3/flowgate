package queue

import (
	"context"
	"encoding/json"
	"flowgate/internal/queuehealth"
	"fmt"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This component reproduction is guest-only. It never runs the live daemon.
func TestKernelDeviceDownMissingVerdict(t *testing.T) {
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	cmdline, _ := os.ReadFile("/proc/cmdline")
	ns, _ := os.Readlink("/proc/self/ns/net")
	if os.Getenv("FLOWGATE_DISPOSABLE_VM") != "1" || strings.TrimSpace(string(boot)) == strings.TrimSpace(os.Getenv("FLOWGATE_PARENT_BOOT_ID")) || !strings.Contains(string(cmdline), "rdinit=/init") || ns == os.Getenv("FLOWGATE_PARENT_NETNS") {
		t.Skip("disposable guest and private netns required")
	}
	run := func(args ...string) {
		t.Helper()
		b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, b)
		}
	}
	run("ip", "link", "add", "fg-gone", "type", "dummy")
	defer exec.Command("ip", "link", "del", "fg-gone").Run()
	run("ip", "addr", "add", "10.88.0.1/24", "dev", "fg-gone")
	run("ip", "link", "set", "fg-gone", "up")
	run("nft", "add", "table", "inet", "fg_gone_test")
	defer exec.Command("nft", "delete", "table", "inet", "fg_gone_test").Run()
	run("nft", "add", "chain", "inet", "fg_gone_test", "out", "{ type filter hook output priority 0; policy accept; }")
	run("nft", "add", "rule", "inet", "fg_gone_test", "out", "udp", "dport", "49099", "queue", "num", "191")
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: 191, MaxQueueLen: 128, MaxPacketLen: 65535, Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ids := make(chan uint32, 10)
	errs := make(chan error, 10)
	var recovered atomic.Uint64
	var rejected atomic.Bool
	var ov atomic.Uint64
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int { ids <- *a.PacketID; return 0 }, func(err error) int {
		errs <- err
		return receiveBoundQueueError(ctx, err, &ov, func(error) { rejected.Store(true); cancel() }, func() bool { return queueStillOwned(191, nf.Con.PID()) }, func(c queuehealth.Cause) {
			if c == queuehealth.VerdictTargetGone {
				recovered.Add(1)
			}
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp4", "10.88.0.2:49099")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte("held-before-device-down")); err != nil {
		t.Fatal(err)
	}
	var id uint32
	select {
	case id = <-ids:
	case <-time.After(3 * time.Second):
		t.Fatal("no queued packet")
	}
	before, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	t.Logf("before device down: %s port=%d heldID=%d", before, nf.Con.PID(), id)
	run("ip", "link", "set", "fg-gone", "down")
	after, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	t.Logf("after device down: %s", after)
	if err = nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal("write itself failed", err)
	}
	var recv error
	select {
	case recv = <-errs:
	case <-time.After(3 * time.Second):
		t.Fatal("no error ACK")
	}
	op, ok := recv.(*netlink.OpError)
	t.Logf("async error type=%T value=%#v", recv, recv)
	if !ok {
		t.Fatal("not netlink OpError")
	}
	var overflow atomic.Uint64
	fatal := false
	ret := receiveError(ctx, recv, &overflow, func(error) { fatal = true })
	row := map[string]any{"held_id": id, "portid": nf.Con.PID(), "error": recv.Error(), "operation": op.Op, "underlying_type": fmt.Sprintf("%T", op.Err), "sequence": op.Sequence, "legacy_fatal": fatal, "legacy_return": ret, "queue_before": string(before), "queue_after_device_down": string(after)}
	b, _ := json.Marshal(row)
	t.Log(string(b))
	if !fatal || ret != -1 {
		t.Fatal("did not reproduce c9 fatal handling")
	}
	// The socket/queue still works: only this one already-flushed packet is gone.
	dst, err := net.ListenPacket("udp4", "127.0.0.1:49099")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	local, err := net.Dial("udp4", "127.0.0.1:49099")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	local.Write([]byte("unrelated-surviving-flow"))
	select {
	case id = <-ids:
	case <-time.After(3 * time.Second):
		t.Fatal("queue did not survive")
	}
	if err = nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
		t.Fatal(err)
	}
	dst.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	if _, _, err = dst.ReadFrom(buf); err != nil {
		t.Fatal("surviving flow delivery", err)
	}
	if rejected.Load() || recovered.Load() != 1 {
		t.Fatalf("production recovery failed rejected=%v recovered=%d", rejected.Load(), recovered.Load())
	}
	t.Log("production handler continued; exact owned queue survived; stale ACK counted once; unrelated packet delivered")
}
