package identity

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This deliberately keeps PID/start, socket inode, cookie and port unchanged.
// A process-liveness-only reuse check would continue returning Alpha after exec.
func TestUDPReuseRealExecRevalidatesApplication(t *testing.T) {
	udpPortLab(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "alpha"), filepath.Join(dir, "beta")
	if out, err := exec.Command("cc", "-Wall", "-Wextra", "-O2", "../../fixtures/ownership/udp-exec.c", "-o", a).CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v %s", err, out)
	}
	data, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(b, data, 0700); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			child := startChurnFixture(t, a, family)
			local, remote := fmt.Sprintf("127.0.0.1:%d", child.worker), "198.51.100.1:443"
			if family == "6" {
				local, remote = fmt.Sprintf("[::1]:%d", child.worker), "[2001:db8::1]:443"
			}
			flow := udpFlow("outgoing", local, remote)
			r := NewUDPAttributionReuse(Resolve)
			before := r.Resolve(flow)
			if before.Application == nil || before.Application.Executable != a || len(before.Owners) != 1 || len(before.Sockets) != 1 {
				t.Fatalf("initial attribution: %+v", before)
			}
			if len(r.entries) != 1 || before.Status != "directly-associated" || !exactNativeHolder(before.Owners[0]) {
				t.Fatalf("initial attribution did not exercise reuse: %+v entries=%d", before, len(r.entries))
			}
			if _, err := io.WriteString(child.in, "EXEC "+b+"\n"); err != nil {
				t.Fatal(err)
			}
			var inode uint64
			var pid, port int
			if _, err := fmt.Sscanf(child.line(t), "READY %d %d %d", &inode, &pid, &port); err != nil {
				t.Fatal(err)
			}
			if pid != child.tgid || port != child.worker || fmt.Sprintf("socket:[%d]", inode) != child.socket {
				t.Fatal("fixture changed process/socket")
			}
			after := r.Resolve(flow)
			if after.Application == nil || after.Application.Executable != b || after.Application.Key == before.Application.Key || len(after.Owners) != 1 || after.Owners[0].Start != before.Owners[0].Start || len(after.Sockets) != 1 || after.Sockets[0].Cookie != before.Sockets[0].Cookie {
				t.Fatalf("exec inherited stale application: before=%+v after=%+v", before, after)
			}
		})
	}
}
