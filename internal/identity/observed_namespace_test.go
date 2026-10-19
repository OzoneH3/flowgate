package identity

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
)

func TestObservedPrivateMountHelper(t *testing.T) {
	if os.Getenv("FLOWGATE_MOUNT_HELPER") != "1" {
		return
	}
	s, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fmt.Println("READY")
	io.Copy(io.Discard, os.Stdin)
}

// Run explicitly in a disposable user/net/mount namespace. No host firewall,
// service or policy is touched. This models systemd service mount sandboxing.
func TestObservedPrivateMountNamespace(t *testing.T) {
	if os.Getenv("FLOWGATE_TEST_PRIVATE_MOUNT") != "1" {
		t.Skip("explicit private namespace fixture required")
	}
	cmd := exec.Command("unshare", "--mount", "--", os.Args[0], "-test.run=^TestObservedPrivateMountHelper$")
	cmd.Env = append(os.Environ(), "FLOWGATE_MOUNT_HELPER=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); cmd.Process.Kill(); cmd.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatalf("helper: %q %v", line, err)
	}
	var collector ActivityCollector
	snapshot := collector.Collect()
	for _, row := range snapshot.Rows {
		if len(row.Owners) != 1 {
			continue
		}
		p := snapshot.Processes[row.Owners[0]]
		if p.PID != cmd.Process.Pid {
			continue
		}
		if p.MountNS == link("/proc/self/ns/mnt") {
			t.Fatal("fixture did not isolate mount namespace")
		}
		verified, err := VerifyObservedNative(row.ID, p)
		if err != nil || verified.MountNS != p.MountNS {
			t.Fatalf("sandboxed native service rejected: %v", err)
		}
		for _, field := range []string{"mount", "pidns", "net", "boot", "revision"} {
			stale := p
			switch field {
			case "mount":
				stale.MountNS += "changed"
			case "pidns":
				stale.PIDNS += "changed"
			case "net":
				stale.NetNS += "changed"
			case "boot":
				stale.BootID += "changed"
			case "revision":
				stale.Application.Revision += "changed"
			}
			if _, err := VerifyObservedNative(row.ID, stale); err == nil {
				t.Fatal("accepted stale " + field)
			}
		}
		return
	}
	t.Fatal("unique helper socket not observed")
}
