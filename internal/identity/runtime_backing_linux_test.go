package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeBackingLiveNamespace(t *testing.T) {
	if os.Getenv("FLOWGATE_RUNTIME_NAMESPACE_TEST") != "1" {
		t.Skip("isolated user/mount namespace fixture only")
	}
	root := t.TempDir()
	source := filepath.Join(root, "deployment", "files", "bin", "sleep")
	os.MkdirAll(filepath.Dir(source), 0700)
	data, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(source, data, 0700)
	os.WriteFile(filepath.Join(root, "deployment", "usr-mtree.txt.gz"), nil, 0600)
	var previous Application
	for n := 0; n < 2; n++ {
		temp := filepath.Join(root, "var", fmt.Sprintf("tmp-%d", n), "usr", "bin", "sleep")
		os.MkdirAll(filepath.Dir(temp), 0700)
		if err := os.Link(source, temp); err != nil {
			t.Fatal(err)
		}
		child := exec.Command("unshare", "--mount", "sh", "-c", `mount --bind "$1" /usr/bin/sleep || exit; exec /usr/bin/sleep 60`, "fixture", temp)
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { child.Process.Kill(); child.Wait() }()
		var p Process
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			p, err = Inspect(child.Process.Pid)
			if err == nil && p.Application.HostExecutable == source {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil || p.Application.HostExecutable != source || !contentRevision(p.Application) {
			t.Fatalf("live attribution: %+v %v", p.Application, err)
		}
		if n > 0 && (p.Application.Key != previous.Key || p.Application.Revision != previous.Revision) {
			t.Fatal("second real instance changed identity")
		}
		evidence, err := CaptureExecutable(p, p.Application)
		if err != nil {
			t.Fatal(err)
		}
		evidence.Wait(time.Second)
		ev := evidence.Evidence()
		evidence.Release()
		if err := VerifyInstanceExecutable(p.PID, p.Start, p.Application); err != nil {
			t.Fatal(err)
		}
		child.Process.Kill()
		child.Wait()
		os.Remove(temp)
		if err := VerifyRetainedEvidence(p.Application, p.UID, ev); err != nil {
			t.Fatal("post-exit verification:", err)
		}
		previous = p.Application
	}
}
