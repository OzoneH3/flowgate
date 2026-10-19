package daemon

import (
	"bufio"
	"flowgate/internal/identity"
	"flowgate/internal/store"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestServiceNamespaceHelper(t *testing.T) {
	if os.Getenv("FLOWGATE_SERVICE_HELPER") != "1" {
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

func TestServicePrivateMountPreviewSave(t *testing.T) {
	if os.Getenv("FLOWGATE_TEST_PRIVATE_MOUNT") != "1" {
		t.Skip("explicit private namespace fixture required")
	}
	cmd := exec.Command("unshare", "--mount", "--", os.Args[0], "-test.run=^TestServiceNamespaceHelper$")
	cmd.Env = append(os.Environ(), "FLOWGATE_SERVICE_HELPER=1")
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
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("helper %q %v", line, err)
	}
	var collector identity.ActivityCollector
	snapshot := collector.Collect()
	var target ObservedTarget
	var owner identity.ActivityProcess
	for _, row := range snapshot.Rows {
		if len(row.Owners) == 1 {
			p := snapshot.Processes[row.Owners[0]]
			if p.PID == cmd.Process.Pid {
				target = ObservedTarget{row.ID, p.ID}
				owner = p
				break
			}
		}
	}
	if target.RowID == "" {
		t.Fatal("native service socket not observed")
	}
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.verifyObserved = nil
		e.Now = time.Now
		e.Activity = func() identity.ActivitySnapshot { return snapshot }
	})
	t.Cleanup(a.e.CloseProcessTargets)
	for _, scope := range []string{"application", "process"} {
		d := observedDraft("incoming")
		d.Action = "allow"
		d.TargetScope = scope
		d.RemoteAddress = "*"
		if scope == "process" {
			expiry := time.Now().Add(time.Hour)
			d.Expires = &expiry
		}
		preview := callResponse(a.path, Request{Version: 1, Operation: "observed-rule-preview", Generation: a.e.Generation, ObservedTarget: &target, ObservedDraft: &d})
		if preview.Error != "" || preview.ObservedPreview == nil {
			t.Fatalf("%s preview: %+v", scope, preview)
		}
		request := saveRequest(a, *preview.ObservedPreview, d)
		saved := callResponse(a.path, request)
		if saved.Error != "" || saved.SavedRule == nil {
			t.Fatalf("%s save: %+v", scope, saved)
		}
		f := saved.SavedRule.Filter
		if f.Application != owner.Application.Key || f.Revision != owner.Application.Revision || f.UID != owner.UID || f.Direction != "incoming" || f.Process.IsZero() != (scope == "application") {
			t.Fatal("scope or identity changed", saved.SavedRule)
		}
		retry := callResponse(a.path, request)
		if retry.Error != "" || !retry.Replayed {
			t.Fatal("receipt replay", retry)
		}
	}
	rules, err := a.s.Load()
	if err != nil || len(rules) != 2 {
		t.Fatal("durable rules", rules, err)
	}
}
