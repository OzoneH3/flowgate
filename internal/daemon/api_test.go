package daemon

import (
	"flowgate/internal/identity"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyAPI(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	e, _, _, _ := fixture()
	l, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ReadOnly || r.Generation != e.Generation || r.ServerTime.IsZero() || r.PeerUID != uint32(os.Getuid()) {
		t.Fatalf("missing session/authorization metadata: %+v", r)
	}
	if New(0).Generation == e.Generation {
		t.Fatal("reused backend generation")
	}
	if _, err = Call(path, Request{Version: 1, Operation: "decide", ID: "fake", Action: "allow", Scope: "once"}); err == nil {
		t.Fatal("read-only endpoint allowed mutation")
	}
	if _, err = Call(path, Request{Version: 2, Operation: "list"}); err == nil {
		t.Fatal("unsupported API accepted")
	}
}

func TestHostMonitorAlwaysReadOnly(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "host-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	e, _, _, _ := fixture()
	e.Mode = "host-monitor"
	e.Activity = func() identity.ActivitySnapshot { return identity.ActivitySnapshot{Sequence: 1, Complete: false} }
	l, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || !r.ReadOnly || r.Activity == nil || r.Activity.Sequence != 1 || len(r.Events) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = Call(path, Request{Version: 1, Operation: "decide", ID: "fake", Action: "allow", Scope: "once"}); err == nil {
		t.Fatal("host mutation accepted")
	}
}

func TestNonActiveEnforcementRejectsMutation(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "health-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	e, _, _, _ := fixture()
	e.Mode = "host-enforcement"
	e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "degraded"} }
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	l, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || !r.ReadOnly || r.Enforcement.State != "degraded" {
		t.Fatal(r, err)
	}
	for _, op := range []string{"decide", "rule"} {
		if _, err = Call(path, Request{Version: 1, Operation: op, ID: "unused", Action: "allow", Scope: "persistent"}); err == nil {
			t.Fatal("degraded mode accepted mutation", op)
		}
	}
}
