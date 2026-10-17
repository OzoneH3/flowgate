package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitAdministratorPermissions(t *testing.T) {
	e := New(0)
	uid := uint32(1000)
	e.APIUID = &uid
	e.SaveRules = func([]policy.Rule) error { return nil }
	e.AdministratorUID = &uid
	for _, tc := range []struct {
		uid   uint32
		admin bool
	}{{0, true}, {1000, true}, {1001, false}} {
		p := e.permissions(tc.uid, false)
		if (p.Role == "administrator") != tc.admin || (p.PolicyScope == "machine") != tc.admin {
			t.Fatal(tc, p)
		}
	}
	if e.permissions(uid, true).CanManageRules {
		t.Fatal("read-only socket inherited write authority")
	}
	e.Mode = "daemon-monitor"
	if e.permissions(uid, false).CanDecide {
		t.Fatal("root monitor gained packet control")
	}
	e.AdministratorUID = nil
	if e.permissions(uid, false).PolicyScope != "self" {
		t.Fatal("grant persisted after removal")
	}
}
func TestRootActivityProjection(t *testing.T) {
	s := identity.ActivitySnapshot{Processes: map[string]identity.ActivityProcess{"self": {UID: 1000}, "service": {UID: 0}}, Rows: []identity.ActivityRow{
		{ID: "mine", Owners: []string{"self"}, Socket: identity.Socket{UID: 1000}},
		{ID: "root", Owners: []string{"service"}, Socket: identity.Socket{UID: 0}},
		{ID: "shared", Owners: []string{"self", "service"}, Socket: identity.Socket{UID: 1000}},
		{ID: "unknown", Socket: identity.Socket{UID: 1000}},
	}}
	projected := activityFor(s, 1000, false)
	if len(projected.Rows) != 2 || len(projected.Processes) != 1 || len(s.Rows) != 4 || len(s.Processes) != 2 {
		t.Fatal("projection leak or mutated collector snapshot", projected)
	}
	if _, ok := projected.Processes["service"]; ok {
		t.Fatal("system service metadata leaked")
	}
	if len(activityFor(s, 1000, true).Rows) != 4 {
		t.Fatal("administrator denied full census")
	}
}
func TestUnixPeerCannotSelfGrantAdministrator(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ordinary peer test requires non-root UID")
	}
	a := newDeleteAPI(t)
	a.e.mu.Lock()
	a.e.rules[0].Filter.UID = 0
	a.e.mu.Unlock()
	c, err := net.Dial("unix", a.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := map[string]any{"version": 1, "operation": "rule-delete", "generation": a.e.Generation, "id": a.rule.ID, "expected_version": a.rule.Version, "administrator": true, "uid": 0}
	if err = json.NewEncoder(c).Encode(q); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err = json.NewDecoder(c).Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.ErrorCode != "forbidden" || r.Permissions.Role != "user" || len(a.e.Rules(0, true)) != 1 {
		t.Fatal("client self-granted machine permission", r)
	}
}
func TestUnprivilegedGrantRejectedBeforeSocket(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires ordinary user")
	}
	dir := t.TempDir()
	e := New(0)
	uid := uint32(os.Getuid())
	e.APIUID = &uid
	e.AdministratorUID = &uid
	path := filepath.Join(dir, "s")
	if l, err := Serve(path, e, false); err == nil {
		l.Close()
		t.Fatal("unprivileged administrator grant accepted")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("invalid grant created socket")
	}
}
func TestAdministratorCannotAllowAmbiguousApplication(t *testing.T) {
	e, f, a, _ := fixture()
	a.Application = nil
	a.Status = "multiple-candidates"
	event := e.Observe(f, "ambiguous")
	if _, err := e.Decide(event.ID, "allow", "once", 0, true); err == nil {
		t.Fatal("administrator invented application authority")
	}
}

func TestMonitorCompanionCompatibilityAndRootOnlyStop(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	e := New(0)
	e.Mode = "daemon-monitor"
	stopped := false
	e.StopMonitoring = func() { stopped = true }
	e.Activity = func() identity.ActivitySnapshot { return identity.ActivitySnapshot{} }
	l, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	r, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || r.Mode != "host-monitor" || r.BackendMode != "daemon-monitor" || !r.ReadOnly {
		t.Fatal(r, err)
	}
	r, err = Call(path, Request{Version: 1, Operation: "monitor-stop", Generation: e.Generation})
	if err == nil || r.ErrorCode != "read_only" || stopped {
		t.Fatal("read-only shutdown", r, err)
	}
	if os.Getuid() != 0 {
		rw, err := Serve(filepath.Join(dir, "rw"), e, false)
		if err != nil {
			t.Fatal(err)
		}
		defer rw.Close()
		r, err = Call(filepath.Join(dir, "rw"), Request{Version: 1, Operation: "monitor-stop", Generation: e.Generation})
		if err == nil || r.ErrorCode != "forbidden" || stopped {
			t.Fatal("delegation became root shutdown", r, err)
		}
	}
}
