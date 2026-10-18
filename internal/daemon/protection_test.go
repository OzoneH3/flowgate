package daemon

import (
	"flowgate/internal/store"
	"os"
	"path/filepath"
	"testing"
)

type fakeProtection struct {
	starts, stops int
	s             ProtectionStatus
}

func (f *fakeProtection) ProtectionStatus() ProtectionStatus                   { return f.s }
func (f *fakeProtection) ProtectionReadiness(string) (ProtectionStatus, error) { return f.s, nil }
func (f *fakeProtection) ProtectionStart(string, string, string) (ProtectionStatus, error) {
	f.starts++
	return f.s, nil
}
func (f *fakeProtection) ProtectionStop(string) (ProtectionStatus, error) { f.stops++; return f.s, nil }
func TestContinuousAPIExplicitAuthorityAndGeneration(t *testing.T) {
	f := &fakeProtection{s: ProtectionStatus{ID: "current", State: "active", DesiredMode: "both", Profile: "both"}}
	a := newDeleteAPI(t, func(e *Engine, _ *store.Store) {
		e.Mode = "daemon-monitor"
		e.Protection = f
		uid := uint32(os.Getuid())
		e.ProtectionControlUID = &uid
	})
	ro := filepath.Join(filepath.Dir(a.path), "protection-readonly")
	l, err := Serve(ro, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	q := Request{Version: 1, Operation: "protection-start", Generation: a.e.Generation, ProtectionID: "current", Profile: "both", RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	assertCode(t, callResponse(ro, q), "forbidden")
	q.Generation = "old"
	q.Operation = "protection-readiness"
	assertCode(t, callResponse(a.path, q), "generation_conflict")
	assertCode(t, callResponse(a.path, Request{Version: 1, Operation: "decide", Generation: "old", ID: "same-id", Scope: "once", Action: "allow"}), "generation_conflict")
	if f.starts != 0 || f.stops != 0 {
		t.Fatal("rejected operation reached controller")
	}
	r := callResponse(a.path, Request{Version: 1, Operation: "list"})
	if r.Protection == nil || r.Protection.State != "active" || !r.Permissions.CanDecide {
		t.Fatal(r)
	}
	r = callResponse(ro, Request{Version: 1, Operation: "list"})
	if r.Permissions.CanControlProtection || r.Permissions.CanDecide {
		t.Fatal("observer gained authority", r.Permissions)
	}
}
