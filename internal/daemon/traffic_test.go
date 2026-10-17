package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/store"
	"flowgate/internal/udpaccount"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fixtureTraffic struct {
	mu            sync.Mutex
	starts, stops int
	value         udpaccount.Status
}

func (f *fixtureTraffic) Status() udpaccount.Status { f.mu.Lock(); defer f.mu.Unlock(); return f.value }
func (f *fixtureTraffic) Start(expected ...string) (udpaccount.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if expected[0] != f.value.Generation {
		return f.value, udpaccount.ErrCollectorGeneration
	}
	f.starts++
	f.value.State = "starting"
	f.value.Generation = "collector-next"
	return f.value, nil
}
func (f *fixtureTraffic) Stop(expected ...string) (udpaccount.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if expected[0] != f.value.Generation {
		return f.value, udpaccount.ErrCollectorGeneration
	}
	f.stops++
	f.value.State = "disabled"
	return f.value, nil
}
func TestTrafficAPIPermissionsAndProjection(t *testing.T) {
	f := &fixtureTraffic{value: udpaccount.Status{State: "disabled", Available: true, Scope: "machine", Missed: 77}}
	a := newDeleteAPI(t, func(e *Engine, _ *store.Store) {
		e.Traffic = f
		e.Mode = "daemon-monitor"
		uid := uint32(os.Getuid())
		e.TrafficControlUID = &uid
	})
	r := callResponse(a.path, Request{Version: 1, Operation: "list"})
	if r.TrafficMonitor == nil || r.TrafficMonitor.Scope != "self" || r.TrafficMonitor.Missed != 0 || !r.Permissions.CanManageRules || r.Permissions.CanControlTraffic {
		t.Fatal(r)
	}
	assertCode(t, callResponse(a.path, Request{Version: 1, Operation: "traffic-start", Generation: a.e.Generation}), "forbidden")
	assertCode(t, callResponse(a.path, Request{Version: 1, Operation: "traffic-stop", Generation: a.e.Generation}), "forbidden")
	if f.starts != 0 || f.stops != 0 {
		t.Fatal("ordinary rule manager controlled collector")
	}
	roPath := filepath.Join(filepath.Dir(a.path), "traffic-readonly")
	ro, err := Serve(roPath, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	roResp := callResponse(roPath, Request{Version: 1, Operation: "traffic-status"})
	if roResp.TrafficMonitor == nil || roResp.Permissions.CanControlTraffic {
		t.Fatal(roResp)
	}
	assertCode(t, callResponse(roPath, Request{Version: 1, Operation: "traffic-start", Generation: a.e.Generation}), "forbidden")
	// Explicit administrator grant affects lifecycle only when separately configured.
	uid := uint32(os.Getuid())
	e := New(time.Second)
	e.Traffic = f
	e.AdministratorUID = &uid
	if e.permissions(uid, false).CanControlTraffic {
		t.Fatal("rule administrator silently granted collector authority")
	}
	e.TrafficControlUID = &uid
	if !e.permissions(uid, false).CanControlTraffic || e.permissions(uid, true).CanControlTraffic {
		t.Fatal("explicit authority/read-only mismatch")
	}
}
func TestMachineUDPCountersPrivacy(t *testing.T) {
	s := identity.ActivitySnapshot{UDP: &identity.UDPSnapshot{Machine: true, UID: 0, Missed: 123, State: "active", Rows: map[string]identity.UDPCount{"foreign": {Uploaded: 999}}}, Processes: map[string]identity.ActivityProcess{"self": {UID: 1000}, "foreign": {UID: 0}}}
	for _, r := range []identity.ActivityRow{
		{ID: "own", Owners: []string{"self"}, OwnershipCategory: "visible-holder"}, {ID: "unknown"}, {ID: "mixed", Owners: []string{"self", "foreign"}}, {ID: "foreign", Owners: []string{"foreign"}},
	} {
		r.Socket = identity.Socket{Protocol: "udp", UID: 1000}
		r.Traffic = identity.Traffic{Available: true, Uploaded: 999, Definition: "udp-api-reported"}
		s.Rows = append(s.Rows, r)
	}
	got := activityFor(s, 1000, false)
	if len(got.Rows) != 2 || got.UDP.Missed != 0 || got.UDP.Rows != nil {
		t.Fatal(got)
	}
	if !got.Rows[0].Traffic.Available || got.Rows[0].Traffic.Uploaded != 999 || !got.Rows[0].Traffic.Partial {
		t.Fatal(got.Rows[0])
	}
	if got.Rows[1].Traffic.Available || got.Rows[1].Traffic.Uploaded != 0 {
		t.Fatal("unknown ownership leaked UDP counters")
	}
	if len(activityFor(s, 1000, true).Rows) != 4 || s.UDP.Missed != 123 || !s.Rows[1].Traffic.Available {
		t.Fatal("projection changed administrator/source")
	}
}
