package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPublishedListIsIndependentAndFilteredWithoutEngineLock(t *testing.T) {
	e, f, a, now := fixture()
	e.LocalPeer = nil
	v := e.Observe(f, "udp")
	e.mu.Lock()
	e.rules = []policy.Rule{{ID: "own", Action: "allow", Filter: policy.Filter{Application: "app", UID: 1000}}, {ID: "other", Action: "block", Filter: policy.Filter{Application: "other", UID: 1001}}}
	other := v
	other.ID = "other-user"
	copyA := *a
	copyA.Owners = append([]identity.Process(nil), a.Owners...)
	copyA.Owners[0].UID = 1001
	other.Attribution = copyA
	e.events["other"] = &other
	e.mu.Unlock()
	var state listReadState
	if err := state.publish(e); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	done := make(chan ListSnapshot, 1)
	go func() {
		view, err := state.read(1000, false, *now)
		if err != nil {
			t.Error(err)
		}
		done <- view
	}()
	var view ListSnapshot
	select {
	case view = <-done:
	case <-time.After(time.Second):
		t.Fatal("snapshot read waited on engine lock")
	}
	if len(view.Events) != 1 || view.Events[0].ID != v.ID || len(view.Rules) != 1 || view.Rules[0].ID != "own" || len(view.RuleStates) != 1 {
		t.Fatal("cross-user snapshot leak", view)
	}
	view.Events[0].ScopePreviews["once"] = "mutated"
	view.Events[0].Attribution.Owners[0].UID = 999
	view.Zones.Local[0] = "mutated"
	again, err := state.read(1000, false, *now)
	if err != nil {
		t.Fatal(err)
	}
	if again.Events[0].ScopePreviews["once"] == "mutated" || again.Events[0].Attribution.Owners[0].UID != 1000 || again.Zones.Local[0] == "mutated" {
		t.Fatal("reader mutated published storage")
	}
	all, _ := state.read(0, true, *now)
	if len(all.Events) != 2 || len(all.Rules) != 2 {
		t.Fatal("admin projection missing rows")
	}
}

func TestPublishedListExpiresPresentationWithoutMutatingEngine(t *testing.T) {
	e, f, _, now := fixture()
	e.LocalPeer = nil
	v := e.Observe(f, "udp")
	var state listReadState
	if err := state.publish(e); err != nil {
		t.Fatal(err)
	}
	view, err := state.read(1000, false, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Events) != 1 || view.Events[0].State != "expired" {
		t.Fatal("expired pending shown actionable")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, event := range e.events {
		if event.ID == v.ID && event.State != "awaiting-decision" {
			t.Fatal("read mutated engine")
		}
	}
}

func TestListLifecycleExpiresWithoutReadersAndStopsWithLastListener(t *testing.T) {
	e := New(20 * time.Millisecond)
	e.LocalPeer = nil
	e.events["pending"] = &Event{ID: "pending", State: "awaiting-decision", Deadline: time.Now().Add(20 * time.Millisecond)}
	var state listReadState
	release, err := state.acquire(e)
	if err != nil {
		t.Fatal(err)
	}
	second, err := state.acquire(e)
	if err != nil {
		release()
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
			second()
		}
	}()
	end := time.Now().Add(2 * time.Second)
	expired := false
	for time.Now().Before(end) {
		e.mu.Lock()
		expired = e.events["pending"].State == "expired"
		e.mu.Unlock()
		if expired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !expired {
		t.Fatal("no-reader lifecycle did not expire request")
	}
	release()
	state.lifecycleMu.Lock()
	users := state.users
	state.lifecycleMu.Unlock()
	if users != 1 {
		t.Fatal("companion listener lost lifecycle")
	}
	second()
	released = true
	select {
	case <-state.done:
	default:
		t.Fatal("last listener leaked publisher")
	}
}

func TestListAPIReadsPublishedSnapshotWhileEngineLocked(t *testing.T) {
	e := New(time.Second)
	e.LocalPeer = nil
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	e.mu.Lock()
	result := make(chan Response, 1)
	go func() {
		r, err := Call(path, Request{Version: 1, Operation: "list"})
		if err != nil {
			t.Error(err)
		}
		result <- r
	}()
	var reply Response
	select {
	case reply = <-result:
	case <-time.After(time.Second):
		e.mu.Unlock()
		t.Fatal("API list blocked on engine lock")
	}
	e.mu.Unlock()
	if reply.SnapshotRevision == "" || reply.SnapshotAt.IsZero() {
		t.Fatal("snapshot ordering metadata missing")
	}
}

func TestMutationAckPublishesBeforeSubsequentList(t *testing.T) {
	e, f, attribution, _ := fixture()
	e.Now = time.Now
	e.LocalPeer = nil
	attribution.Owners[0].UID = uint32(os.Getuid())
	v := e.Observe(f, "udp")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ack, err := Call(path, Request{Version: 1, Operation: "decide", ID: v.ID, Action: "allow", Scope: "once"})
	if err != nil || ack.Error != "" {
		t.Fatal("decision", err, ack.Error)
	}
	list, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil || list.Error != "" {
		t.Fatal("list", err, list.Error)
	}
	a, _ := strconv.ParseUint(ack.SnapshotRevision, 10, 64)
	b, _ := strconv.ParseUint(list.SnapshotRevision, 10, 64)
	if a == 0 || b < a {
		t.Fatal("list older than acknowledged mutation", a, b)
	}
	if len(list.Events) != 1 || list.Events[0].State != "allowed" {
		t.Fatal("published acknowledgement resurrected pending", list.Events)
	}
}

func TestSnapshotPublishErrorMetadata(t *testing.T) {
	e := New(time.Second)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Force JSON serialization to fail after the first good publication.
	e.mu.Lock()
	e.events["invalid-time"] = &Event{ID: "invalid-time", State: "blocked", FirstSeen: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Deadline: time.Now().Add(time.Hour)}
	e.mu.Unlock()
	r, err := Call(path, Request{Version: 1, Operation: "unknown-operation"})
	if err == nil {
		t.Fatal("publication failure must report an error")
	}
	if r.ErrorCode != "snapshot_unavailable" || r.Error == "" || r.SnapshotRevision == "" || r.SnapshotAt.IsZero() {
		t.Fatalf("publication error lost protocol metadata: %+v", r)
	}
}

func TestReadOnlyReplyDoesNotPublish(t *testing.T) {
	e := New(time.Second)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	e.listReads.publishMu.Lock()
	defer e.listReads.publishMu.Unlock()
	done := make(chan Response, 1)
	go func() {
		r, _ := Call(path, Request{Version: 1, Operation: "traffic-status"})
		done <- r
	}()
	select {
	case r := <-done:
		if r.SnapshotRevision == "" {
			t.Fatal("query lost snapshot metadata")
		}
	case <-time.After(time.Second):
		t.Fatal("pure query waited for publication")
	}
}
