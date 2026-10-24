package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func observedDraft(direction string) ObservedDraft {
	zero := uint16(0)
	expiry := time.Time{}
	return ObservedDraft{Direction: direction, Protocol: "udp", Action: "block", RemoteAddress: "127.0.0.2", LocalPort: &zero, RemotePort: &zero, Expires: &expiry}
}
func observedAPI(t *testing.T, config ...func(*Engine, *store.Store)) (*deleteAPI, *identity.ActivitySnapshot, *identity.Process, *time.Time) {
	t.Helper()
	var snap identity.ActivitySnapshot
	var live identity.Process
	var clock *time.Time
	a := newDeleteAPI(t, func(e *Engine, s *store.Store) {
		clockNow := time.Now()
		clock = &clockNow
		e.Now = func() time.Time { return *clock }
		e.Mode = "daemon-monitor"
		e.SetRules(nil)
		s.Replace(nil)
		actor := uint32(os.Getuid())
		app := identity.Application{Key: "verified-app", Revision: "revision", Kind: "native", Executable: "/fixture/native"}
		p := identity.ActivityProcess{ID: "123:10", PID: 123, Start: "10", UID: actor, Application: app}
		snap = identity.ActivitySnapshot{Collected: *clock, Sequence: 1, Complete: true, Processes: map[string]identity.ActivityProcess{p.ID: p}, Rows: []identity.ActivityRow{{ID: "cookie", Owners: []string{p.ID}, OwnershipCategory: "visible-holder"}}}
		live = identity.Process{PID: p.PID, Start: p.Start, UID: p.UID, Application: app, NetNS: "net", MountNS: "mount", ExecutableRevision: app.Revision}
		e.Activity = func() identity.ActivitySnapshot { return snap }
		e.verifyObserved = func(string, identity.ActivityProcess) (identity.Process, error) { return live, nil }
		e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "stopped"} }
		for _, f := range config {
			f(e, s)
		}
	})
	return a, &snap, &live, clock
}
func previewRequest(a *deleteAPI, d ObservedDraft) Request {
	return Request{Version: 1, Operation: "observed-rule-preview", Generation: a.e.Generation, ObservedTarget: &ObservedTarget{"cookie", "123:10"}, ObservedDraft: &d}
}
func requirePreview(t *testing.T, a *deleteAPI, d ObservedDraft) ObservedPreview {
	t.Helper()
	r := callResponse(a.path, previewRequest(a, d))
	if r.Error != "" || r.ObservedPreview == nil {
		t.Fatalf("preview: %+v", r)
	}
	return *r.ObservedPreview
}
func saveRequest(a *deleteAPI, p ObservedPreview, d ObservedDraft) Request {
	return Request{Version: 1, Operation: "observed-rule-save", Generation: a.e.Generation, PreviewToken: p.Token, ObservedDraft: &d}
}
func TestObservedCreationAtomicAPIAndRestart(t *testing.T) {
	a, _, _, clock := observedAPI(t)
	d := observedDraft("incoming")
	port := uint16(8080)
	d.LocalPort = &port
	expiry := clock.Add(time.Hour)
	d.Expires = &expiry
	p := requirePreview(t, a, d)
	if p.Enforcement.Covered || p.Enforcement.State != "stopped" || p.Rule.Version != 1 || p.Rule.ID == "" || p.Rule.Filter.LocalPort != 8080 || p.Rule.Filter.RemotePort != 0 {
		t.Fatal(p)
	}
	// No pending event is needed, and creation never approves or releases an
	// unrelated one. (Requests are re-evaluated; one whose identity cannot be
	// resolved is finalized as ended, never allowed.)
	a.e.mu.Lock()
	unrelated := &Event{ID: "pending", State: "awaiting-decision", Deadline: clock.Add(time.Minute)}
	a.e.events["unrelated"] = unrelated
	a.e.mu.Unlock()
	saved := callResponse(a.path, saveRequest(a, p, d))
	if saved.Error != "" || saved.SavedRule == nil || !reflect.DeepEqual(*saved.SavedRule, p.Rule) {
		t.Fatalf("save: %+v", saved)
	}
	a.e.mu.Lock()
	state := unrelated.State
	a.e.mu.Unlock()
	if state == "allowed" {
		t.Fatal("creation approved an unrelated pending request")
	}
	retry := callResponse(a.path, saveRequest(a, p, d))
	if retry.Error != "" || !retry.Replayed || retry.SavedRule.ID != p.Rule.ID || len(a.e.Rules(uint32(os.Getuid()), false)) != 1 {
		t.Fatal(retry)
	}
	// Outgoing uses a distinct explicit direction and service rather than source port.
	out := observedDraft("outgoing")
	service := uint16(443)
	out.RemotePort = &service
	op := requirePreview(t, a, out)
	r := callResponse(a.path, saveRequest(a, op, out))
	if r.Error != "" || r.SavedRule.Filter.Direction != "outgoing" || r.SavedRule.Filter.LocalPort != 0 || r.SavedRule.Filter.RemotePort != 443 {
		t.Fatal(r)
	}
	view := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation})
	if view.PolicyView == nil || view.PolicyView.Applications[0].Incoming.Active != 1 || view.PolicyView.Applications[0].Outgoing.Active != 1 || view.PolicyView.Applications[0].Incoming.Enforcement.Covered {
		t.Fatal(view)
	}
	a.s.Close()
	s, err := store.Open(a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err := s.Load()
	if err != nil || len(rs) != 2 {
		t.Fatal(rs, err)
	}
	var found bool
	for _, rule := range rs {
		if rule.ID == p.Rule.ID {
			found = true
			if !rule.Expires.Equal(expiry) || rule.Filter != p.Rule.Filter {
				t.Fatal(rule)
			}
		}
	}
	if !found {
		t.Fatal("missing restarted rule")
	}
}
func TestObservedCreationRejections(t *testing.T) {
	for _, name := range []string{"draft", "generation", "start", "revision", "uid", "namespace", "exit", "expired-preview", "expired-rule", "shared", "runtime", "unknown", "stale-activity", "incomplete-input", "duplicate", "overlap-change"} {
		t.Run(name, func(t *testing.T) {
			a, snap, live, clock := observedAPI(t)
			d := observedDraft("incoming")
			p := requirePreview(t, a, d)
			q := saveRequest(a, p, d)
			want := "stale_target"
			switch name {
			case "draft":
				q.ObservedDraft.Action = "allow"
				want = "preview_mismatch"
			case "generation":
				q.Generation = "old"
				want = "generation_conflict"
			case "start":
				live.Start = "11"
			case "revision":
				live.Application.Revision = "new"
			case "uid":
				live.UID++
			case "namespace":
				live.NetNS = "replacement"
			case "exit":
				a.e.verifyObserved = func(string, identity.ActivityProcess) (identity.Process, error) {
					return identity.Process{}, errors.New("process exited")
				}
			case "expired-preview":
				a.e.mu.Lock()
				*clock = clock.Add(31 * time.Second)
				a.e.mu.Unlock()
				want = "preview_expired"
			case "expired-rule":
				d.Expires = func() *time.Time { x := clock.Add(time.Second); return &x }()
				p = requirePreview(t, a, d)
				q = saveRequest(a, p, d)
				a.e.mu.Lock()
				*clock = clock.Add(2 * time.Second)
				a.e.mu.Unlock()
				want = "preview_expired"
			case "stale-activity":
				snap.Collected = clock.Add(-time.Minute)
				q = previewRequest(a, d)
				want = "stale_target"
			case "shared":
				snap.Rows[0].Owners = []string{"123:10", "other:9"}
				snap.Rows[0].OwnershipCategory = "shared"
				q = previewRequest(a, d)
				want = "unsupported_target"
			case "runtime":
				v := snap.Processes["123:10"]
				v.Application.Kind = "wine"
				snap.Processes[v.ID] = v
				q = previewRequest(a, d)
				want = "unsupported_target"
			case "unknown":
				snap.Rows[0].Owners = nil
				q = previewRequest(a, d)
				want = "unsupported_target"
			case "incomplete-input":
				q = previewRequest(a, d)
				q.ObservedDraft.LocalPort = nil
				want = "invalid_request"
			case "duplicate":
				if r := callResponse(a.path, q); r.Error != "" {
					t.Fatal(r)
				}
				q = previewRequest(a, d)
				want = "invalid_rule"
			case "overlap-change":
				other := p.Rule
				other.ID = "other"
				other.Filter.RemoteAddress = "*"
				other.Action = "allow"
				if err := a.e.SetRules([]policy.Rule{other}); err != nil {
					t.Fatal(err)
				}
				want = "policy_conflict"
			}
			r := callResponse(a.path, q)
			assertCode(t, r, want)
			if r.SavedRule != nil {
				t.Fatal("failed creation acknowledged")
			}
		})
	}
}
func TestObservedCreationAuthorizationAndPersistence(t *testing.T) {
	var failed atomic.Bool
	a, snap, live, _ := observedAPI(t, func(e *Engine, s *store.Store) {
		e.SaveRules = func(rs []policy.Rule) error {
			if failed.Load() {
				return errors.New("disk failure")
			}
			return s.Replace(rs)
		}
	})
	d := observedDraft("incoming")
	foreign := uint32(os.Getuid() + 1)
	v := snap.Processes["123:10"]
	v.UID = foreign
	snap.Processes[v.ID] = v
	live.UID = foreign
	assertCode(t, callResponse(a.path, previewRequest(a, d)), "forbidden")
	actor := uint32(os.Getuid())
	// Ordinary peer stays UID scoped; administrator principal validation is covered
	// separately without mutating immutable server configuration after Serve.
	v.UID = actor
	snap.Processes[v.ID] = v
	live.UID = actor
	p := requirePreview(t, a, d)
	if p.PrincipalUID != actor {
		t.Fatal(p)
	}
	roPath := filepath.Join(filepath.Dir(a.path), "ro")
	ro, err := Serve(roPath, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	assertCode(t, callResponse(roPath, previewRequest(a, d)), "read_only")
	assertCode(t, callResponse(roPath, saveRequest(a, p, d)), "read_only")
	failed.Store(true)
	assertCode(t, callResponse(a.path, saveRequest(a, p, d)), "persistence_failed")
	stored, err := a.s.Load()
	if err != nil || len(stored) != 0 || len(a.e.Rules(actor, true)) != 0 {
		t.Fatal("failed commit published", stored, err)
	}
	failed.Store(false)
	r := callResponse(a.path, saveRequest(a, p, d))
	if r.Error != "" || r.SavedRule.Filter.UID != actor {
		t.Fatal(r)
	}
	// A receipt cannot resurrect a deleted/edited rule. Scope and lifetime are immutable here.
	version := r.SavedRule.Version
	del := callResponse(a.path, Request{Version: 1, Operation: "rule-delete", Generation: a.e.Generation, ID: r.SavedRule.ID, ExpectedVersion: &version})
	if del.Error != "" {
		t.Fatal(del)
	}
	assertCode(t, callResponse(a.path, saveRequest(a, p, d)), "replay_conflict")
}
func TestObservedConcurrentSaveAndBounds(t *testing.T) {
	a, _, _, _ := observedAPI(t)
	d := observedDraft("incoming")
	p := requirePreview(t, a, d)
	var wg sync.WaitGroup
	rs := make(chan Response, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rs <- callResponse(a.path, saveRequest(a, p, d)) }()
	}
	wg.Wait()
	close(rs)
	replay := 0
	for r := range rs {
		if r.Error != "" || r.SavedRule == nil {
			t.Fatal(r)
		}
		if r.Replayed {
			replay++
		}
	}
	if replay != 1 || len(a.e.Rules(uint32(os.Getuid()), true)) != 1 {
		t.Fatal("duplicate commit")
	}
	a2, _, _, clock := observedAPI(t)
	for i := 0; i < 16; i++ {
		requirePreview(t, a2, d)
	}
	assertCode(t, callResponse(a2.path, previewRequest(a2, d)), "limit_exceeded")
	a2.e.mu.Lock()
	*clock = clock.Add(31 * time.Second)
	a2.e.mu.Unlock()
	requirePreview(t, a2, d) // expired state is reclaimed, not unbounded
}
func TestObservedActualNativeUnixAPI(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		t.Skip("real ownership fixture requires disposable PID/network namespace; run scripts/lab.sh")
	}

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var c identity.ActivityCollector
	snapshot := c.Collect()
	var target ObservedTarget
	for _, row := range snapshot.Rows {
		if row.Socket.Protocol == "udp" && row.Socket.Local.String() == listener.LocalAddr().String() && len(row.Owners) == 1 {
			target = ObservedTarget{row.ID, row.Owners[0]}
			break
		}
	}
	if target.RowID == "" {
		t.Fatal("real native fixture missing")
	}
	a := newDeleteAPI(t, func(e *Engine, s *store.Store) {
		e.Mode = "daemon-monitor"
		e.Now = time.Now
		e.SetRules(nil)
		s.Replace(nil)
		e.Activity = func() identity.ActivitySnapshot { return snapshot }
		e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "stopped"} }
	})
	d := observedDraft("incoming")
	q := previewRequest(a, d)
	q.ObservedTarget = &target
	r := callResponse(a.path, q)
	if r.Error != "" || r.ObservedPreview == nil || r.PeerUID != uint32(os.Getuid()) {
		t.Fatalf("actual preview %+v", r)
	}
	p := *r.ObservedPreview
	blob, _ := json.MarshalIndent(struct {
		Request  Request  `json:"request"`
		Response Response `json:"response"`
	}{q, r}, "", "  ")
	os.WriteFile("../../.workspace/observed-rule-preview-example.json", blob, 0600)
	saved := callResponse(a.path, saveRequest(a, p, d))
	if saved.Error != "" || saved.SavedRule == nil {
		t.Fatal(saved)
	}
	blob, _ = json.MarshalIndent(struct {
		Request  Request  `json:"request"`
		Response Response `json:"response"`
	}{saveRequest(a, p, d), saved}, "", "  ")
	os.WriteFile("../../.workspace/observed-rule-save-example.json", blob, 0600)
	// A stored Block in this non-enforcing API session has no packet effect.
	peer, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err = peer.WriteTo([]byte("stored-only"), listener.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := listener.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "stored-only" {
		t.Fatal("monitor mode must not block", n, err)
	}
	view := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation})
	var inactive bool
	for _, app := range view.PolicyView.Applications {
		if app.Identity.Key == p.Rule.Filter.Application {
			inactive = app.Incoming.Active == 1 && !app.Incoming.Enforcement.Covered && app.Incoming.Enforcement.State == "stopped"
		}
	}
	if !inactive {
		t.Fatal("stored Block reported effective", view)
	}
	if r.Permissions.CanDecide || !r.Permissions.CanManageRules {
		t.Fatal("management must be independent of decisions", r.Permissions)
	}
	// Actual inherited FD in another executable turns the target into shared
	// ownership. A stale single-holder Activity row cannot authorize creation.
	out := observedDraft("outgoing")
	q = previewRequest(a, out)
	q.ObservedTarget = &target
	next := callResponse(a.path, q)
	if next.Error != "" {
		t.Fatal(next)
	}
	file, err := listener.(*net.UDPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("python3", "-c", "import os,time; os.fstat(3); print('READY',flush=True); time.sleep(30)")
	child.ExtraFiles = []*os.File{file}
	ready, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	t.Cleanup(func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	line, _ := bufio.NewReader(ready).ReadString('\n')
	if line != "READY\n" {
		t.Fatal("shared fixture not ready", line)
	}
	assertCode(t, callResponse(a.path, saveRequest(a, *next.ObservedPreview, out)), "stale_target")
	child.Process.Kill()
	child.Wait()
	sharedRecovered := callResponse(a.path, saveRequest(a, *next.ObservedPreview, out))
	if sharedRecovered.Error != "" {
		t.Fatal(sharedRecovered)
	}
	// Closing the real FD invalidates a fresh preview; committed receipts remain.
	out.RemoteAddress = "127.0.0.3"
	q = previewRequest(a, out)
	q.ObservedTarget = &target
	next = callResponse(a.path, q)
	if next.Error != "" {
		t.Fatal(next)
	}
	listener.Close()
	assertCode(t, callResponse(a.path, saveRequest(a, *next.ObservedPreview, out)), "stale_target")
	t.Log("real native Activity -> fresh bounded census/Inspect -> authenticated Unix preview/save, stored-only Block; actual shared holder and close rejected")
}

func TestObservedAdministratorServiceIdentity(t *testing.T) {
	a, snap, live, _ := observedAPI(t)
	v := snap.Processes["123:10"]
	v.UID = 0
	snap.Processes[v.ID] = v
	live.UID = 0
	d := observedDraft("incoming")
	p, err := a.e.PreviewObservedRule(a.e.Generation, ObservedTarget{"cookie", "123:10"}, d, 1000, true, nil)
	if err != nil || p.PrincipalUID != 0 {
		t.Fatal(p, err)
	}
	r, _, _, err := a.e.SaveObservedRule(a.e.Generation, p.Token, d, 1000, true)
	if err != nil || r.Filter.UID != 0 {
		t.Fatal(r, err)
	}
}

func TestObservedExplicitScopesAndPrincipalBinding(t *testing.T) {
	for _, address := range []string{"*", "2001:db8::1", "192.0.2.0/24"} {
		t.Run(address, func(t *testing.T) {
			a, _, _, _ := observedAPI(t)
			d := observedDraft("outgoing")
			d.Protocol = "tcp"
			d.RemoteAddress = address
			p := requirePreview(t, a, d)
			if p.Rule.Filter.RemoteAddress != address || p.Rule.Filter.LocalPort != 0 || p.Rule.Filter.RemotePort != 0 || p.Rule.Priority != 100 || !p.Rule.Expires.IsZero() {
				t.Fatal(p)
			}
			if _, _, _, err := a.e.SaveObservedRule(a.e.Generation, p.Token, d, uint32(os.Getuid()+1), false); err == nil {
				t.Fatal("foreign principal reused token")
			}
			d.Expires = nil
			assertCode(t, callResponse(a.path, previewRequest(a, d)), "invalid_request")
		})
	}
}
