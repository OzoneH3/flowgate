package daemon

import (
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func processAPI(t *testing.T, configs ...func(*Engine, *store.Store)) (*deleteAPI, identity.Process, *identity.ActivitySnapshot, *time.Time) {
	t.Helper()
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	a, snap, _, clock := observedAPI(t, func(e *Engine, db *store.Store) {
		e.verifyObserved = func(string, identity.ActivityProcess) (identity.Process, error) { return p, nil }
		for _, f := range configs {
			f(e, db)
		}
	})
	id := fmt.Sprintf("%d:%s", p.PID, p.Start)
	snap.Processes = map[string]identity.ActivityProcess{id: {ID: id, PID: p.PID, Start: p.Start, UID: p.UID, Executable: p.Executable, Application: p.Application, BootID: p.BootID, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS}}
	snap.Rows[0].Owners = []string{id}
	t.Cleanup(a.e.CloseProcessTargets)
	return a, p, snap, clock
}
func processPreview(t *testing.T, a *deleteAPI, p identity.Process, d ObservedDraft) ObservedPreview {
	t.Helper()
	r := callResponse(a.path, Request{Version: 1, Operation: "observed-rule-preview", Generation: a.e.Generation, ObservedTarget: &ObservedTarget{"cookie", fmt.Sprintf("%d:%s", p.PID, p.Start)}, ObservedDraft: &d})
	if r.Error != "" || r.ObservedPreview == nil {
		t.Fatalf("preview %+v", r)
	}
	return *r.ObservedPreview
}
func TestProcessActualAPIStorageAndLifecycle(t *testing.T) {
	a, p, _, _ := processAPI(t)
	d := observedDraft("incoming")
	d.TargetScope = "process"
	d.Action = "allow"
	preview := processPreview(t, a, p, d)
	b := preview.Rule.Filter.Process
	if preview.Rule.Schema != 3 || len(b.ID) != 32 || !b.Matches(p) || preview.Enforcement.Covered {
		t.Fatal(preview)
	}
	r := callResponse(a.path, saveRequest(a, preview, d))
	if r.Error != "" || r.SavedRule == nil || r.SavedRule.Filter.Process != b {
		t.Fatal(r)
	}
	if retry := callResponse(a.path, saveRequest(a, preview, d)); retry.Error != "" || !retry.Replayed {
		t.Fatal(retry)
	}
	ad := d
	ad.TargetScope = "application"
	ap := processPreview(t, a, p, ad)
	if r = callResponse(a.path, saveRequest(a, ap, ad)); r.Error != "" {
		t.Fatal(r)
	}
	view := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation})
	if view.Error != "" || len(view.PolicyView.Processes) != 1 || view.PolicyView.Processes[0].Incoming.Active != 1 || view.PolicyView.Processes[0].ApplicationIncoming.Active != 1 || view.PolicyView.Applications[0].Incoming.Active != 1 {
		t.Fatalf("view %+v", view.PolicyView)
	}
	if s := decisionlog.Snapshot(preview.Rule); s.TargetScope != "process" || s.Filter.Process != b {
		t.Fatal(s)
	}
	// Native resolver attribution is rechecked even while a matching admission is cached.
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.2:2222")
	att := identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, Sockets: []identity.Socket{{}}, VisibilityComplete: true, Fingerprint: "live"}
	a.e.Resolve = func(identity.Flow) identity.Attribution { return att }
	if a.e.Observe(f, "udp").State != "allowed" {
		t.Fatal("not allowed")
	}
	candidate := preview.Rule
	candidate.Action = "block"
	v := candidate.Version
	r = callResponse(a.path, Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation, ID: candidate.ID, ExpectedVersion: &v, Rule: &candidate})
	if r.Error != "" {
		t.Fatal(r)
	}
	if a.e.Observe(f, "udp").State != "blocked" {
		t.Fatal("cache defeated process override")
	}
	candidate = *r.SavedRule
	candidate.Filter.Process = identity.Instance{}
	v = candidate.Version
	assertCode(t, callResponse(a.path, Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation, ID: candidate.ID, ExpectedVersion: &v, Rule: &candidate}), "immutable_target")
	// Simulate losing current target authority; persisted rule remains with explicit lifecycle state.
	a.e.mu.Lock()
	a.e.processHandles[b].Close()
	a.e.mu.Unlock()
	inactive := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation})
	if inactive.PolicyView.Snapshot.Token == view.PolicyView.Snapshot.Token || func() bool {
		for _, x := range inactive.PolicyView.Processes {
			if x.Target == b {
				return x.State != "inactive"
			}
		}
		return true
	}() {
		t.Fatal(inactive.PolicyView)
	}
	stored, err := a.s.Load()
	if err != nil || len(stored) != 2 {
		t.Fatal(stored, err)
	}
	fresh := New(time.Second)
	defer fresh.CloseProcessTargets()
	fresh.SetRules(stored)
	for _, s := range fresh.RuleStates(p.UID, true) {
		if s.TargetScope == "process" && s.State != "inactive" {
			t.Fatal("restart revived process rule")
		}
	}
}
func TestProcessPreviewBoundariesAndAtomicFailure(t *testing.T) {
	for _, kind := range []string{"expiry", "generation", "draft", "shared", "runtime", "exit", "failure", "readonly", "unauthorized"} {
		t.Run(kind, func(t *testing.T) {
			var fail atomic.Bool
			a, p, snap, clock := processAPI(t, func(e *Engine, db *store.Store) {
				e.SaveRules = func(rs []policy.Rule) error {
					if fail.Load() {
						return errors.New("injected SQLite failure")
					}
					return db.Replace(rs)
				}
			})
			d := observedDraft("outgoing")
			d.TargetScope = "process"
			pv := processPreview(t, a, p, d)
			q := saveRequest(a, pv, d)
			want := ""
			switch kind {
			case "expiry":
				*clock = clock.Add(31 * time.Second)
				want = "preview_expired"
			case "generation":
				q.Generation = "old"
				want = "generation_conflict"
			case "draft":
				q.ObservedDraft.Action = "allow"
				want = "preview_mismatch"
			case "shared":
				snap.Rows[0].Owners = append(snap.Rows[0].Owners, "other")
				a.e.verifyObserved = func(string, identity.ActivityProcess) (identity.Process, error) {
					return identity.Process{}, errors.New("fresh exclusive native identity unavailable")
				}
				want = "stale_target"
			case "runtime":
				p2 := snap.Processes[snap.Rows[0].Owners[0]]
				p2.Application.Kind = "wine-unresolved"
				snap.Processes[p2.ID] = p2
				a.e.verifyObserved = func(string, identity.ActivityProcess) (identity.Process, error) {
					return identity.Process{}, errors.New("fresh exclusive native identity unavailable")
				}
				want = "stale_target"
			case "exit":
				a.e.processHandles[pv.Rule.Filter.Process].Close()
				want = "target_inactive"
			case "failure":
				fail.Store(true)
				want = "persistence_failed"
			case "readonly":
				l, err := Serve(a.path+"r", a.e, true)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				assertCode(t, callResponse(a.path+"r", q), "read_only")
				return
			case "unauthorized":
				_, err := a.e.PreviewObservedRule(a.e.Generation, ObservedTarget{"cookie", fmt.Sprintf("%d:%s", p.PID, p.Start)}, d, p.UID+1, false, nil)
				if err == nil {
					t.Fatal("foreign UID accepted")
				}
				return
			}
			r := callResponse(a.path, q)
			assertCode(t, r, want)
			stored, err := a.s.Load()
			if err != nil || len(stored) != 0 || len(a.e.Rules(p.UID, true)) != 0 {
				t.Fatal("failed mutation changed policy", stored, err)
			}
		})
	}
}
func TestProcessInventoryPrivacyAndUnsafePreview(t *testing.T) {
	a, p, snap, _ := processAPI(t)
	d := observedDraft("incoming")
	d.TargetScope = "process"
	pv := processPreview(t, a, p, d)
	r := callResponse(a.path, saveRequest(a, pv, d))
	if r.Error != "" {
		t.Fatal(r)
	}
	v, err := a.e.PolicyView(a.e.Generation, "", p.UID+1, false, nil)
	if err != nil || len(v.Processes) != 0 || len(v.Applications) != 0 || len(v.Rows) != 0 {
		t.Fatal("foreign inventory leaked", v, err)
	}
	for _, kind := range []string{"shared", "runtime", "unknown"} {
		old := snap.Rows[0]
		procs := snap.Processes
		copy := map[string]identity.ActivityProcess{}
		for k, v := range procs {
			copy[k] = v
		}
		snap.Processes = copy
		switch kind {
		case "shared":
			snap.Rows[0].Owners = []string{old.Owners[0], "second"}
		case "unknown":
			snap.Rows[0].Owners = nil
		case "runtime":
			x := snap.Processes[old.Owners[0]]
			x.Application.Kind = "wine-unresolved"
			snap.Processes[x.ID] = x
		}
		out := callResponse(a.path, Request{Version: 1, Operation: "observed-rule-preview", Generation: a.e.Generation, ObservedTarget: &ObservedTarget{"cookie", fmt.Sprintf("%d:%s", p.PID, p.Start)}, ObservedDraft: &d})
		if out.Error == "" {
			t.Fatal("unsafe preview", kind)
		}
		snap.Rows[0] = old
		snap.Processes = procs
	}
}
func TestProcessBlockSupersedesRetainedOnce(t *testing.T) {
	a, p, _, _ := processAPI(t)
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.2:2222")
	att := identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, Sockets: []identity.Socket{{}}, VisibilityComplete: true, Fingerprint: "pinned"}
	a.e.Resolve = func(identity.Flow) identity.Attribution { return att }
	v := a.e.Observe(f, "udp")
	if _, err := a.e.Decide(v.ID, "allow", "once", p.UID, false); err != nil {
		t.Fatal(err)
	}
	if a.e.RetainedState(v.ID, att.Fingerprint) != "allow" {
		t.Fatal("Once not admitted")
	}
	d := observedDraft("incoming")
	d.TargetScope = "process"
	pv := processPreview(t, a, p, d)
	r := callResponse(a.path, saveRequest(a, pv, d))
	if r.Error != "" {
		t.Fatal(r)
	}
	if a.e.RetainedState(v.ID, att.Fingerprint) != "drop" {
		t.Fatal("Once bypassed new process Block")
	}
	if a.e.Observe(f, "udp").State != "blocked" {
		t.Fatal("cached Once bypassed Block")
	}
}
