package daemon

import (
	"database/sql"
	"encoding/json"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type deleteAPI struct {
	e        *Engine
	s        *store.Store
	path, db string
	rule     policy.Rule
}

func newDeleteAPI(t *testing.T, setup ...func(*Engine, *store.Store)) *deleteAPI {
	t.Helper()
	dir, err := os.MkdirTemp("../../.workspace/tmp", "delete-")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ = filepath.Abs(dir)
	t.Cleanup(func() { os.RemoveAll(dir) })
	e, f, a, now := fixture()
	r := policy.Rule{Schema: 2, ID: "seed", Version: 1, Action: "allow", Created: *now, Filter: policy.Remembered(f, *a)}
	s, err := store.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if err = e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	e.SaveRules = s.Replace
	for _, configure := range setup {
		configure(e, s)
	}
	path := filepath.Join(dir, "s")
	l, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &deleteAPI{e: e, s: s, path: path, db: filepath.Join(dir, "rules.db"), rule: r}
}
func (a *deleteAPI) deleteRequest() Request {
	v := a.rule.Version
	return Request{Version: 1, Operation: "rule-delete", Generation: a.e.Generation, ID: a.rule.ID, ExpectedVersion: &v}
}
func (a *deleteAPI) editRequest() Request {
	r := a.rule
	r.Action = "block"
	v := r.Version
	return Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation, ID: r.ID, ExpectedVersion: &v, Rule: &r}
}
func callResponse(path string, q Request) Response { r, _ := Call(path, q); return r }
func assertCode(t *testing.T, r Response, code string) {
	t.Helper()
	if r.ErrorCode != code || r.Error == "" || r.DeletedRule != nil {
		t.Fatalf("want %s, got %+v", code, r)
	}
}
func TestConditionalDeleteCurrentAndRestart(t *testing.T) {
	a := newDeleteAPI(t)
	r := callResponse(a.path, Request{Version: 1, Operation: "list"})
	if len(r.Capabilities) == 0 || r.Capabilities[0] != ConditionalDeleteCapability {
		t.Fatal("missing capability")
	}
	r = callResponse(a.path, a.deleteRequest())
	if r.Error != "" || r.DeletedRule == nil || r.DeletedRule.Version != a.rule.Version {
		t.Fatal(r)
	}
	restarted, err := store.Open(a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	rs, err := restarted.Load()
	if err != nil || len(rs) != 0 {
		t.Fatal("delete not persisted", rs, err)
	}
	fresh := New(time.Second)
	fresh.SaveRules = restarted.Replace
	if err = fresh.SetRules(rs); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(a.path), "restarted")
	l, err := Serve(path, fresh, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	listed := callResponse(path, Request{Version: 1, Operation: "list"})
	if listed.Error != "" || len(listed.Rules) != 0 || listed.Generation == a.e.Generation {
		t.Fatal("restart did not preserve deletion/new generation", listed)
	}

	assertCode(t, callResponse(a.path, a.deleteRequest()), "not_found")
}
func TestConditionalDeleteEditOrdering(t *testing.T) {
	for _, first := range []string{"edit", "delete"} {
		t.Run(first, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			a := newDeleteAPI(t, func(e *Engine, s *store.Store) {
				e.SaveRules = func(rs []policy.Rule) error { once.Do(func() { close(entered); <-release }); return s.Replace(rs) }
			})
			firstQ, secondQ := a.editRequest(), a.deleteRequest()
			if first == "delete" {
				firstQ, secondQ = secondQ, firstQ
			}
			done1, done2 := make(chan Response, 1), make(chan Response, 1)
			go func() { done1 <- callResponse(a.path, firstQ) }()
			<-entered // First mutation owns engine lock, before durable commit.
			go func() { done2 <- callResponse(a.path, secondQ) }()
			close(release)
			if r := <-done1; r.Error != "" {
				t.Fatal(r)
			}
			second := <-done2
			rs, err := a.s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if first == "edit" {
				assertCode(t, second, "version_conflict")
				if len(rs) != 1 || rs[0].Action != "block" || rs[0].Version != 2 {
					t.Fatal(rs)
				}
			} else {
				assertCode(t, second, "not_found")
				if len(rs) != 0 {
					t.Fatal("stale edit recreated rule", rs)
				}
			}
		})
	}
}
func TestConditionalDeleteTwoClients(t *testing.T) {
	a := newDeleteAPI(t)
	start := make(chan struct{})
	results := make(chan Response, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; results <- callResponse(a.path, a.deleteRequest()) }()
	}
	close(start)
	ok, missing := 0, 0
	for i := 0; i < 2; i++ {
		r := <-results
		if r.Error == "" && r.DeletedRule != nil {
			ok++
		} else if r.ErrorCode == "not_found" {
			missing++
		} else {
			t.Fatal(r)
		}
	}
	if ok != 1 || missing != 1 {
		t.Fatal(ok, missing)
	}
}
func TestConditionalDeleteRecreationAndGeneration(t *testing.T) {
	a := newDeleteAPI(t)
	if r := callResponse(a.path, a.deleteRequest()); r.Error != "" {
		t.Fatal(r)
	}
	// API creation cannot choose an ID: even the same scope gets a fresh random ID.
	_, f, _, _ := fixture()
	v := a.e.Observe(f, "fresh-after-delete")
	candidate := a.rule
	candidate.ID = "seed"
	candidate.Version = 1
	create := Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation, EventID: v.ID, Rule: &candidate}
	r := callResponse(a.path, create)
	if r.Error != "" || r.SavedRule == nil || r.SavedRule.ID == a.rule.ID {
		t.Fatal("recreated identity was reused", r)
	}
	assertCode(t, callResponse(a.path, a.deleteRequest()), "not_found")
	if len(a.e.Rules(1000, false)) != 1 {
		t.Fatal("replacement deleted")
	}
	// Simulate a new daemon loading the *same* ID/version from storage. Generation
	// alone must reject the old request before it can mutate this session.
	e2 := New(time.Second)
	e2.SaveRules = a.s.Replace
	if err := e2.SetRules([]policy.Rule{a.rule}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(a.path), "new")
	l, err := Serve(path, e2, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	assertCode(t, callResponse(path, a.deleteRequest()), "generation_conflict")
	if len(e2.Rules(1000, false)) != 1 {
		t.Fatal("new session mutated")
	}
}
func TestConditionalDeleteTransactionFailure(t *testing.T) {
	a := newDeleteAPI(t)
	db, err := sql.Open("sqlite3", a.db)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Real SQLite abort inside Store.Replace, not a simulated storage helper.
	_, err = db.Exec("CREATE TRIGGER reject_delete BEFORE DELETE ON rules BEGIN SELECT RAISE(ABORT,'injected delete failure'); END;")
	if err != nil {
		t.Fatal(err)
	}
	_, f, _, _ := fixture()
	event := a.e.Observe(f, "preserve-cache")
	assertCode(t, callResponse(a.path, a.deleteRequest()), "persistence_failed")
	rs, err := a.s.Load()
	if err != nil || len(rs) != 1 || rs[0].Version != a.rule.Version {
		t.Fatal(rs, err)
	}
	if len(a.e.Rules(1000, false)) != 1 || a.e.RetainedState(event.ID, event.Attribution.Fingerprint) != "allow" {
		t.Fatal("failed delete changed effective policy or cache")
	}
}
func TestConditionalDeleteAuthorizationAndErrors(t *testing.T) {
	a := newDeleteAPI(t)
	q := a.deleteRequest()
	q.ExpectedVersion = nil
	assertCode(t, callResponse(a.path, q), "invalid_request")
	q = a.deleteRequest()
	q.Generation = ""
	assertCode(t, callResponse(a.path, q), "generation_conflict")
	ro := filepath.Join(filepath.Dir(a.path), "ro")
	l, err := Serve(ro, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	assertCode(t, callResponse(ro, a.deleteRequest()), "read_only")
	if os.Getuid() != 0 {
		a.e.mu.Lock()
		a.e.rules[0].Filter.UID = uint32(os.Getuid() + 1)
		a.e.mu.Unlock()
		assertCode(t, callResponse(a.path, a.deleteRequest()), "forbidden")
	} else {
		t.Log("wrong-UID Unix peer test requires unprivileged test user; root remains admin")
	}
	if len(a.e.Rules(0, true)) != 1 {
		t.Fatal("unauthorized mutation")
	}
}
func TestConditionalDeleteUnavailableAndLegacyCompatibility(t *testing.T) {
	degraded := newDeleteAPI(t, func(e *Engine, _ *store.Store) {
		e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "degraded"} }
	})
	assertCode(t, callResponse(degraded.path, degraded.deleteRequest()), "unavailable")
	unavailable := newDeleteAPI(t, func(e *Engine, _ *store.Store) { e.SaveRules = nil })
	assertCode(t, callResponse(unavailable.path, unavailable.deleteRequest()), "unavailable")
	a := newDeleteAPI(t)
	edit := callResponse(a.path, a.editRequest())
	if edit.Error != "" {
		t.Fatal(edit)
	}
	assertCode(t, callResponse(a.path, a.deleteRequest()), "version_conflict")
	// Legacy Qt clients deliberately retain unconditional deletion semantics.
	r := callResponse(a.path, Request{Version: 1, Operation: "rule", ID: a.rule.ID, Action: "delete"})
	if r.Error != "" || len(a.e.Rules(0, true)) != 0 {
		t.Fatal("legacy compatibility changed", r)
	}
}

func TestConditionalDeleteLostResponse(t *testing.T) {
	committed := make(chan struct{})
	a := newDeleteAPI(t, func(e *Engine, s *store.Store) {
		e.SaveRules = func(rs []policy.Rule) error {
			err := s.Replace(rs)
			if err == nil {
				close(committed)
			}
			return err
		}
	})
	c, err := net.Dial("unix", a.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(c).Encode(a.deleteRequest()); err != nil {
		t.Fatal(err)
	}
	c.Close() // Deliberately discard acknowledgement.
	<-committed
	listed := callResponse(a.path, Request{Version: 1, Operation: "list"})
	if len(listed.Rules) != 0 {
		t.Fatal("authoritative inspection did not resolve ambiguity")
	}
	assertCode(t, callResponse(a.path, a.deleteRequest()), "not_found")
}

func TestConditionalDeleteVersionExhaustion(t *testing.T) {
	a := newDeleteAPI(t)
	a.rule.Version = ^uint64(0)
	if err := a.e.SetRules([]policy.Rule{a.rule}); err != nil {
		t.Fatal(err)
	}
	if err := a.s.Replace([]policy.Rule{a.rule}); err != nil {
		t.Fatal(err)
	}
	r := callResponse(a.path, a.editRequest())
	if r.Error == "" {
		t.Fatal("edit wrapped version")
	}
	r = callResponse(a.path, Request{Version: 1, Operation: "rule", ID: a.rule.ID, Action: "enable"})
	if r.Error == "" {
		t.Fatal("enable wrapped version")
	}
	if a.e.Rules(0, true)[0].Version != ^uint64(0) {
		t.Fatal("version reset")
	}
	r = callResponse(a.path, a.deleteRequest())
	if r.Error != "" || r.DeletedRule == nil {
		t.Fatal("exhausted version could not be deleted", r)
	}
}
