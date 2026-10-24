package daemon

import (
	"errors"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"slices"
	"sync/atomic"
	"testing"
)

// Existing rule-effect tests explicitly use the current listed version. Stale
// and missing conditions are exercised directly below, without this helper.
func changeListedRule(e *Engine, id, action string, uid uint32, admin bool) error {
	var version *uint64
	for _, r := range e.Rules(0, true) {
		if r.ID == id {
			v := r.Version
			version = &v
			break
		}
	}
	return e.ChangeRule(e.Generation, id, action, version, uid, admin)
}
func TestLegacyRuleMutationConditions(t *testing.T) {
	for _, action := range []string{"enable", "disable", "delete"} {
		t.Run(action, func(t *testing.T) {
			a := newDeleteAPI(t)
			if !slices.Contains(callResponse(a.path, Request{Version: 1, Operation: "list"}).Capabilities, ConditionalMutationCapability) {
				t.Fatal("mutation capability absent")
			}
			v := a.rule.Version
			q := Request{Version: 1, Operation: "rule", ID: a.rule.ID, Action: action, Generation: a.e.Generation, ExpectedVersion: &v}
			for _, test := range []struct {
				name, code string
				edit       func(*Request)
			}{
				{"missing generation", "generation_conflict", func(q *Request) { q.Generation = "" }},
				{"old daemon", "generation_conflict", func(q *Request) { q.Generation = "old" }},
				{"missing version", "invalid_request", func(q *Request) { q.ExpectedVersion = nil }},
				{"old version", "version_conflict", func(q *Request) { old := uint64(0); q.ExpectedVersion = &old }},
			} {
				t.Run(test.name, func(t *testing.T) { bad := q; test.edit(&bad); assertCode(t, callResponse(a.path, bad), test.code) })
			}
			if r := callResponse(a.path, q); r.Error != "" {
				t.Fatal(r)
			}
			code := "version_conflict"
			if action == "delete" {
				code = "not_found"
			}
			assertCode(t, callResponse(a.path, q), code)
			rows, err := a.s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if action == "delete" {
				if len(rows) != 0 {
					t.Fatal(rows)
				}
			} else if len(rows) != 1 || rows[0].Version != v+1 || rows[0].Disabled != (action == "disable") {
				t.Fatal(rows)
			}
		})
	}
}
func TestLegacyRuleMutationPersistenceFailureRetainsVersion(t *testing.T) {
	var failed atomic.Bool
	failed.Store(true)
	a := newDeleteAPI(t, func(e *Engine, s *store.Store) {
		e.SaveRules = func(rs []policy.Rule) error {
			if failed.Load() {
				return errors.New("injected write failure")
			}
			return s.Replace(rs)
		}
	})
	version := a.rule.Version
	q := Request{Version: 1, Operation: "rule", ID: a.rule.ID, Action: "disable", Generation: a.e.Generation, ExpectedVersion: &version}
	assertCode(t, callResponse(a.path, q), "persistence_failed")
	rows := a.e.Rules(0, true)
	if len(rows) != 1 || rows[0].Version != version || rows[0].Disabled {
		t.Fatal(rows)
	}
	failed.Store(false)
	if r := callResponse(a.path, q); r.Error != "" {
		t.Fatal(r)
	}
}
