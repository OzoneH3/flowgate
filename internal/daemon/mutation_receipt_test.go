package daemon

import (
	"encoding/json"
	"errors"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func waitMutation(t *testing.T, path string, q Request) *MutationReceipt {
	t.Helper()
	status := Request{Version: 1, Operation: "mutation-status", Generation: q.Generation, MutationID: q.MutationID}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		r := callResponse(path, status)
		if r.MutationReceipt != nil && r.MutationReceipt.State == "completed" {
			return r.MutationReceipt
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("missing completed receipt")
	return nil
}

func mutationResultFor(t *testing.T, receipt *MutationReceipt) mutationResult {
	t.Helper()
	if receipt == nil || receipt.State != "completed" {
		t.Fatal(receipt)
	}
	var result mutationResult
	if err := json.Unmarshal(receipt.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMutationReceiptReconcilesDisconnectedCreation(t *testing.T) {
	a, _, _, _ := observedAPI(t)
	draft := observedDraft("incoming")
	p := requirePreview(t, a, draft)
	if r := callResponse(a.path, saveRequest(a, p, draft)); r.SavedRule == nil {
		t.Fatal(r)
	}
	// Legacy creation from a saved basis has no preview token. Repeating the
	// same request without an id would allocate a second ID.
	candidate := p.Rule
	candidate.Filter.Direction = "outgoing"
	q := Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation,
		MutationID: "11111111111111111111111111111111", BasisRuleID: p.Rule.ID, Rule: &candidate}
	c, err := net.Dial("unix", a.path)
	if err != nil {
		t.Fatal(err)
	}
	err = json.NewEncoder(c).Encode(q)
	c.Close() // deliberately discard the reply
	if err != nil {
		t.Fatal(err)
	}
	receipt := waitMutation(t, a.path, q)
	got := mutationResultFor(t, receipt)
	if got.Error != "" || got.SavedRule == nil || got.SavedRule.Filter.Direction != "outgoing" {
		t.Fatal(string(receipt.Result))
	}
	replay := callResponse(a.path, q)
	if !replay.Replayed || replay.MutationReceipt == nil || !reflect.DeepEqual(receipt, replay.MutationReceipt) {
		t.Fatal(replay)
	}
	candidate.Action = "allow"
	assertCode(t, callResponse(a.path, q), "mutation_conflict")
	if rows, err := a.s.Load(); err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}

	ordinary := Response{PeerUID: uint32(os.Getuid()) + 1}
	_, _ = a.e.beginMutation(Request{Version: 1, Operation: "mutation-status", Generation: q.Generation, MutationID: q.MutationID}, &ordinary, false)
	if ordinary.ErrorCode != "not_found" || ordinary.MutationReceipt != nil {
		t.Fatal(ordinary)
	}
	q.Generation = "formerly-running"
	assertCode(t, callResponse(a.path, q), "generation_conflict")
}

func TestApplicationRuleDeleteByExactSnapshot(t *testing.T) {
	a := newDeleteAPI(t)
	first := a.rule
	second := first
	second.ID, second.Filter.Direction = "other-direction", "incoming"
	if first.Filter.Direction == "incoming" {
		second.Filter.Direction = "outgoing"
	}
	other := first
	other.ID, other.Filter.Application = "other-application", "other-app"
	forward := first
	forward.ID = "added-after-selection"
	rules := append(a.e.Rules(uint32(os.Getuid()), true), second, other, forward)
	if err := a.e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	if err := a.s.Replace(rules); err != nil {
		t.Fatal(err)
	}
	q := Request{Version: 1, Operation: "application-rule-delete", Generation: a.e.Generation,
		ApplicationRuleDelete: &ApplicationRuleDelete{Application: first.Filter.Application, UID: &first.Filter.UID,
			Rules: []ApplicationRuleRef{{first.ID, &first.Version}, {second.ID, nil}}}}
	assertCode(t, callResponse(a.path, q), "invalid_request")
	stale := second.Version + 1
	q.ApplicationRuleDelete.Rules[1].Version = &stale
	assertCode(t, callResponse(a.path, q), "version_conflict")
	q.ApplicationRuleDelete.Rules[1] = ApplicationRuleRef{other.ID, &other.Version}
	assertCode(t, callResponse(a.path, q), "invalid_target")
	roPath := a.path + ".ro"
	ro, err := Serve(roPath, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	q.ApplicationRuleDelete.Rules[1] = ApplicationRuleRef{second.ID, &second.Version}
	q.MutationID = "22222222222222222222222222222222"
	assertCode(t, callResponse(roPath, q), "read_only")
	if rows, err := a.s.Load(); err != nil || len(rows) != len(rules) {
		t.Fatal(rows, err)
	}
	want := []DeletedRule{{first.ID, first.Version}, {second.ID, second.Version}}
	r := callResponse(a.path, q)
	if r.Error != "" || !reflect.DeepEqual(r.DeletedRules, want) {
		t.Fatal(r)
	}
	if got := mutationResultFor(t, waitMutation(t, a.path, q)); !reflect.DeepEqual(got.DeletedRules, want) {
		t.Fatal(got)
	}
	r = callResponse(a.path, q)
	if !r.Replayed || r.Error != "" {
		t.Fatal(r)
	}
	if rows, err := a.s.Load(); err != nil || len(rows) != 2 || rows[0].ID != forward.ID || rows[1].ID != other.ID {
		t.Fatal(rows, err)
	}
}

func TestRuleToggleReturnsConditionalResult(t *testing.T) {
	a := newDeleteAPI(t)
	q := a.deleteRequest()
	q.Operation, q.Action = "rule", "disable"
	q.MutationID = "33333333333333333333333333333333"
	r := callResponse(a.path, q)
	if r.SavedRule == nil || r.SavedRule.ID != q.ID || !r.SavedRule.Disabled || r.SavedRule.Version != *q.ExpectedVersion+1 {
		t.Fatal(r)
	}
	if got := mutationResultFor(t, r.MutationReceipt); got.SavedRule == nil || got.SavedRule.Version != r.SavedRule.Version {
		t.Fatal(got)
	}
	q.Action = "enable"
	q.MutationID = ""
	assertCode(t, callResponse(a.path, q), "version_conflict")
	q.ExpectedVersion = &r.SavedRule.Version
	r = callResponse(a.path, q)
	if r.SavedRule == nil || r.SavedRule.Disabled {
		t.Fatal(r)
	}
}

func TestApplicationRuleDeleteStoreErrorIsAtomic(t *testing.T) {
	a := newDeleteAPI(t, func(e *Engine, _ *store.Store) {
		e.SaveRules = func([]policy.Rule) error { return errors.New("fixture storage failure") }
	})
	r := a.rule
	q := Request{Version: 1, Operation: "application-rule-delete", Generation: a.e.Generation,
		ApplicationRuleDelete: &ApplicationRuleDelete{Application: r.Filter.Application, UID: &r.Filter.UID,
			Rules: []ApplicationRuleRef{{r.ID, &r.Version}}}}
	assertCode(t, callResponse(a.path, q), "persistence_failed")
	if rows := a.e.Rules(uint32(os.Getuid()), true); len(rows) != 1 {
		t.Fatal(rows)
	}
}
