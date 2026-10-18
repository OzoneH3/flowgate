package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestObservedWildcardAPI(t *testing.T) {
	a, p, _, _ := processAPI(t)
	for _, scope := range []string{"application", "process"} {
		d := observedDraft("incoming")
		d.TargetScope = scope
		d.Protocol = "*"
		d.RemoteAddress = "*"
		d.Action = "allow"
		pv := processPreview(t, a, p, d)
		if pv.Rule.Filter.Protocol != "*" || !strings.Contains(pv.ScopePreview, "TCP+UDP only") {
			t.Fatal(pv)
		}
		r := callResponse(a.path, saveRequest(a, pv, d))
		if r.Error != "" || r.SavedRule.Filter.Protocol != "*" {
			t.Fatal(r)
		}
		retry := callResponse(a.path, saveRequest(a, pv, d))
		if !retry.Replayed || retry.SavedRule.ID != r.SavedRule.ID {
			t.Fatal(retry)
		}
		changed := d
		changed.Protocol = "tcp"
		assertCode(t, callResponse(a.path, saveRequest(a, pv, changed)), "preview_mismatch")
	}
	view := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation}).PolicyView
	if view.Applications[0].Incoming.Configured != "uniform" || view.Processes[0].Incoming.Configured != "uniform" || view.Applications[0].Outgoing.Configured != "absent" {
		t.Fatal(view)
	}
	for _, r := range a.e.Rules(p.UID, true) {
		candidate := r
		candidate.Filter.Protocol = "tcp"
		v := r.Version
		assertCode(t, callResponse(a.path, Request{Version: 1, Operation: "rule-save", Generation: a.e.Generation, ID: r.ID, ExpectedVersion: &v, Rule: &candidate}), "protocol_scope_changed")
	}
	stored, err := a.s.Load()
	if err != nil || len(stored) != 2 {
		t.Fatal(stored, err)
	}
	for _, r := range stored {
		if r.Filter.Protocol != "*" {
			t.Fatal(r)
		}
	}
	list := callResponse(a.path, Request{Version: 1, Operation: "list"})
	found := false
	for _, c := range list.Capabilities {
		found = found || c == ObservedAnyProtocolCapability
	}
	if !found {
		t.Fatal("capability absent")
	}
	// A specific protocol with opposite action overlaps a wildcard, without adding
	// specificity precedence or silently deduplicating/replacing either rule.
	x := stored[0].Filter
	y := x
	y.Protocol = "tcp"
	if !filtersOverlap(x, y) {
		t.Fatal("overlap lost")
	}
	rules := []policy.Rule{{ID: "a", Priority: 1, Action: "block", Filter: x}, {ID: "b", Priority: 2, Action: "allow", Filter: y}}
	for i := range rules {
		rules[i].Filter.Process = identity.Instance{}
	}
	f, _ := identity.ParseFlow("tcp", "incoming", "127.0.0.1:80", "127.0.0.2:90")
	action, id, _ := policy.Evaluate(rules, f, identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}}, time.Now())
	if action != "allow" || id != "b" {
		t.Fatal(action, id)
	}
}

func TestWildcardSummaryDoesNotOverstateScope(t *testing.T) {
	a := PolicyIdentity{Key: "a", Revision: "r", UID: 1000}
	now := time.Now()
	r := policy.Rule{Schema: 2, ID: "wide", Action: "allow", Filter: policy.Filter{Application: "a", Revision: "r", UID: 1000, Direction: "incoming", Protocol: "*", RemoteAddress: "*"}}
	s := summaryFor(a, "incoming", "daemon-monitor", nil, []policy.Rule{r}, now)
	if s.Configured != "uniform" || s.Enforcement.Covered {
		t.Fatal(s)
	}
	r.Filter.LocalPort = 8080
	s = summaryFor(a, "incoming", "daemon-monitor", nil, []policy.Rule{r}, now)
	if s.Configured != "scoped" {
		t.Fatal(s)
	}
	other := r
	other.ID = "specific"
	other.Action = "block"
	other.Filter.Protocol = "tcp"
	s = summaryFor(a, "incoming", "daemon-monitor", nil, []policy.Rule{r, other}, now)
	if s.Configured != "mixed" || !s.OverlappingActions {
		t.Fatal(s)
	}
}
