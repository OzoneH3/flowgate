package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
)

func TestRuleInvocationIsHistoricalDisplayOnly(t *testing.T) {
	e, f, a, _ := fixture()
	a.Application.Kind = "native"
	a.Owners[0].Provenance = &identity.Provenance{Invocation: &identity.Invocation{Mode: "file", Name: "alpha.py", Path: "/scripts/alpha.py", Revision: "script-a"}}
	v := e.Observe(f, "udp")
	_, err := e.Decide(v.ID, "allow", "application", 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	rules := e.Rules(1000, false)
	if len(rules) != 1 || rules[0].Invocation == nil || rules[0].Invocation.Name != "alpha.py" {
		t.Fatalf("missing script display: %+v", rules)
	}
	if rules[0].Filter.Application != a.Application.Key {
		t.Fatal("script replaced permission identity")
	}
	raw, err := json.Marshal(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	var stored policy.Rule
	if err = json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Invocation.Path != "/scripts/alpha.py" {
		t.Fatal("display context not retained")
	}
	a.Owners[0].Provenance.Invocation.Name = "beta.py"
	if stored.Invocation.Name != "alpha.py" || rules[0].Invocation.Name != "alpha.py" {
		t.Fatal("stored context shares mutable owner data")
	}
	if ruleInvocation(*a.Application, &identity.Provenance{Invocation: &identity.Invocation{Mode: "unverified-file", Name: "beta.py"}}) != nil {
		t.Fatal("unverified argument used for label")
	}
}
