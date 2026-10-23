package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

// A program that is not running: a new rule may only reuse the exact identity
// (application key, revision, UID) of one of its existing stored rules.
func TestCreateRuleFromBasis(t *testing.T) {
	e, _, _, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	basis := policy.Rule{Version: 1, Schema: 2, ID: "user:basis", Executable: "/usr/bin/curl", Priority: 100, Action: "allow", Created: *now,
		Filter: policy.Filter{Application: "k-curl", Revision: "r1", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	e.rules = []policy.Rule{basis}
	cand := func(mut func(*policy.Rule)) policy.Rule {
		c := policy.Rule{Schema: 2, Action: "block", Priority: 100, Filter: policy.Filter{Application: "k-curl", Revision: "r1", UID: 1000, Direction: "incoming", Protocol: "*", RemoteAddress: "*"}}
		if mut != nil {
			mut(&c)
		}
		return c
	}
	// Preview stores nothing; save creates a separate rule with the basis identity.
	if _, _, err := e.CreateRuleFromBasis("user:basis", cand(nil), 1000, false, false); err != nil || len(e.rules) != 1 {
		t.Fatalf("preview: %v rules=%d", err, len(e.rules))
	}
	r, _, err := e.CreateRuleFromBasis("user:basis", cand(nil), 1000, false, true)
	if err != nil || len(e.rules) != 2 || r.ID == basis.ID || r.Executable != basis.Executable || r.Filter.Direction != "incoming" || r.Action != "block" || r.Version != 1 {
		t.Fatalf("created: %+v %v", r, err)
	}
	if e.rules[0].Action != "allow" || e.rules[0].Version != 1 {
		t.Fatal("the basis rule must stay unchanged")
	}
	for name, c := range map[string]struct {
		basis string
		rule  policy.Rule
		uid   uint32
		want  string
	}{
		"other application": {"user:basis", cand(func(c *policy.Rule) { c.Filter.Application = "k-other" }), 1000, "identity must match"},
		"other revision":    {"user:basis", cand(func(c *policy.Rule) { c.Filter.Revision = "r2" }), 1000, "identity must match"},
		"other user":        {"user:basis", cand(func(c *policy.Rule) { c.Filter.UID = 1001 }), 1000, "identity must match"},
		"not the owner":     {"user:basis", cand(nil), 1001, "not authorized"},
		"all programs":      {"user:basis", cand(func(c *policy.Rule) { c.Filter.AllPrograms = true }), 1000, "application rule for that identity only"},
		"missing basis":     {"user:gone", cand(nil), 1000, "no longer exists"},
	} {
		if _, _, err := e.CreateRuleFromBasis(c.basis, c.rule, c.uid, false, true); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, err)
		}
	}
	// Process-bound and preset bases are refused.
	proc := basis
	proc.ID, proc.Schema = "user:proc", 3
	proc.Filter.Process = identity.Instance{Session: "s", PID: 7, Start: "1", BootID: "b", NetNS: "n", MountNS: "m", PIDNS: "p", Executable: "/usr/bin/curl", Revision: "r1"}
	preset := basis
	preset.ID, preset.Preset = "preset:x", &policy.Preset{Name: "essential-system-networking", Component: "dns", EntryID: "e", Revision: "v"}
	e.rules = append(e.rules, proc, preset)
	if _, _, err := e.CreateRuleFromBasis("user:proc", cand(nil), 1000, false, true); err == nil || !strings.Contains(err.Error(), "process-bound") {
		t.Errorf("process basis: %v", err)
	}
	if _, _, err := e.CreateRuleFromBasis("preset:x", cand(nil), 1000, false, true); err == nil || !strings.Contains(err.Error(), "preset") {
		t.Errorf("preset basis: %v", err)
	}
	_ = time.Second
}
