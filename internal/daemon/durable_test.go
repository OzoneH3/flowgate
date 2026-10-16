package daemon

import (
	"flowgate/internal/policy"
	"fmt"
	"strings"
	"testing"
)

func TestPersistenceBeforeVerdict(t *testing.T) {
	e, f, _, _ := fixture()
	e.SaveRules = func([]policy.Rule) error { return fmt.Errorf("disk failure") }
	v := e.Observe(f, "udp")
	if !strings.Contains(v.ScopePreviews["persistent"], "Persistent until") {
		t.Fatal(v.ScopePreviews)
	}
	if _, err := e.Decide(v.ID, "allow", "persistent", 1000, false); err == nil {
		t.Fatal("allowed after storage error")
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "pending" {
		t.Fatal("failed persistence released packet")
	}
	e.SaveRules = func(rs []policy.Rule) error {
		if len(rs) != 1 || !rs[0].Expires.IsZero() {
			t.Fatal(rs)
		}
		return nil
	}
	if _, err := e.Decide(v.ID, "allow", "persistent", 1000, false); err != nil {
		t.Fatal(err)
	}
	r := e.Rules(1000, false)[0]
	if len(e.Rules(1001, false)) != 0 {
		t.Fatal("cross-user rule exposed")
	}
	if err := e.ChangeRule(r.ID, "disable", 1001, false); err == nil {
		t.Fatal("cross-user mutation")
	}
	if err := e.ChangeRule(r.ID, "disable", 1000, false); err != nil {
		t.Fatal(err)
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("stale retained grant survived disable")
	}
}
