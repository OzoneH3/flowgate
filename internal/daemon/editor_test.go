package daemon

import (
	"flowgate/internal/policy"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEditorAtomicVersionAndIdentity(t *testing.T) {
	e, f, _, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	r := policy.Rule{Priority: 100, Action: "allow", Filter: *v.RememberedFilter, Expires: now.Add(time.Hour)}
	saved, _, err := e.EditRule("", v.ID, nil, r, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "allow" {
		t.Fatal("editor did not release selected held packet")
	}
	oldVersion := saved.Version
	changed := saved
	changed.Action = "block"
	e.SaveRules = func([]policy.Rule) error { return fmt.Errorf("disk failed") }
	if _, _, err = e.EditRule(saved.ID, "", &oldVersion, changed, 1000, false, true); err == nil {
		t.Fatal("failed storage accepted")
	}
	if e.Rules(1000, false)[0].Action != "allow" {
		t.Fatal("failed transaction published")
	}
	e.SaveRules = func([]policy.Rule) error { return nil }
	next, _, err := e.EditRule(saved.ID, "", &oldVersion, changed, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.EditRule(saved.ID, "", &oldVersion, saved, 1000, false, true); err == nil {
		t.Fatal("stale overwrite")
	}
	v2 := next.Version
	forged := next
	forged.Filter.Direction = "outgoing"
	if _, _, err = e.EditRule(next.ID, "", &v2, forged, 1000, false, true); err == nil {
		t.Fatal("identity/direction widened")
	}
	if _, _, err = e.EditRule(next.ID, "", &v2, next, 1001, false, true); err == nil {
		t.Fatal("cross-user edit")
	}

}
func TestEditorOverlapAndDuplicate(t *testing.T) {
	e, f, _, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	broad := policy.Rule{Priority: 90, Action: "allow", Filter: *v.RememberedFilter, Expires: now.Add(time.Hour)}
	broad.Filter.RemoteAddress = "127.0.0.0/8"
	r, _, err := e.EditRule("", v.ID, nil, broad, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	// Force Ask solely for creation fixture; resolve remains the same current owner.
	e.mu.Lock()
	e.rules[0].Disabled = true
	e.mu.Unlock()
	v = e.Observe(f, "new")
	exact := policy.Rule{Priority: 100, Action: "block", Filter: *v.RememberedFilter}
	exactRule, _, err := e.EditRule("", v.ID, nil, exact, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	e.ChangeRule(r.ID, "enable", 1000, false)
	a, _, _ := policy.Evaluate(e.Rules(1000, false), f, e.Resolve(f), *now)
	if a != "block" {
		t.Fatal("priority changed")
	}
	version := exactRule.Version
	preview := exactRule
	preview.Priority = 90
	_, sentence, err := e.EditRule(exactRule.ID, "", &version, preview, 1000, false, false)
	if err != nil || !strings.Contains(sentence, "Overlap:") {
		t.Fatal(sentence, err)
	}
	// Duplicate semantic host-prefix scope is identified rather than creating two.
	e.mu.Lock()
	e.rules = nil
	e.events = map[string]*Event{}
	e.mu.Unlock()
	v = e.Observe(f, "fresh")
	same := exact
	same.Filter.RemoteAddress = "127.0.0.1/32"
	if _, _, err = e.EditRule("", v.ID, nil, same, 1000, false, true); err != nil {
		t.Fatal(err)
	}
	if duplicate(e.Rules(1000, false), policy.Rule{Filter: exact.Filter}, *now) == "" {
		t.Fatal("duplicate missed")
	}
}

func TestEditorExpiredRuleStaysExpired(t *testing.T) {
	e, f, _, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	r := policy.Rule{Priority: 100, Action: "allow", Filter: *v.RememberedFilter, Expires: now.Add(time.Minute)}
	saved, _, err := e.EditRule("", v.ID, nil, r, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	oldExpiry := saved.Expires
	saved.Action = "block"
	version := saved.Version
	next, _, err := e.EditRule(saved.ID, "", &version, saved, 1000, false, true)
	if err != nil || !next.Expires.Equal(oldExpiry) {
		t.Fatal("expired edit changed expiry", err)
	}
	if err := e.ChangeRule(next.ID, "enable", 1000, false); err != nil {
		t.Fatal(err)
	}
	action, _, _ := policy.Evaluate(e.Rules(1000, false), f, e.Resolve(f), *now)
	if action != "ask" {
		t.Fatal("expired rule revived", action)
	}
}
