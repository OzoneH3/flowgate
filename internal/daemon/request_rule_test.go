package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

func requestRuleFixture(t *testing.T) (*Engine, identity.Flow, *identity.Attribution, *time.Time, Event, *[]policy.Rule) {
	e, f, a, now := fixture()
	e.Timeout = time.Minute
	saved := &[]policy.Rule{}
	e.SaveRules = func(r []policy.Rule) error { *saved = r; return nil }
	e.verifyRetained = func(identity.Application, uint32, string) error { return nil }
	alive := true
	e.instanceRunning = func(int, string) bool { return alive }
	a.Owners[0].PID = 42
	a.VisibilityComplete = true
	v := e.Observe(f, "original")
	if v.State != "awaiting-decision" {
		t.Fatal(v)
	}
	alive = false
	return e, f, a, now, v, saved
}

func appOnly() RememberOptions { return RememberOptions{Fields: &RememberFields{}} }

func TestRequestRuleAfterExitSavesApplicationWideFutureRuleOnly(t *testing.T) {
	e, f, a, now, v, saved := requestRuleFixture(t)
	// The process exits; the request times out unanswered.
	*a = identity.Attribution{Fingerprint: "gone"}
	*now = now.Add(2 * time.Minute)
	// The ended request stays listed for its retained record: ended, never deliverable.
	for _, ev := range e.List(1000, false) {
		if ev.State == "awaiting-decision" || ev.State == "allowed" || ev.RequestRule == nil || !ev.RequestRule.Available {
			t.Fatal("ended request not retained as ended", ev.State, ev.RequestRule)
		}
	}
	p, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	if err != nil {
		t.Fatal(err)
	}
	r := p.Rule.Filter
	if r.Application != "app" || r.Revision != "rev" || r.UID != 1000 || r.Direction != "incoming" || r.Protocol != "*" || r.RemoteAddress != "*" || r.LocalPort != 0 || r.RemotePort != 0 || r.NetworkZone != "" || !r.Process.IsZero() || !p.Rule.Expires.IsZero() {
		t.Fatalf("application-only selection is not application-wide: %+v", r)
	}
	if !strings.Contains(p.ScopePreview, "not allowed") || strings.Contains(strings.ToLower(p.Summary), "allowed") {
		t.Fatal("preview implies the old connection was allowed", p.ScopePreview, p.Summary)
	}
	rule, _, replayed, err := e.SaveRequestRule(e.Generation, p.Token, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	if err != nil || replayed || len(*saved) != 1 || (*saved)[0].ID != rule.ID {
		t.Fatal(err, replayed, *saved)
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("ended request approved retroactively")
	}
	// Lost acknowledgement: the same token returns the same receipt, no second rule.
	again, _, replayed, err := e.SaveRequestRule(e.Generation, p.Token, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	if err != nil || !replayed || again.ID != rule.ID || len(e.rules) != 1 {
		t.Fatal("replay created/changed rules", err, replayed, e.rules)
	}
	// A repeated review of the same scope updates in place; never a duplicate.
	p2, err := e.PreviewRequestRule(e.Generation, v.ID, "block", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	if err != nil || p2.Replaces == nil || p2.Replaces.ID != rule.ID {
		t.Fatal(err, p2.Replaces)
	}
	if _, _, _, err = e.SaveRequestRule(e.Generation, p2.Token, v.ID, "block", "persistent", "any", e.Zones.Revision, 1000, false, appOnly()); err != nil || len(e.rules) != 1 || e.rules[0].Action != "block" || e.rules[0].Version != 2 {
		t.Fatal(err, e.rules)
	}
	// A new launch of the same application (new PID/source port) is decided by the rule.
	*a = identity.Attribution{Application: &identity.Application{Key: "app", Revision: "rev"}, Owners: []identity.Process{{UID: 1000, PID: 77, Start: "99"}}, Fingerprint: "new-launch"}
	if n := e.Observe(f, "relaunch"); n.State != "blocked" || n.Rule != rule.ID {
		t.Fatal("future launch not governed by saved rule", n)
	}
	// A different executable does not inherit it.
	*a = identity.Attribution{Application: &identity.Application{Key: "other", Revision: "rev"}, Owners: []identity.Process{{UID: 1000, PID: 78, Start: "100"}}, Fingerprint: "other"}
	if n := e.Observe(f, "other"); n.State != "awaiting-decision" {
		t.Fatal("different executable inherited the rule", n)
	}
}

func TestRequestRuleExplicitPropertiesAndAsk(t *testing.T) {
	e, _, a, _, v, _ := requestRuleFixture(t)
	*a = identity.Attribution{Fingerprint: "exited"}
	o := RememberOptions{Fields: &RememberFields{Protocol: true, Port: true}, DurationSeconds: 300}
	p, err := e.PreviewRequestRule(e.Generation, v.ID, "ask", "application", "any", e.Zones.Revision, 1000, false, o)
	if err != nil {
		t.Fatal(err)
	}
	if f := p.Rule.Filter; f.Protocol != "udp" || f.LocalPort != 80 || f.RemoteAddress != "*" || p.Rule.Action != "ask" || p.DurationSeconds != 300 {
		t.Fatalf("explicit selections not kept: %+v", p.Rule)
	}
	if !strings.HasPrefix(p.Summary, "Ask ") {
		t.Fatal(p.Summary)
	}
	if _, _, _, err = e.SaveRequestRule(e.Generation, p.Token, v.ID, "ask", "application", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{Protocol: true}, DurationSeconds: 300}); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Fatal("changed draft saved", err)
	}
}

func TestRequestRulePendingLiveRequestUsesRemember(t *testing.T) {
	e, _, _, _, v, _ := requestRuleFixture(t)
	if _, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly()); err == nil || !strings.Contains(err.Error(), "still pending") {
		t.Fatal(err)
	}
}

func TestRequestRuleEndsDeadBindingFirstAndKeepsDraftOnRefusal(t *testing.T) {
	e, _, a, _, v, _ := requestRuleFixture(t)
	*a = identity.Attribution{Fingerprint: "exited"}
	if _, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{Process: true}}); err == nil || !strings.Contains(err.Error(), "process instance has ended") {
		t.Fatal("process scope silently changed", err)
	}
	if len(e.rules) != 0 {
		t.Fatal("rule saved")
	}
	e.verifyRetained = func(identity.Application, uint32, string) error {
		return errors.New("a different file now occupies /usr/bin/x (device/inode changed)")
	}
	_, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	var typed *RuleMutationError
	if !errors.As(err, &typed) || typed.Code != "executable_changed" || !strings.Contains(err.Error(), "device/inode changed") {
		t.Fatal(err)
	}
	listed := e.List(1000, false)
	if len(listed) != 1 || listed[0].State != "expired" || listed[0].RequestRule == nil || listed[0].RequestRule.ProcessState != "ended" {
		t.Fatal("ended request/retained identity not reported", listed)
	}
	e.verifyRetained = func(identity.Application, uint32, string) error { return nil }
	if _, err = e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1001, false, appOnly()); err == nil {
		t.Fatal("other principal used retained identity")
	}
	if _, err = e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestRuleRetentionIsBounded(t *testing.T) {
	e, _, _, now, v, _ := requestRuleFixture(t)
	*now = now.Add(time.Minute + requestRuleRetention)
	if _, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly()); err == nil || !strings.Contains(err.Error(), "no longer retained") {
		t.Fatal(err)
	}
}

func TestUnresolvedRuntimeCannotSaveFutureApplicationRule(t *testing.T) {
	e, f, a, now := fixture()
	e.SaveRules = func([]policy.Rule) error { t.Fatal("unresolved identity saved"); return nil }
	a.Application.Hosted = &identity.Hosted{State: "best-effort", Runtime: "/synthetic/electron", Bundle: "/synthetic/app.asar"}
	a.Application.Kind = "electron" // client-shaped claim has no private resolver receipt
	v := e.Observe(f, "unresolved")
	*now = now.Add(2 * time.Minute)
	_, err := e.PreviewRequestRule(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, appOnly())
	if code(err) != identity.CodeIdentityUnverifiable || !strings.Contains(err.Error(), "No application was successfully matched") {
		t.Fatal(err)
	}
	if len(e.rules) != 0 {
		t.Fatal("unresolved claim granted permission")
	}
}
