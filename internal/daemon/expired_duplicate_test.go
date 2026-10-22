package daemon

import (
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestRememberAfterExpiredRuleWithoutRestart(t *testing.T) {
	for _, reviewed := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "reviewed"}[reviewed], func(t *testing.T) {
			e, f, a, now := fixture()
			e.SaveRules = func([]policy.Rule) error { return nil }
			first := e.Observe(f, "first")
			if _, err := e.Decide(first.ID, "allow", "application", 1000, false); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(time.Hour)
			a.Fingerprint = "new-socket"
			next := e.Observe(f, "second")
			if next.State != "awaiting-decision" {
				t.Fatal(next)
			}
			if reviewed {
				preview, err := e.PreviewDecision(e.Generation, next.ID, "allow", "application", "any", e.Zones.Revision, 1000, false)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err = e.DecideReviewed(e.Generation, next.ID, "allow", "application", "any", e.Zones.Revision, preview.Token, 1000, false); err != nil {
					t.Fatal(err)
				}
			} else if _, err := e.Decide(next.ID, "allow", "application", 1000, false); err != nil {
				t.Fatal(err)
			}
			if got := e.Observe(f, "second"); got.State != "allowed" {
				t.Fatal(got)
			}
			rules := e.Rules(1000, false)
			active := 0
			for _, r := range rules {
				if r.Expires.After(*now) {
					active++
				}
			}
			if active != 1 {
				t.Fatal("expected one renewed permission", rules)
			}
		})
	}
}

func TestExpiredDuplicateDoesNotHideLiveFallback(t *testing.T) {
	now := time.Now()
	old := policy.Rule{ID: "persistent", Executable: "/opt/tool", Created: now.Add(-time.Hour), Filter: policy.Filter{Application: "key", Revision: "v1", UID: 1000, Direction: "incoming", Protocol: "tcp"}}
	expired := old
	expired.ID = "expired"
	expired.Created = now
	expired.Expires = now
	candidate := old
	candidate.ID = "candidate"
	if got := duplicate([]policy.Rule{old, expired}, candidate, now); got != old.ID {
		t.Fatal("expired override hid live duplicate", got)
	}
}

func TestDuplicateExpiryBoundaryAndDisabledProtection(t *testing.T) {
	now := time.Now()
	candidate := policy.Rule{ID: "candidate", Filter: policy.Filter{Application: "app", Revision: "old", UID: 1000, Direction: "incoming", Protocol: "tcp"}}
	for _, disabled := range []bool{false, true} {
		old := candidate
		old.ID = "old"
		old.Disabled = disabled
		for _, expiry := range []time.Time{time.Time{}, now.Add(time.Nanosecond), now, now.Add(-time.Nanosecond)} {
			old.Expires = expiry
			got := duplicate([]policy.Rule{old}, candidate, now)
			want := expiry.IsZero() || now.Before(expiry)
			if (got != "") != want {
				t.Fatalf("expiry=%v disabled=%v got=%q", expiry, disabled, got)
			}
		}
	}
}

func TestEditorCreatesScopeAlongsideExpiredRule(t *testing.T) {
	e, f, a, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "initial")
	draft := policy.Rule{Priority: 100, Action: "block", Filter: *v.RememberedFilter, Expires: now.Add(time.Hour)}
	old, _, err := e.EditRule("", v.ID, nil, draft, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	*now = old.Expires
	a.Fingerprint = "replacement"
	v = e.Observe(f, "replacement")
	draft.Action = "allow"
	draft.Expires = now.Add(time.Hour)
	saved, _, err := e.EditRule("", v.ID, nil, draft, 1000, false, true)
	if err != nil {
		t.Fatal(err)
	}
	rules := e.Rules(1000, false)
	if len(rules) != 2 {
		t.Fatal("expected exact expired history retained", rules)
	}
	action, id, matching := policy.Evaluate(rules, f, *a, *now)
	if action != "allow" || id != saved.ID || len(matching) != 1 {
		t.Fatal("expired block matched", action, id, matching)
	}
}

func TestObservedRuleCreatesScopeAlongsideExpiredRule(t *testing.T) {
	a, p, _, now := processAPI(t)
	old := policy.Rule{ID: "expired", Version: 1, Schema: 2, Created: now.Add(-time.Hour), Executable: p.Application.Executable, Action: "block", Expires: *now, Filter: policy.Filter{Application: p.Application.Key, Revision: p.Application.Revision, UID: p.UID, Direction: "incoming", Protocol: "udp", RemoteAddress: "127.0.0.2"}}
	if err := a.e.SetRules([]policy.Rule{old}); err != nil {
		t.Fatal(err)
	}
	d := observedDraft("incoming")
	d.Action = "allow"
	preview := processPreview(t, a, p, d)
	saved := callResponse(a.path, saveRequest(a, preview, d))
	if saved.Error != "" || saved.SavedRule == nil {
		t.Fatal(saved)
	}
	rules := a.e.Rules(p.UID, true)
	if len(rules) != 2 {
		t.Fatal("expired history removed unexpectedly", rules)
	}
}
