package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func rememberStorageFixture(t *testing.T, askID string) (*Engine, identity.Flow, policy.Rule, *time.Time, *store.Store) {
	t.Helper()
	e, flow, a, now := fixture()
	a.Application.Executable = "/fixture/program"
	a.Application.Kind = "native"
	a.Application.Key = identity.ApplicationKey(1000, *a.Application)
	db, err := store.OpenExclusive(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e.SaveRules = db.Replace
	return e, flow, policy.Rule{Schema: 2, ID: askID, Version: 3, Priority: 135,
		Action: "ask", Created: now.Add(-time.Hour), Executable: a.Application.KeyPath(),
		Filter: policy.Filter{Application: a.Application.Key, Revision: a.Application.Revision, UID: 1000,
			Direction: "incoming", Protocol: "*", RemoteAddress: "*"}}, now, db
}

func TestPersistentRememberAfterExpiredOverlay(t *testing.T) {
	for _, action := range []string{"allow", "block"} {
		for _, askFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ask-first=%t", action, askFirst), func(t *testing.T) {
				id := "user:z-ask"
				if askFirst {
					id = "user:a-ask"
				}
				e, flow, ask, now, db := rememberStorageFixture(t, id)
				expired := ask
				expired.ID, expired.Action = "user:m-expired", "block"
				expired.Created, expired.Expires = now.Add(-time.Minute), now.Add(-time.Second)
				if err := db.Replace([]policy.Rule{ask, expired}); err != nil {
					t.Fatal(err)
				}
				rules, err := db.Load()
				if err != nil || len(rules) != 2 || (rules[0].ID == ask.ID) != askFirst {
					t.Fatalf("wrong order: %+v %v", rules, err)
				}
				if err := e.SetRules(rules); err != nil {
					t.Fatal(err)
				}
				v := e.Observe(flow, "udp")
				if v.AskRule == nil || v.AskRule.ID != ask.ID {
					t.Fatalf("wrong rule opened the prompt: %+v", v.AskRule)
				}
				options := RememberOptions{Fields: &RememberFields{}}
				preview, err := e.PreviewDecision(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, 1000, false, options)
				if err != nil || preview.Replaces != nil || preview.Rule.ID == ask.ID || !preview.Rule.Expires.IsZero() {
					t.Fatalf("wrong reviewed choice: %+v %v", preview, err)
				}
				// Simulate a concurrent version change without replacing the pending request.
				e.mu.Lock()
				for i := range e.rules {
					if e.rules[i].ID == ask.ID {
						e.rules[i].Version++
					}
				}
				e.mu.Unlock()
				if _, _, _, err := e.DecideReviewed(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, preview.Token, 1000, false, options); err == nil {
					t.Fatal("stale preview saved")
				}
				preview, err = e.PreviewDecision(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, 1000, false, options)
				if err != nil || preview.Replaces != nil || preview.Rule.ID == ask.ID {
					t.Fatalf("wrong refreshed target: %+v %v", preview.Replaces, err)
				}
				_, saved, _, err := e.DecideReviewed(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, preview.Token, 1000, false, options)
				if err != nil || saved.ID != preview.Rule.ID || saved.Action != action || saved.Version != 1 || saved.ProgramScope() != ask.ProgramScope() {
					t.Fatalf("wrong save: %+v %v", saved, err)
				}
				// Authoritative startup cleanup must keep the Ask and its separate choice.
				rules, err = db.LoadCurrent(*now)
				if err != nil {
					t.Fatal(err)
				}
				if err := e.SetRules(rules); err != nil {
					t.Fatal(err)
				}
				ask.Version++ // The intervening edit is the only Ask version change.
				if got := e.ruleLocked(ask.ID); got == nil || *got != ask {
					t.Fatalf("changed original Ask: %+v", got)
				}
				if got := e.ruleLocked(saved.ID); got == nil || *got != saved {
					t.Fatalf("lost remembered choice: %+v", got)
				}
				next, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9100")
				got := e.Observe(next, "udp")
				want := map[string]string{"allow": "allowed", "block": "blocked"}[action]
				if got.State != want || got.Rule != saved.ID {
					t.Fatalf("fresh attempt got %s/%s, want %s/%s", got.State, got.Rule, want, saved.ID)
				}
				t.Logf("prompt %s; preview and saved %s; next %s", v.AskRule.ID, saved.ID, got.State)
				disabled := saved
				disabled.Disabled = true
				edit, _, err := e.EditRule(saved.ID, "", &saved.Version, disabled, 1000, false, true)
				if err != nil || edit.ID != saved.ID || edit.Version != saved.Version+1 {
					t.Fatalf("direct disable must update selected rule in place: %+v %v", edit, err)
				}
				fallback, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9101")
				got = e.Observe(fallback, "udp")
				wantSource := "default-ask"
				if action == "block" {
					wantSource = ask.ID
				}
				if got.State != "awaiting-decision" || got.Rule != wantSource {
					t.Fatalf("disabled choice prompted from %s, want %s: %+v", got.Rule, wantSource, got)
				}
				if _, err := e.DeleteRule(e.Generation, edit.ID, &edit.Version, 1000, false); err != nil {
					t.Fatal(err)
				}
				restored, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9102")
				if got := e.Observe(restored, "udp"); got.State != "awaiting-decision" || got.AskRule == nil || got.AskRule.ID != ask.ID {
					t.Fatalf("delete did not restore original Ask: %+v", got)
				}
			})
		}
	}
}

func TestRepeatedTemporaryRememberReusesOneSlotAcrossReloads(t *testing.T) {
	e, flow, ask, now, db := rememberStorageFixture(t, "user:z-ask")
	ordinary := ask
	ordinary.ID, ordinary.Action = "user:ordinary-expired", "block"
	ordinary.Created, ordinary.Expires = now.Add(-time.Minute), now.Add(-time.Second)
	seeds := []policy.Rule{ask, ordinary}
	for i := 0; len(seeds) < 255; i++ {
		r := ordinary
		r.ID, r.Filter.RemotePort = fmt.Sprintf("unrelated-%03d", i), uint16(10000+i)
		seeds = append(seeds, r)
	}
	if err := db.Replace(seeds); err != nil {
		t.Fatal(err)
	}
	options := RememberOptions{Fields: &RememberFields{}, DurationSeconds: 60}
	var id string
	for i, action := range []string{"allow", "block", "allow", "block"} {
		rules, err := db.Load()
		wantCount := 256
		if i == 0 {
			wantCount = 255
		}
		if err != nil || len(rules) != wantCount {
			t.Fatalf("cycle %d before: %d %v", i, len(rules), err)
		}
		if err := e.SetRules(rules); err != nil {
			t.Fatal(err)
		}
		v := e.Observe(flow, "udp")
		if v.AskRule == nil || v.AskRule.ID != ask.ID {
			t.Fatalf("cycle %d lost Ask: %+v", i, v)
		}
		p, err := e.PreviewDecision(e.Generation, v.ID, action, "application", "any", e.Zones.Revision, 1000, false, options)
		if err != nil || p.Rule.ID == ordinary.ID {
			t.Fatalf("preview: %+v %v", p, err)
		}
		_, saved, _, err := e.DecideReviewed(e.Generation, v.ID, action, "application", "any", e.Zones.Revision, p.Token, 1000, false, options)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			id = saved.ID
		}
		if saved.ID != id || saved.Version != uint64(i+1) {
			t.Fatalf("changed overlay slot: %+v", saved)
		}
		if got := e.ruleLocked(ask.ID); got == nil || *got != ask {
			t.Fatalf("changed original Ask: %+v", got)
		}
		if got := e.ruleLocked(ordinary.ID); got == nil || *got != ordinary {
			t.Fatalf("changed unmarked expired exact-scope rule: %+v", got)
		}
		for _, seed := range seeds[2:] {
			if got := e.ruleLocked(seed.ID); got == nil || *got != seed {
				t.Fatalf("changed unrelated expired rule: %+v", got)
			}
		}
		if n := len(e.Rules(1000, false)); n != 256 {
			t.Fatalf("rule count %d", n)
		}
		next, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9100")
		outcome := e.Observe(next, "udp")
		if outcome.Rule != id || outcome.State != map[string]string{"allow": "allowed", "block": "blocked"}[action] {
			t.Fatalf("wrong fresh decision: %+v", outcome)
		}
		t.Logf("cycle %d %s, reload %d rules, source %s, slot %s v%d, saved 256 rules, next %s", i+1, action, wantCount, v.AskRule.ID, id, saved.Version, outcome.State)
		*now = saved.Expires
	}
	v := e.Observe(flow, "udp")
	permanent := RememberOptions{Fields: &RememberFields{}}
	for _, action := range []string{"allow", "block"} {
		p, err := e.PreviewDecision(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, 1000, false, permanent)
		if err != nil || p.Replaces != nil || p.Rule.ID == ask.ID {
			t.Fatalf("permanent Remember should preview a distinct choice: %+v %v", p, err)
		}
		_, _, _, err = e.DecideReviewed(e.Generation, v.ID, action, "persistent", "any", e.Zones.Revision, p.Token, 1000, false, permanent)
		var refusal *RuleMutationError
		if !errors.As(err, &refusal) || refusal.Code != "capacity" || len(e.Rules(1000, false)) != 256 {
			t.Fatalf("permanent Remember must still respect capacity: %v", err)
		}
		if got := e.ruleLocked(ask.ID); got == nil || *got != ask {
			t.Fatalf("refusal changed the original Ask: %+v", got)
		}
	}
}
