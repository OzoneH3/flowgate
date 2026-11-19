package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestSavedApplicationRulesFollowUpdatesWithoutChangingScope(t *testing.T) {
	now := time.Now()
	app := identity.Application{Kind: "native", Executable: "/opt/program/native", Revision: "old"}
	app.Key = identity.ApplicationKey(1000, app)
	r := Rule{ID: "saved", Schema: 2, Executable: app.Executable, Created: now, Action: "allow", Filter: Filter{Application: app.Key, Revision: "old", UID: 1000, Direction: "outgoing", Protocol: "tcp", RemoteAddress: "192.0.2.1", RemotePort: 443}}
	f, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:10000", "192.0.2.1:443")
	app.Revision = "new"
	evaluate := func(rule Rule, flow identity.Flow, a identity.Application, uid uint32) string {
		a.Key = identity.ApplicationKey(uid, a)
		action, _, _ := Evaluate([]Rule{rule}, flow, identity.Attribution{Application: &a, Owners: []identity.Process{{UID: uid}}}, now)
		return action
	}
	for _, action := range []string{"allow", "block", "ask"} {
		r.Action = action
		if got := evaluate(r, f, app, 1000); got != action {
			t.Fatal("updated program lost saved action", action, got)
		}
	}
	r.Action = "allow"
	if got := evaluate(r, f, app, 1001); got != "ask" {
		t.Fatal("different user inherited permission", got)
	}
	other := app
	other.Executable = "/other/program/native"
	if got := evaluate(r, f, other, 1000); got != "ask" {
		t.Fatal("different executable inherited permission", got)
	}
	forged := other
	forged.Key = app.Key
	if r.MatchesApplication(app.Key, forged.Revision, 1000, forged) {
		t.Fatal("display path substituted for current identity")
	}
	incoming := f
	incoming.Direction = "incoming"
	if got := evaluate(r, incoming, app, 1000); got != "ask" {
		t.Fatal("direction broadened", got)
	}
	remote, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:10000", "192.0.2.2:443")
	if got := evaluate(r, remote, app, 1000); got != "ask" {
		t.Fatal("address scope broadened", got)
	}
	port, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:10000", "192.0.2.1:8443")
	if got := evaluate(r, port, app, 1000); got != "ask" {
		t.Fatal("port scope broadened", got)
	}
	disabled := r
	disabled.Disabled = true
	if evaluate(disabled, f, app, 1000) != "ask" {
		t.Fatal("disabled rule revived")
	}
	expired := r
	expired.Expires = now.Add(-time.Second)
	if evaluate(expired, f, app, 1000) != "ask" {
		t.Fatal("expired rule revived")
	}
	missing := app
	missing.Revision = ""
	if evaluate(r, f, missing, 1000) != "block" {
		t.Fatal("missing executable evidence allowed")
	}
	pinned := r
	pinned.Filter.Process = identity.Instance{ID: "process"}
	if pinned.FollowsUpdates() || pinned.MatchesApplication(app.Key, "new", 1000) {
		t.Fatal("process grant inherited update")
	}
	preset := r
	preset.Preset = &Preset{}
	if preset.FollowsUpdates() || preset.MatchesApplication(app.Key, "new", 1000) {
		t.Fatal("preset inherited update")
	}
	legacy := r
	legacy.Executable = ""
	if legacy.FollowsUpdates() || legacy.MatchesApplication(app.Key, "new", 1000) {
		t.Fatal("unbound legacy identity inherited update")
	}
}

func TestWineSavedUpdatesKeepApplicationsAndPrefixesIndependent(t *testing.T) {
	now := time.Now()
	f, _ := identity.ParseFlow("udp", "outgoing", "127.0.0.1:10000", "192.0.2.1:443")
	alpha := identity.Application{Kind: "wine", Prefix: "/prefix-a", Executable: "/games/alpha.exe", Revision: "old"}
	alpha.Key = identity.ApplicationKey(1000, alpha)
	rule := Rule{ID: "alpha", Schema: 2, Executable: alpha.Executable, Created: now, Action: "allow", Filter: Filter{Application: alpha.Key, Revision: "old", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	for _, exe := range []string{"/games/alpha.exe", "/games/beta.exe"} {
		for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
			app := identity.Application{Kind: "wine", Prefix: prefix, Executable: exe, Revision: "updated"}
			app.Key = identity.ApplicationKey(1000, app)
			got, _, _ := Evaluate([]Rule{rule}, f, identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}, now)
			want := "ask"
			if exe == alpha.Executable && prefix == alpha.Prefix {
				want = "allow"
			}
			if got != want {
				t.Fatal("application/prefix update scope", exe, prefix, got, want)
			}
		}
	}
}

func TestNewestProgramChoiceDoesNotReviveOlderPermissions(t *testing.T) {
	now := time.Now()
	app := identity.Application{Kind: "native", Executable: "/opt/program/native", Revision: "current"}
	app.Key = identity.ApplicationKey(1000, app)
	f, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:10000", "192.0.2.1:443")
	old := Rule{ID: "old", Executable: app.Executable, Created: now.Add(-time.Hour), Priority: 999, Action: "allow", Filter: Filter{Application: app.Key, Revision: "v1", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	newest := old
	newest.ID = "new"
	newest.Created = now
	newest.Priority = 1
	newest.Action = "block"
	newest.Filter.Revision = "v2"
	evaluate := func(r Rule) string {
		action, _, _ := Evaluate([]Rule{old, r}, f, identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}, now)
		return action
	}
	if evaluate(newest) != "block" {
		t.Fatal("stale higher priority allow won")
	}
	old.Action = "block"
	newest.Action = "allow"
	if evaluate(newest) != "allow" {
		t.Fatal("stale block won")
	}
	newest.Disabled = true
	if evaluate(newest) != "ask" {
		t.Fatal("disabled latest choice revived old rule")
	}
	newest.Disabled = false
	newest.Expires = now.Add(-time.Second)
	if evaluate(newest) != "block" {
		t.Fatal("expired temporary setting did not restore persistent rule")
	}
	other := newest
	other.Filter.RemotePort = 8443
	if len(LatestProgramRules([]Rule{old, other})) != 2 {
		t.Fatal("different scope removed")
	}
	other = old
	other.ID = "tied"
	other.Action = "allow"
	if len(LatestProgramRules([]Rule{old, other})) != 2 {
		t.Fatal("guessed timestamp tie")
	}
}

func TestRuntimeUpdateWitnessMustBeValidAndExact(t *testing.T) {
	for _, kind := range []string{"wine", "electron"} {
		app := identity.Application{Kind: kind, Executable: "/games/alpha", Prefix: "/prefix-a", Revision: "new"}
		if kind == "electron" {
			app.Hosted = &identity.Hosted{State: "verified", Bundle: "/games/alpha"}
		}
		app.Key = identity.ApplicationKey(1000, app)
		r := Rule{Executable: app.Executable, Filter: Filter{Application: app.Key, Revision: "old", UID: 1000}}
		if got := r.MatchesApplication(app.Key, "new", 1000, app); got != (kind == "wine") {
			t.Fatal("runtime update authority", kind, got)
		}
		bad := app
		if kind == "wine" {
			bad.Prefix = "relative"
		} else {
			bad.Hosted = &identity.Hosted{State: "unverified"}
		}
		if r.MatchesApplication(app.Key, "new", 1000, bad) {
			t.Fatal("invalid runtime accepted", kind)
		}
		other := app
		other.Executable = "/games/beta"
		other.Key = identity.ApplicationKey(1000, other)
		if r.MatchesApplication(other.Key, "new", 1000, other) {
			t.Fatal("other runtime inherited", kind)
		}
	}
}

func TestDisabledRememberedChoiceRestoresOnlyItsApplicationAsk(t *testing.T) {
	now := time.Now()
	ask := Rule{ID: "user:ask", Schema: 2, Executable: "/fixture/program", Action: "ask",
		Created: now.Add(-time.Minute), Filter: Filter{Direction: "outgoing", Protocol: "*",
			RemoteAddress: "*", Application: "app", Revision: "rev", UID: 1000}}
	block := ask
	block.ID, block.Action, block.Created, block.Disabled = RememberAskPrefix(ask.ID)+"choice", "block", now, true
	for _, tc := range []struct {
		name   string
		change func(*Rule, *Rule) []Rule
		want   bool
	}{
		{"disabled permanent", nil, true},
		{"enabled permanent", func(_, b *Rule) []Rule { b.Disabled = false; return nil }, false},
		{"disabled timed Block", func(_, b *Rule) []Rule { b.Expires = now.Add(time.Minute); return nil }, true},
		{"ordinary disabled", func(_, b *Rule) []Rule { b.ID = "user:direct"; return nil }, false},
		{"disabled permanent Allow", func(_, b *Rule) []Rule { b.Action = "allow"; return nil }, true},
		{"enabled permanent Allow", func(_, b *Rule) []Rule { b.Action, b.Disabled = "allow", false; return nil }, false},
		{"disabled timed Allow", func(_, b *Rule) []Rule { b.Action, b.Expires = "allow", now.Add(time.Minute); return nil }, true},
		{"ordinary disabled timed", func(_, b *Rule) []Rule { b.ID, b.Expires = "user:direct-timed", now.Add(time.Minute); return nil }, false},
		{"unbound Ask", func(a, _ *Rule) []Rule { a.ID = "user:other-ask"; return nil }, false},
		{"disabled Ask", func(a, _ *Rule) []Rule { a.Disabled = true; return nil }, false},
		{"expired Ask", func(a, _ *Rule) []Rule { a.Expires = now; return nil }, false},
		{"scoped Remember", func(a, b *Rule) []Rule {
			a.Filter.RemotePort, b.Filter.RemotePort = 443, 443
			return nil
		}, false},
		{"intervening ordinary mask", func(a, _ *Rule) []Rule {
			intervening := *a
			intervening.ID, intervening.Created, intervening.Disabled = "user:ordinary", now.Add(-time.Second), true
			return []Rule{intervening}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := ask, block
			rules := []Rule{a, b}
			if tc.change != nil {
				extra := tc.change(&a, &b)
				rules = append([]Rule{a, b}, extra...)
			}
			for _, ordered := range [][]Rule{rules, append([]Rule{b, a}, rules[2:]...)} {
				configured := CurrentProgramRules(ordered, now)
				if len(configured) != 1 || configured[0].ID != b.ID {
					t.Fatalf("canonical edit target changed: %+v", configured)
				}
				effective := EffectiveProgramRules(ordered, now)
				if tc.want {
					if len(effective) != 2 || effective[0].ID != a.ID || effective[1].ID != b.ID {
						t.Fatalf("expected retained Ask followed by its disabled choice: %+v", effective)
					}
				} else if len(effective) != 1 || effective[0].ID != b.ID {
					t.Fatalf("unexpected active fallback: %+v", effective)
				}
			}
		})
	}
}
