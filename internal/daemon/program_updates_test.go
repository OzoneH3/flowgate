package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
)

func TestApplicationPolicyUpdatesExistingProgramScopeAcrossRevision(t *testing.T) {
	a, p, _, clock := processAPI(t)
	old := policy.Rule{Schema: 2, ID: "saved-program", Version: 3, Created: *clock, Executable: p.Application.Executable, Action: "allow", Priority: 100, Filter: policy.Filter{Application: p.Application.Key, Revision: "previous-version", UID: p.UID, Direction: "incoming", Protocol: "*", RemoteAddress: "*"}}
	if err := a.e.SetRules([]policy.Rule{old}); err != nil {
		t.Fatal(err)
	}
	d := observedDraft("incoming")
	d.TargetScope = "application"
	d.Protocol = "*"
	d.RemoteAddress = "*"
	d.ApplicationPolicy = true
	d.Action = "block"
	preview := processPreview(t, a, p, d)
	if preview.Replaces == nil || preview.Replaces.ID != old.ID || preview.Rule.Version != 4 {
		t.Fatal("update created a second version scope", preview)
	}
	saved := callResponse(a.path, saveRequest(a, preview, d))
	if saved.Error != "" || saved.SavedRule == nil || saved.SavedRule.ID != old.ID {
		t.Fatal(saved)
	}
	rules := a.e.Rules(p.UID, true)
	if len(rules) != 1 || rules[0].Action != "block" || rules[0].Filter.Revision != p.Application.Revision {
		t.Fatal("program setting not updated in place", rules)
	}
}

func TestDaemonWineUpdatesKeepTwoAppsAndPrefixesIndependent(t *testing.T) {
	for _, exe := range []string{"/games/alpha.exe", "/games/beta.exe"} {
		for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
			e, f, a, _ := fixture()
			saved := identity.Application{Kind: "wine", Prefix: "/prefix-a", Executable: "/games/alpha.exe", Revision: "old"}
			saved.Key = identity.ApplicationKey(1000, saved)
			r := policy.Rule{Schema: 2, ID: "saved", Executable: saved.Executable, Action: "allow", Filter: policy.Filter{Application: saved.Key, Revision: "old", UID: 1000, Direction: f.Direction, Protocol: "*"}}
			if err := e.SetRules([]policy.Rule{r}); err != nil {
				t.Fatal(err)
			}
			current := saved
			current.Executable = exe
			current.Prefix = prefix
			current.Revision = "new"
			current.Key = identity.ApplicationKey(1000, current)
			a.Application = &current
			event := e.ObserveResolved(f, "udp", *a)
			want := "awaiting-decision"
			if exe == saved.Executable && prefix == saved.Prefix {
				want = "allowed"
			}
			if event.State != want {
				t.Fatal(exe, prefix, event.State, want)
			}
		}
	}
}
