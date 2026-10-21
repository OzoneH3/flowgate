package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestPairedRootApplicationScope(t *testing.T) {
	now := time.Now()
	app := identity.Application{Kind: "native", Executable: "/usr/bin/tool", Revision: "v1"}
	app.Key = identity.ApplicationKey(1000, app)
	r := Rule{ShareWithRoot: true, ID: "user", Schema: 2, Executable: app.Executable, Action: "allow", Created: now, Filter: Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Direction: "outgoing", Protocol: "tcp"}, RootApplication: identity.ApplicationKey(0, app)}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	flow, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:1234", "1.2.3.4:443")
	eval := func(rules []Rule, uid uint32, a identity.Application) string {
		a.Key = identity.ApplicationKey(uid, a)
		action, _, _ := Evaluate(rules, flow, identity.Attribution{Application: &a, Owners: []identity.Process{{UID: uid}}}, now)
		return action
	}
	for _, uid := range []uint32{1000, 0} {
		if eval([]Rule{r}, uid, app) != "allow" {
			t.Fatal("paired account not allowed", uid)
		}
	}
	if eval([]Rule{r}, 970, app) != "ask" {
		t.Fatal("service account inherited permission")
	}
	other := app
	other.Executable = "/other/tool"
	if eval([]Rule{r}, 0, other) != "ask" {
		t.Fatal("different path allowed")
	}
	other = app
	other.Revision = "v2"
	if eval([]Rule{r}, 0, other) != "ask" {
		t.Fatal("different revision allowed")
	}
	for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
		other = app
		other.Kind = "wine"
		other.Prefix = prefix
		if eval([]Rule{r}, 0, other) != "ask" {
			t.Fatal("Wine identity inherited native permission")
		}
	}
	flow.Direction = "incoming"
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("direction transferred")
	}
	flow.Direction = "outgoing"
	block := r
	block.ID = "root-block"
	block.RootApplication = ""
	block.Filter.UID = 0
	block.Filter.Application = identity.ApplicationKey(0, app)
	block.Action = "block"
	if eval([]Rule{r, block}, 0, app) != "block" {
		t.Fatal("root block lost precedence")
	}
	r.Disabled = true
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("disabled shared rule allowed")
	}
	r.Disabled = false
	r.Expires = now
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("expired shared rule allowed")
	}
	r.Expires = time.Time{}
	r.RootApplication = "forged"
	if r.Validate() == nil {
		t.Fatal("invalid counterpart accepted")
	}
}

func TestRootExplicitPolicyOverridesSharedAcrossActionsAndPriorities(t *testing.T) {
	app := identity.Application{Kind: "native", Executable: "/usr/bin/tool", Revision: "v1"}
	app.Key = identity.ApplicationKey(0, app)
	flow, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:1234", "1.2.3.4:443")
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 0}}}
	for _, sharedAction := range []string{"allow", "block", "ask"} {
		for _, rootAction := range []string{"allow", "block", "ask"} {
			for _, priority := range []int{-1000, 0, 1000} {
				shared := Rule{ShareWithRoot: true, ID: "shared", Executable: app.Executable, RootApplication: app.Key, Action: sharedAction, Priority: priority, Filter: Filter{Application: identity.ApplicationKey(1000, app), Revision: "v1", UID: 1000, Direction: "outgoing", Protocol: "tcp"}}
				explicit := shared
				explicit.ID, explicit.RootApplication, explicit.Action, explicit.Priority = "root", "", rootAction, 0
				explicit.Filter.UID, explicit.Filter.Application = 0, app.Key
				got, id, _ := Evaluate([]Rule{shared, explicit}, flow, a, time.Now())
				if got != rootAction || id != "root" {
					t.Fatalf("shared %s/%d root %s: %s %s", sharedAction, priority, rootAction, got, id)
				}
			}
		}
	}
}

func TestAutomaticRootSharingRejectedWithoutBreakingLegacyLoad(t *testing.T) {
	for _, path := range []string{"/usr/bin/python3.13", "/usr/bin/bun", "/usr/bin/tclsh8.6", "/usr/bin/beam.smp", "/usr/bin/guile", "/custom/unknown", "/usr/bin/tool", "/custom/script-host"} {
		app := identity.Application{Kind: "native", Executable: path, Revision: "v1"}
		r := Rule{Schema: 2, ID: "legacy", Executable: path, RootApplication: identity.ApplicationKey(0, app), Action: "allow", Filter: Filter{Application: identity.ApplicationKey(1000, app), UID: 1000, Revision: "v1", Direction: "outgoing", Protocol: "tcp"}}
		if path == "/custom/script-host" {
			r.Invocation = &identity.Invocation{Mode: "file", Name: "script"}
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("legacy rule cannot be loaded for revocation: %v", err)
		}
		if r.CanShareRoot() || r.MatchesApplication(r.RootApplication, "v1", 0) {
			t.Fatalf("%s shared with root", path)
		}
		if !r.MatchesApplication(r.Filter.Application, "v1", 1000) {
			t.Fatal("original user permission lost")
		}
	}
}
