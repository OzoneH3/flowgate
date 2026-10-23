package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestHostedHintsCannotMatchLegacyApplicationRules(t *testing.T) {
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.10:40000", "198.51.100.20:443")
	now := time.Now()
	for _, kind := range []string{"native", "electron"} {
		for _, state := range []string{"unverified", "verified"} {
			app := identity.Application{Kind: kind, Executable: "/runtime/electron", Revision: "revision", Hosted: &identity.Hosted{State: state, Runtime: "/runtime/electron", Bundle: "/apps/claimed"}}
			app.Key = identity.ApplicationKey(1000, app)
			a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
			r := Rule{Schema: 2, ID: "old", Executable: app.Executable, Action: "allow", Created: now, Filter: Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Direction: "outgoing", Protocol: "tcp", RemoteAddress: "*"}}
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			if r.MatchesApplication(app.Key, app.Revision, 1000, app) {
				t.Fatalf("legacy hosted label matched %s/%s", kind, state)
			}
			got, _, matches := Evaluate([]Rule{r}, f, a, now)
			if got != "ask" || len(matches) != 0 {
				t.Fatalf("legacy allow granted %s/%s: %s %v", kind, state, got, matches)
			}
			// A block is not silently reinterpreted as authority for another app either.
			r.Action = "block"
			if got, _, _ := Evaluate([]Rule{r}, f, a, now); got != "ask" {
				t.Fatalf("legacy scope revived: %s", got)
			}
		}
	}
}

func TestHostedHintsPreserveExplicitGlobalRuleScopes(t *testing.T) {
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.10:40000", "198.51.100.20:443")
	now := time.Now()
	app := identity.Application{Kind: "native", Executable: "/runtime/electron", Revision: "r", Hosted: &identity.Hosted{State: "unverified"}}
	app.Key = identity.ApplicationKey(1000, app)
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "internet"}
	r := Rule{Schema: 4, ID: "explicit-global", Action: "allow", Created: now, Filter: Filter{AllPrograms: true, UID: 1000, NetworkZone: "internet", Direction: "outgoing", Protocol: "tcp", RemoteAddress: "198.51.100.20", RemotePort: 443}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"allow", "block"} {
		r.Action = action
		if got, _, _ := Evaluate([]Rule{r}, f, a, now); got != action {
			t.Fatalf("explicit global %s: %s", action, got)
		}
	}
	for _, change := range []string{"uid", "direction", "protocol", "address", "port"} {
		b := r
		switch change {
		case "uid":
			b.Filter.UID = 1001
		case "direction":
			b.Filter.Direction = "incoming"
		case "protocol":
			b.Filter.Protocol = "udp"
		case "address":
			b.Filter.RemoteAddress = "203.0.113.10"
		case "port":
			b.Filter.RemotePort = 8443
		}
		if got, _, _ := Evaluate([]Rule{b}, f, a, now); got != "ask" {
			t.Fatalf("global %s scope widened: %s", change, got)
		}
	}
}
