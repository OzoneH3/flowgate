package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
)

func TestRememberSpecificIPAllowsOnlyThatAddress(t *testing.T) {
	for _, scope := range []string{"application", "persistent"} {
		t.Run(scope, func(t *testing.T) {
			e, _, a, _ := fixture()
			e.SaveRules = func([]policy.Rule) error { return nil }
			first, _ := identity.ParseFlow("udp", "outgoing", "127.0.0.1:30000", "192.0.2.10:443")
			v := e.Observe(first, "first")
			opts := RememberOptions{Fields: &RememberFields{Address: true}}
			if scope == "application" {
				opts.DurationSeconds = 3600
			}
			preview, err := e.PreviewDecision(e.Generation, v.ID, "allow", scope, "any", e.Zones.Revision, 1000, false, opts)
			if err != nil {
				t.Fatal(err)
			}
			decided, saved, _, err := e.DecideReviewed(e.Generation, v.ID, "allow", scope, "any", e.Zones.Revision, preview.Token, 1000, false, opts)
			if err != nil || decided.State != "allowed" {
				t.Fatal(decided, err)
			}
			if saved.Filter.RemoteAddress != "192.0.2.10" || saved.Filter.Protocol != "*" || saved.Filter.RemotePort != 0 {
				t.Fatal(saved)
			}
			same, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:30001", "192.0.2.10:8443")
			if got := e.Observe(same, "next"); got.State != "allowed" || got.Rule != saved.ID {
				t.Fatal("same IP was not remembered", got)
			}
			other, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:30002", "192.0.2.11:8443")
			if got := e.Observe(other, "other"); got.State != "awaiting-decision" {
				t.Fatal("other IP inherited permission", got)
			}
			a.Owners[0].UID = 1001
			a.Fingerprint = "other-user"
			otherUser, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:30003", "192.0.2.10:8443")
			if got := e.Observe(otherUser, "other-user"); got.State != "awaiting-decision" {
				t.Fatal("other user inherited permission", got)
			}
		})
	}
}
