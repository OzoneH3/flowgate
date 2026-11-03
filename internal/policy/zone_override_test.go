package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

// Zone exceptions are symmetric for Allow/Block and incoming/outgoing, but
// never cross application, principal, direction or confident-zone boundaries.
func TestNamedZoneOverridesMainAtEqualPriority(t *testing.T) {
	for _, direction := range []string{"incoming", "outgoing"} {
		for _, zone := range []string{"local", "internet"} {
			for _, action := range []string{"allow", "block"} {
				for _, key := range []string{"synthetic-a-prefix-a", "synthetic-b-prefix-b"} {
					t.Run(direction+"/"+zone+"/"+action+"/"+key, func(t *testing.T) {
						app := identity.Application{Key: key, Revision: "revision-" + key}
						attr := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
						flow, err := identity.ParseFlow("udp", direction, "192.0.2.1:40000", "198.51.100.1:27000")
						if err != nil {
							t.Fatal(err)
						}
						flow.NetworkScope = identity.NetworkScope{State: "known", Zone: zone, Source: identity.AutomaticZoneModel}
						other := "block"
						if action == "block" {
							other = "allow"
						}
						main := Rule{Schema: 4, ID: "main", Version: 1, Priority: 100, Action: other, Filter: Filter{Application: key, Revision: app.Revision, UID: 1000, Direction: direction, Protocol: "*", RemoteAddress: "*"}}
						scoped := main
						scoped.Schema = 6
						scoped.ID = "zone"
						scoped.Action = action
						scoped.Filter.NetworkZone = zone
						scoped.Filter.ZoneModel = identity.AutomaticZoneModel
						for _, r := range []Rule{main, scoped} {
							if err := r.Validate(); err != nil {
								t.Fatal(err)
							}
						}
						check := func(want string) {
							t.Helper()
							for _, rules := range [][]Rule{{main, scoped}, {scoped, main}} {
								_, got, _ := Evaluate(rules, flow, attr, time.Now())
								if got != want {
									t.Fatalf("winner %s, want %s", got, want)
								}
							}
						}
						check("zone")
						if !Precedes(scoped, main) || DecidingFactor(scoped, main) != "Local or Internet rule overrides All networks rule at equal priority" {
							t.Fatal("explanation disagrees")
						}
						main.Priority = 101
						check("main")
						main.Priority = 100
						scoped.Preset = &Preset{Name: "synthetic-preset", Component: "network", EntryID: "entry", Revision: "rev", Digest: "digest"}
						scoped.Priority = -1000
						check("main")
						scoped.Priority = 100
						scoped.Preset = nil
						flow.NetworkScope.State = "unavailable"
						check("main")
						flow.NetworkScope.State = "known"
						flow.NetworkScope.Zone = "other"
						check("main")
						flow.NetworkScope.Zone = zone
						scoped.Filter.UID = 2000
						check("main")
						scoped.Filter.UID = 1000
						scoped.Filter.Application = "another-prefix"
						check("main")
						scoped.Filter.Application = key
						scoped.Filter.Direction = "incoming"
						if direction == "incoming" {
							scoped.Filter.Direction = "outgoing"
						}
						check("main")
						scoped.Filter.Direction = direction
						// Same-zone action ties keep the established Deny-over-Allow rule.
						main.Schema = 6
						main.Filter.NetworkZone = zone
						main.Filter.ZoneModel = identity.AutomaticZoneModel
						want := "main"
						if action == "block" {
							want = "zone"
						}
						check(want)
					})
				}
			}
		}
	}
}
