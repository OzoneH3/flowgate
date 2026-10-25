package policy

import (
	"flowgate/internal/identity"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestFlowCandidatesPreserveVerdictsAndProgramReplacement(t *testing.T) {
	now := time.Unix(1700000000, 0)
	app := identity.Application{Kind: "native", Executable: "/synthetic/app-a", Revision: "new"}
	app.Key = identity.ApplicationKey(1000, app)
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	var rules []Rule
	for _, direction := range []string{"incoming", "outgoing"} {
		for _, protocol := range []string{"*", "tcp", "udp"} {
			for _, port := range []uint16{0, 53, 443} {
				for _, action := range []string{"allow", "block", "ask"} {
					r := Rule{ID: fmt.Sprintf("%s-%s-%d-%s", direction, protocol, port, action), Schema: 2, Executable: app.Executable, Action: action, Created: now.Add(-time.Hour), Filter: Filter{Application: app.Key, Revision: "old", UID: 1000, Direction: direction, Protocol: protocol, RemotePort: port}}
					rules = append(rules, r)
					newer := r
					newer.ID += "-new-disabled"
					newer.Created = now.Add(-time.Minute)
					newer.Disabled = action == "allow"
					if !newer.FollowsUpdates() {
						t.Fatal("fixture must exercise update-following precedence")
					}
					rules = append(rules, newer)
				}
			}
		}
	}
	for _, direction := range []string{"incoming", "outgoing"} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, port := range []uint16{53, 443, 9999} {
				f, _ := identity.ParseFlow(protocol, direction, "192.0.2.1:40000", fmt.Sprintf("198.51.100.1:%d", port))
				for _, localhost := range []bool{false, true} {
					probe := func(identity.Flow) bool { return localhost }
					x, y, z := EvaluateSessionObserved(rules, f, a, now, "session", probe)
					u, v, w := EvaluateSessionObserved(FlowCandidates(rules, f), f, a, now, "session", probe)
					if x != u || y != v || !reflect.DeepEqual(z, w) {
						t.Fatalf("filter changed evaluation: %s %s %d localhost%v: %s/%s %v vs %s/%s %v", direction, protocol, port, localhost, x, y, z, u, v, w)
					}
				}
			}
		}
	}
}

func TestFlowCandidatesRetainEndpointRulesAndDoNotMutateInput(t *testing.T) {
	f, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:40000", "198.51.100.1:443")
	rules := []Rule{{ID: "endpoint", NetworkEndpoint: true}, {ID: "dns", Filter: Filter{Direction: "outgoing", Protocol: "udp", RemotePort: 53}}, {ID: "local-port", Filter: Filter{Direction: "outgoing", Protocol: "udp", LocalPort: 1}}, {ID: "app", Filter: Filter{Direction: "outgoing", Protocol: "*"}}}
	got := FlowCandidates(rules, f)
	if len(got) != 2 || got[0].ID != "endpoint" || got[1].ID != "app" {
		t.Fatal(got)
	}
	got[1].Disabled = true
	if rules[3].Disabled {
		t.Fatal("mutated stored rules")
	}
}

func TestFlowCandidatesCanonicalRemoteReplacement(t *testing.T) {
	now := time.Unix(1700000000, 0)
	app := identity.Application{Kind: "native", Executable: "/synthetic/app-a", Revision: "new"}
	app.Key = identity.ApplicationKey(1000, app)
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	old := Rule{ID: "old", Schema: 2, Executable: app.Executable, Action: "allow", Created: now.Add(-time.Hour), Filter: Filter{Application: app.Key, Revision: "old", UID: 1000, Direction: "outgoing", Protocol: "udp", Remote: "198.51.100.1:443"}}
	newer := old
	newer.ID, newer.Created, newer.Disabled = "new", now.Add(-time.Minute), true
	newer.Filter.Remote, newer.Filter.RemoteAddress, newer.Filter.RemotePort = "", "198.51.100.1", 443
	rules := []Rule{old, newer}
	if !old.FollowsUpdates() || !newer.FollowsUpdates() {
		t.Fatal("fixture must follow updates")
	}
	if old.ProgramScope() != newer.ProgramScope() {
		t.Fatal("not a replacement scope")
	}
	for _, port := range []int{443, 444} {
		f, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:40000", fmt.Sprintf("198.51.100.1:%d", port))
		probe := func(identity.Flow) bool { return false }
		x, y, z := EvaluateSessionObserved(rules, f, a, now, "session", probe)
		u, v, w := EvaluateSessionObserved(FlowCandidates(rules, f), f, a, now, "session", probe)
		if x != u || y != v || !reflect.DeepEqual(z, w) || x == "allow" {
			t.Fatal("revived old rule", port, x, y, z, u, v, w)
		}
	}
}
