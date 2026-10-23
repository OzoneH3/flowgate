package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

// The advertised winner (Precedes/DecidingFactor, used by every explanation)
// must be the rule the evaluator actually applies, for two distinct programs.
func TestAdvertisedPrecedenceMatchesEvaluator(t *testing.T) {
	now := time.Now()
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.1:40000", "198.51.100.7:443")
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "internet"}
	for _, key := range []string{"synthetic-a", "synthetic-b"} {
		app := identity.Application{Key: key, Revision: "rev-" + key}
		a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
		rule := func(id, action string, priority int, edit func(*Rule)) Rule {
			r := Rule{Schema: 4, ID: id, Version: 1, Priority: priority, Action: action, Filter: Filter{Application: key, Revision: app.Revision, UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
			if edit != nil {
				edit(&r)
			}
			return r
		}
		scoped := func(r *Rule) { r.Filter.RemoteAddress, r.Filter.Protocol, r.Filter.RemotePort = "198.51.100.7", "tcp", 443 }
		machine := func(r *Rule) {
			r.Filter = Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}
		}
		preset := func(r *Rule) { r.Preset = &Preset{Name: "p", Component: "c", EntryID: "e", Revision: "r", Digest: "d"} }
		for _, tc := range []struct {
			name, winner, factor string
			a, b                 Rule
		}{
			{"scoped Allow priority 1 vs broad Deny priority 0", "s-allow", "higher priority", rule("s-allow", "allow", 1, scoped), rule("b-deny", "block", 0, nil)},
			{"equal priority: Deny over Allow", "z-deny", "Deny › Allow › Ask at equal weight and priority", rule("a-allow", "allow", 0, scoped), rule("z-deny", "block", 0, nil)},
			{"application weight over machine priority", "z-app", "higher target weight", rule("z-app", "allow", 0, nil), rule("a-machine", "block", 1000, machine)},
			{"user over preset", "z-user", "user rule over preset", rule("z-user", "allow", 0, scoped), rule("a-preset", "allow", 0, preset)},
			{"smaller ID last", "a-one", "smaller rule ID", rule("a-one", "allow", 0, scoped), rule("b-two", "allow", 0, nil)},
		} {
			for _, order := range [][2]Rule{{tc.a, tc.b}, {tc.b, tc.a}} {
				_, got, _ := Evaluate([]Rule{order[0], order[1]}, f, a, now)
				advertised := order[1]
				if Precedes(order[0], order[1]) {
					advertised = order[0]
				}
				loser := order[0]
				if loser.ID == advertised.ID {
					loser = order[1]
				}
				if got != tc.winner || advertised.ID != got || DecidingFactor(advertised, loser) != tc.factor {
					t.Fatalf("%s/%s: evaluator %s, advertised %s (%s)", key, tc.name, got, advertised.ID, DecidingFactor(advertised, loser))
				}
			}
		}
	}
}

// Same-host traffic: the advertised exception (LoopbackSentence) matches the
// evaluator; a broad rule does not apply and an exact loopback scope does.
func TestAdvertisedLoopbackScopeMatchesEvaluator(t *testing.T) {
	now := time.Now()
	f := loopbackFixture(t)
	app := identity.Application{Key: "synthetic-a", Revision: "r"}
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	broad := Rule{ID: "broad", Priority: 1000, Action: "block", Filter: Filter{Application: "synthetic-a", Revision: "r", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	if broad.Filter.TargetsLoopback() {
		t.Fatal("broad rule advertised as a localhost scope")
	}
	if act, id, _ := Evaluate([]Rule{broad}, f, a, now); act != "allow" || id != DefaultLoopback {
		t.Fatal(act, id)
	}
	exact := broad
	exact.ID, exact.Priority, exact.Filter.RemoteAddress = "exact", 0, "127.0.0.1"
	if !exact.Filter.TargetsLoopback() {
		t.Fatal("loopback scope not advertised")
	}
	if act, id, _ := Evaluate([]Rule{broad, exact}, f, a, now); act != "block" || id != "exact" {
		t.Fatal(act, id)
	}
}
