package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

// NetLimiter Blocker precedence: higher weight wins (machine 1, zone 2,
// application/filter 3); on equal weight Deny is applied before Allow.
func TestNetLimiterWeightPrecedence(t *testing.T) {
	app := identity.Application{Key: "app", Revision: "rev"}
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.1:40000", "198.51.100.7:443")
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "internet"}
	rule := func(id, action string, edit func(*Filter)) Rule {
		r := Rule{Schema: 4, ID: id, Version: 1, Priority: 100, Action: action, Filter: Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
		if edit != nil {
			edit(&r.Filter)
		}
		return r
	}
	appAllow := rule("z-app", "allow", nil)
	scopedDeny := rule("z-scoped", "block", func(f *Filter) { f.RemoteAddress = "198.51.100.7"; f.Protocol = "tcp"; f.RemotePort = 443 })
	machineDeny := rule("a-machine", "block", func(f *Filter) {
		*f = Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}
	})
	zoneDeny := rule("a-zone", "block", func(f *Filter) {
		*f = Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "*", RemoteAddress: "*", NetworkZone: "internet"}
	})
	zoneAllow := zoneDeny
	zoneAllow.ID, zoneAllow.Action = "b-zone", "allow"
	for _, tc := range []struct {
		name  string
		rules []Rule
		want  string
		id    string
	}{
		{"application (3) beats machine (1)", []Rule{machineDeny, appAllow}, "allow", "z-app"},
		{"application (3) beats zone (2)", []Rule{zoneDeny, appAllow}, "allow", "z-app"},
		{"zone (2) beats machine (1)", []Rule{machineDeny, zoneAllow}, "allow", "b-zone"},
		{"equal weight: Deny before Allow regardless of ID", []Rule{appAllow, scopedDeny}, "block", "z-scoped"},
		{"equal weight zone: Deny before Allow", []Rule{zoneAllow, zoneDeny}, "block", "a-zone"},
	} {
		act, id, _ := Evaluate(tc.rules, f, a, time.Now())
		if act != tc.want || id != tc.id {
			t.Fatalf("%s: got %s/%s", tc.name, act, id)
		}
	}
	// The scoped Deny applies only to its destination: other destinations stay allowed.
	other, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:40000", "203.0.113.9:53")
	if act, id, _ := Evaluate([]Rule{appAllow, scopedDeny}, other, a, time.Now()); act != "allow" || id != "z-app" {
		t.Fatalf("application Allow did not cover another destination/port/protocol: %s %s", act, id)
	}
}

// Observed NetLimiter 5.3.28: equal weight applies Deny, then Allow, then Ask;
// weight still dominates the action order.
func TestStoredAskPrecedence(t *testing.T) {
	app := identity.Application{Key: "app", Revision: "rev"}
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.1:40000", "198.51.100.7:443")
	mk := func(id, action string, all bool) Rule {
		r := Rule{Schema: 2, ID: id, Version: 1, Priority: 100, Action: action, Filter: Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
		if all {
			r.Schema, r.Filter = 4, Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}
		}
		return r
	}
	ask, allow, deny := mk("a-ask", "ask", false), mk("z-allow", "allow", false), mk("z-deny", "block", false)
	for _, tc := range []struct {
		rules   []Rule
		act, id string
	}{
		{[]Rule{ask, allow}, "allow", "z-allow"},
		{[]Rule{ask, deny}, "block", "z-deny"},
		{[]Rule{ask, allow, deny}, "block", "z-deny"},
		{[]Rule{ask}, "ask", "a-ask"},
		{[]Rule{mk("m-allow", "allow", true), ask}, "ask", "a-ask"}, // application Ask (3) beats machine Allow (1)
	} {
		act, id, _ := Evaluate(tc.rules, f, a, time.Now())
		if act != tc.act || id != tc.id {
			t.Fatalf("%v: got %s/%s want %s/%s", tc.rules, act, id, tc.act, tc.id)
		}
	}
}
