package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestPrecedenceAndIdentity(t *testing.T) {
	f, _ := identity.ParseFlow("tcp", "incoming", "127.0.0.1:80", "127.0.0.1:90")
	a := identity.Attribution{Application: &identity.Application{Key: "alpha", Revision: "r1"}, Owners: []identity.Process{{UID: 1000}}}
	filter := Filter{Application: "alpha", Revision: "r1", UID: 1000, Protocol: "tcp", Direction: "incoming"}
	rules := []Rule{{ID: "b", Priority: 10, Filter: filter, Action: "allow"}, {ID: "a", Priority: 10, Filter: filter, Action: "block"}}
	action, id, matches := Evaluate(rules, f, a, time.Now())
	if action != "block" || id != "a" || len(matches) != 2 {
		t.Fatal(action, id, matches)
	}
	a.Application.Key = "beta"
	action, _, _ = Evaluate(rules, f, a, time.Now())
	if action != "ask" {
		t.Fatal("runtime-wide permission")
	}
	a.Application.Key = "alpha"
	a.Application.Revision = "r2"
	action, _, _ = Evaluate(rules, f, a, time.Now())
	if action != "ask" {
		t.Fatal("changed executable permitted")
	}
}

func TestDirectionAwareScope(t *testing.T) {
	a := identity.Attribution{Application: &identity.Application{Key: "a", Revision: "r"}, Owners: []identity.Process{{UID: 1000}}}
	f, _ := identity.ParseFlow("tcp", "incoming", "127.0.0.1:80", "127.0.0.2:9000")
	x := Remembered(f, a)
	r := Rule{Schema: 2, ID: "r", Filter: x, Action: "allow"}
	for _, tc := range []struct{ local, remote, want string }{{"127.0.0.1:80", "127.0.0.2:9001", "allow"}, {"127.0.0.1:81", "127.0.0.2:9000", "ask"}, {"127.0.0.1:80", "127.0.0.3:9000", "ask"}} {
		flow, _ := identity.ParseFlow("tcp", "incoming", tc.local, tc.remote)
		act, _, _ := Evaluate([]Rule{r}, flow, a, time.Now())
		if act != tc.want {
			t.Fatal(tc, act)
		}
	}
	f.Direction = "outgoing"
	x = Remembered(f, a)
	if x.RemotePort != 9000 || x.LocalPort != 0 {
		t.Fatal("outgoing destination broadened")
	}
	r.Filter = Filter{Application: "a", Revision: "r", UID: 1000, Protocol: "tcp", Direction: "incoming", Remote: "127.0.0.2:9000"}
	f.Direction = "incoming"
	act, _, _ := Evaluate([]Rule{r}, f, a, time.Now())
	if act != "allow" {
		t.Fatal("v1 exact remote changed")
	}
}
