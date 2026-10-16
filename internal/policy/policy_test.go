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
