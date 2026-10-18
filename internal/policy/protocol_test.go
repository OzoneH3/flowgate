package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestTCPUDPWildcardIsBounded(t *testing.T) {
	app := identity.Application{Key: "a", Revision: "r"}
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
	r := Rule{Schema: 2, ID: "r", Action: "allow", Filter: Filter{Application: "a", Revision: "r", UID: 1000, Protocol: "*", Direction: "incoming", RemoteAddress: "*"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, proto := range []string{"tcp", "udp", "icmp", "sctp", "*", ""} {
		f, _ := identity.ParseFlow("tcp", "incoming", "127.0.0.1:80", "127.0.0.2:90")
		f.Protocol = proto
		action, _, _ := Evaluate([]Rule{r}, f, a, time.Now())
		want := "ask"
		if proto == "tcp" || proto == "udp" {
			want = "allow"
		}
		if action != want {
			t.Fatal(proto, action, want)
		}
		f.Direction = "outgoing"
		action, _, _ = Evaluate([]Rule{r}, f, a, time.Now())
		if action != "ask" {
			t.Fatal("direction widened")
		}
	}
	for _, proto := range []string{"", "any", "icmp"} {
		x := r
		x.Filter.Protocol = proto
		if x.Validate() == nil {
			t.Fatal("invalid protocol", proto)
		}
	}
	x := r
	x.Schema = 1
	if x.Validate() == nil {
		t.Fatal("wildcard on legacy schema")
	}
	if !ProtocolsOverlap("*", "tcp") || !ProtocolsOverlap("udp", "*") || ProtocolsOverlap("tcp", "udp") || ProtocolsOverlap("*", "icmp") {
		t.Fatal("overlap semantics")
	}
}
