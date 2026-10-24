package policy

import (
	"flowgate/internal/identity"
	"net/netip"
	"testing"
	"time"
)

func endpointRule(action string) Rule {
	return Rule{NetworkEndpoint: true, Schema: 7, ID: "endpoint:test", Version: 1, Priority: 100, Action: action, Created: time.Unix(1, 0), Filter: Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "tcp", RemoteAddress: "192.0.2.40", RemotePort: 8445}}
}
func TestNetworkEndpointScopeValidation(t *testing.T) {
	r := endpointRule("allow")
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"*", "", "192.0.2.0/24", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1%eth0", "::ffff:192.0.2.40"} {
		t.Run(addr, func(t *testing.T) {
			c := r
			c.Filter.RemoteAddress = addr
			if c.Validate() == nil {
				t.Fatal("accepted broad/invalid scope")
			}
		})
	}
	for name, change := range map[string]func(*Rule){
		"legacy": func(c *Rule) { c.Schema = 4 }, "missingflag": func(c *Rule) { c.NetworkEndpoint = false }, "uid": func(c *Rule) { c.Filter.UID = 1000 }, "alluid": func(c *Rule) { c.Filter.AllUIDs = false }, "allprogram": func(c *Rule) { c.Filter.AllPrograms = false }, "app": func(c *Rule) { c.Filter.Application = "fake" }, "revision": func(c *Rule) { c.Filter.Revision = "fake" }, "incoming": func(c *Rule) { c.Filter.Direction = "incoming" }, "udp": func(c *Rule) { c.Filter.Protocol = "udp" }, "port": func(c *Rule) { c.Filter.RemotePort = 0 }, "localport": func(c *Rule) { c.Filter.LocalPort = 10 }, "zone": func(c *Rule) { c.Filter.NetworkZone = "local" }, "iface": func(c *Rule) { c.Filter.InterfaceName = "test" }, "executable": func(c *Rule) { c.Executable = "/fixture/a" }, "invocation": func(c *Rule) { c.Invocation = &identity.Invocation{} }, "root": func(c *Rule) { c.ShareWithRoot = true }, "ask": func(c *Rule) { c.Action = "ask" }, "priority": func(c *Rule) { c.Priority = 101 }, "preset": func(c *Rule) { c.Preset = &Preset{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := r
			change(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid authority")
			}
		})
	}
}
func TestNetworkEndpointPrecedesApplicationAndUnsafe(t *testing.T) {
	now := time.Unix(100, 0)
	r := endpointRule("allow")
	f := identity.Flow{Protocol: "tcp", Direction: "outgoing", Local: netip.MustParseAddrPort("192.0.2.5:40000"), Remote: netip.MustParseAddrPort("192.0.2.40:8445")}
	a := identity.Attribution{Application: &identity.Application{Key: "alpha", Revision: "one"}, Owners: []identity.Process{{UID: 1000}}}
	app := Rule{ID: "appdeny", Action: "block", Priority: 1000, Filter: Remembered(f, a)}
	for _, owner := range []identity.Attribution{a, {}, {Status: "multiple-candidates"}} {
		if action, id, _ := Evaluate([]Rule{app, r}, f, owner, now); action != "allow" || id != r.ID {
			t.Fatalf("endpoint override missing %s %s", action, id)
		}
	}
	deny := r
	deny.ID = "endpoint:deny"
	deny.Action = "block"
	if action, id, ids := Evaluate([]Rule{r, deny, app}, f, a, now); action != "block" || id != deny.ID || len(ids) != 2 || ids[0] != deny.ID {
		t.Fatal(action, id, ids)
	}
	for name, change := range map[string]func(*identity.Flow){"address": func(c *identity.Flow) { c.Remote = netip.MustParseAddrPort("192.0.2.41:8445") }, "port": func(c *identity.Flow) { c.Remote = netip.MustParseAddrPort("192.0.2.40:8446") }, "incoming": func(c *identity.Flow) { c.Direction = "incoming" }, "udp": func(c *identity.Flow) { c.Protocol = "udp" }} {
		t.Run(name, func(t *testing.T) {
			c := f
			change(&c)
			if _, id, _ := Evaluate([]Rule{r}, c, identity.Attribution{}, now); id != "unsafe-attribution" {
				t.Fatal(id)
			}
		})
	}
	for _, disable := range []bool{true, false} {
		c := r
		c.Disabled = disable
		if !disable {
			c.Expires = now
		}
		if _, id, _ := Evaluate([]Rule{c}, f, identity.Attribution{}, now); id != "unsafe-attribution" {
			t.Fatal("inactive endpoint applied", id)
		}
	}
	legacy := r
	legacy.NetworkEndpoint = false
	legacy.Schema = 4
	legacy.Filter.NetworkZone = "local"
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "local"}
	if _, id, _ := Evaluate([]Rule{legacy}, f, identity.Attribution{}, now); id != "unsafe-attribution" {
		t.Fatal("legacy scope acquired endpoint power", id)
	}
	r.Filter.RemoteAddress = "2001:db8::40"
	f.Remote = netip.MustParseAddrPort("[2001:db8::40]:8445")
	if action, _, _ := Evaluate([]Rule{r}, f, identity.Attribution{}, now); action != "allow" {
		t.Fatal("IPv6 endpoint missed")
	}
}

// The caller has already identified a same-host flow when selecting these
// rules. A private IP endpoint rule must not suppress the localhost exemption.
func TestNetworkEndpointDoesNotParticipateInLocalhostRules(t *testing.T) {
	r := endpointRule("block")
	f := identity.Flow{Protocol: "tcp", Direction: "outgoing", Local: netip.MustParseAddrPort("192.0.2.5:40000"), Remote: netip.MustParseAddrPort("192.0.2.40:8445")}
	if len(LoopbackRules([]Rule{r}, f, time.Unix(100, 0))) != 0 {
		t.Fatal("network rule suppressed default localhost policy")
	}
	// Legacy explicit application localhost matching remains in place.
	r.NetworkEndpoint = false
	r.Schema = 2
	r.Filter.AllPrograms = false
	r.Filter.AllUIDs = false
	r.Filter.Application = "test"
	r.Filter.Revision = "rev"
	if len(LoopbackRules([]Rule{r}, f, time.Unix(100, 0))) != 1 {
		t.Fatal("legacy same-host explicit match changed")
	}
}
