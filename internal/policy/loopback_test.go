package policy

import (
	"flowgate/internal/identity"
	"net"
	"net/netip"
	"testing"
	"time"
)

func loopbackFixture(t *testing.T) identity.Flow {
	t.Helper()
	interfaces, e := net.Interfaces()
	if e != nil {
		t.Fatal(e)
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			return identity.Flow{NetNS: identity.NetNS(), Interface: uint32(i.Index), Protocol: "tcp", Direction: "outgoing", Local: netip.MustParseAddrPort("127.0.0.2:43000"), Remote: netip.MustParseAddrPort("127.0.0.1:5000")}
		}
	}
	t.Fatal("loopback interface missing")
	return identity.Flow{}
}
func TestLocalhostDefaultAndExplicitScope(t *testing.T) {
	now := time.Now()
	f := loopbackFixture(t)
	a := identity.Attribution{Application: &identity.Application{Key: "a", Revision: "r"}, Owners: []identity.Process{{UID: 1000}}}
	broad := Rule{ID: "broad", Action: "block", Filter: Filter{Application: "a", Revision: "r", UID: 1000, Direction: "outgoing", Protocol: "tcp"}}
	for _, address := range []string{"", "*", "0.0.0.0/0", "127.0.0.0/7"} {
		r := broad
		r.Filter.RemoteAddress = address
		if act, id, _ := Evaluate([]Rule{r}, f, a, now); act != "allow" || id != DefaultLoopback {
			t.Fatal(address, act, id)
		}
	}
	if act, _, _ := Evaluate(nil, f, identity.Attribution{}, now); act != "allow" {
		t.Fatal("default required app identity")
	}
	for _, address := range []string{"127.0.0.1", "127.0.0.0/8", "127.0.0.1/32"} {
		r := broad
		r.Filter.RemoteAddress = address
		if act, id, _ := Evaluate([]Rule{r}, f, a, now); act != "block" || id != r.ID {
			t.Fatal(address, act, id)
		}
		r.Action = "ask"
		if act, _, _ := Evaluate([]Rule{r}, f, a, now); act != "ask" {
			t.Fatal("explicit ask lost")
		}
		if act, _, _ := Evaluate([]Rule{r}, f, identity.Attribution{}, now); act != "block" {
			t.Fatal("explicit target bypassed unsafe attribution")
		}
		r.Filter.Application = "another"
		if act, _, _ := Evaluate([]Rule{r}, f, a, now); act != "allow" {
			t.Fatal("cross-app block")
		}
	}
	for _, state := range []string{"disabled", "expired", "wrong-direction", "wrong-port", "other-uid"} {
		r := broad
		r.Filter.RemoteAddress = "127.0.0.1"
		switch state {
		case "disabled":
			r.Disabled = true
		case "expired":
			r.Expires = now
		case "wrong-direction":
			r.Filter.Direction = "incoming"
		case "wrong-port":
			r.Filter.RemotePort = 5001
		case "other-uid":
			r.Filter.UID = 1001
		}
		if act, _, _ := Evaluate([]Rule{r}, f, a, now); act != "allow" {
			t.Fatal(state, act)
		}
	}
	v6 := f
	v6.Local = netip.MustParseAddrPort("[::1]:43000")
	v6.Remote = netip.MustParseAddrPort("[::1]:5000")
	if act, _, _ := Evaluate(nil, v6, identity.Attribution{}, now); act != "allow" {
		t.Fatal("IPv6 localhost")
	}
	r := broad
	r.Filter.RemoteAddress = "::1/128"
	if act, _, _ := Evaluate([]Rule{r}, v6, a, now); act != "block" {
		t.Fatal("IPv6 explicit block")
	}
	for _, change := range []string{"interface", "namespace", "remote", "local", "direction"} {
		g := f
		switch change {
		case "interface":
			g.Interface = 0
		case "namespace":
			g.NetNS = "foreign"
		case "remote":
			g.Remote = netip.MustParseAddrPort("192.0.2.1:5000")
		case "local":
			g.Local = netip.MustParseAddrPort("192.0.2.1:43000")
		case "direction":
			g.Direction = "unknown"
		}
		if act, _, _ := Evaluate(nil, g, identity.Attribution{}, now); act == "allow" {
			t.Fatal("unsafe exemption", change)
		}
	}
}
