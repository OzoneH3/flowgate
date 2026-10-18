package identity

import (
	"net/netip"
	"testing"
)

func TestConfiguredZonesNoAddressClassGuess(t *testing.T) {
	z, e := NewNetworkZones([]string{"192.0.2.0/24", "100.64.0.0/10", "fd79::/64"}, []string{"203.0.113.0/24", "2001:db8::/32"})
	if e != nil {
		t.Fatal(e)
	}
	for addr, want := range map[string]string{"127.0.0.1": "local", "::1": "local", "169.254.3.2": "local", "fe80::1%4": "local", "192.0.2.9": "local", "100.64.2.3": "local", "fd79::2": "local", "203.0.113.2": "internet", "2001:db8::2": "internet", "10.1.2.3": "", "172.16.1.2": "", "fd80::1": "", "8.8.8.8": "", "0.0.0.0": "", "ff02::1": "", "255.255.255.255": ""} {
		v := z.Classify(netip.MustParseAddr(addr))
		if v.Zone != want || (v.State == "known") != (want != "") {
			t.Errorf("%s %+v", addr, v)
		}
	}
	z2, e := NewNetworkZones([]string{"192.0.2.0/24"}, []string{"0.0.0.0/0", "::/0"})
	if e != nil {
		t.Fatal(e)
	}
	if z2.Classify(netip.MustParseAddr("192.0.2.1")).Zone != "local" || z2.Classify(netip.MustParseAddr("10.3.4.5")).Zone != "internet" {
		t.Fatal("explicit partition failed")
	}
	if _, e = NewNetworkZones([]string{"192.0.2.0/24"}, []string{"192.0.2.0/24"}); e == nil {
		t.Fatal("conflict accepted")
	}
	z3, _ := NewNetworkZones([]string{"192.0.2.20/24", "192.0.2.0/24"}, []string{"::/0", "0.0.0.0/0"})
	if z3.Revision != z2.Revision {
		t.Fatal("canonical revision unstable")
	}
	for _, s := range []Socket{{Protocol: "tcp", State: 10, Remote: netip.MustParseAddrPort("192.0.2.9:0")}, {Protocol: "udp", Remote: netip.MustParseAddrPort("0.0.0.0:0")}} {
		if z.SocketScope(s).State != "unavailable" {
			t.Fatal("listener/UDP invented zone")
		}
	}
}
