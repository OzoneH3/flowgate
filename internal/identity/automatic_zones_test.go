package identity

import (
	"golang.org/x/sys/unix"
	"net/netip"
	"strings"
	"testing"
)

func automaticFixture() NetworkSnapshot {
	s := NetworkSnapshot{State: "ready", NetNS: NetNS(), Links: []NetworkLink{{Index: 2, Name: "lan0", Kind: "veth", Flags: unix.IFF_UP | unix.IFF_BROADCAST}, {Index: 3, Name: "tailscale0", Kind: "tun", Flags: unix.IFF_UP | unix.IFF_POINTOPOINT}}, Addresses: []NetworkAddress{{Interface: 2, Prefix: "9.9.9.1/24"}, {Interface: 3, Prefix: "8.8.8.1/24"}}, Routes: []NetworkRoute{{Prefix: "9.9.9.0/24", Interface: 2, Table: 254, Type: unix.RTN_UNICAST}, {Prefix: "8.8.8.0/24", Interface: 3, Table: 254, Type: unix.RTN_UNICAST}, {Prefix: "0.0.0.0/0", Interface: 3, Table: 254, Type: unix.RTN_UNICAST}}, Rules: []string{}}
	s.seal()
	return s
}
func TestAutomaticAddressScopeAndVPN(t *testing.T) {
	z := AutomaticNetworkZones(DefaultNetworkZones(), automaticFixture())
	for address, want := range map[string]string{"1.1.1.1": "internet", "2001:4860:4860::8888": "internet", "8.8.8.8": "internet", "9.9.9.4": "local", "10.99.2.3": "local", "172.20.9.1": "local", "192.168.8.1": "local", "100.101.3.4": "local", "fd7a:115c:a1e0::1": "local", "fdca::2": "local", "127.1.2.3": "local", "::1": "local", "fe80::1%2": "local", "169.254.1.2": "local", "224.0.0.251": "local", "239.1.2.3": "local", "ff02::1": "local", "ff0e::1": "", "224.1.1.1": "", "0.0.0.0": "", "::": "", "192.0.2.1": "", "198.18.0.1": "", "2001:db8::1": "", "4000::1": "", "192.0.0.9": "internet", "64:ff9b::808:808": "internet"} {
		got := z.Classify(netip.MustParseAddr(address))
		if got.Zone != want {
			t.Errorf("%s got%+v want%s", address, got, want)
		}
		if want != "" && !strings.Contains(got.Reason, "permission") {
			t.Error("scope implied permission", got)
		}
	}
	z2 := AutomaticNetworkZones(DefaultNetworkZones(), automaticFixture())
	if z.Revision != z2.Revision {
		t.Fatal("stable config changed revision")
	}
	s := automaticFixture()
	s.Routes = append(s.Routes, NetworkRoute{Prefix: "9.9.9.4/32", Interface: 3, Table: 254, Type: unix.RTN_UNICAST})
	s.seal()
	z2 = AutomaticNetworkZones(DefaultNetworkZones(), s)
	if z2.Revision == z.Revision || z2.Classify(netip.MustParseAddr("9.9.9.4")).Zone != "internet" {
		t.Fatal("more-specific VPN route did not update public peer scope")
	}
	if got := z.ClassifyFlow(Flow{Remote: netip.MustParseAddrPort("1.1.1.1:80"), NetNS: "other"}); got.State != "unavailable" {
		t.Fatal("crossnamespace topology used", got)
	}
}
func TestAutomaticOverridesAndUnavailable(t *testing.T) {
	legacy, _ := NewNetworkZones([]string{"1.1.1.0/24"}, []string{"10.90.0.0/16"})
	s := automaticFixture()
	s.State = "unavailable"
	s.seal()
	z := AutomaticNetworkZones(legacy, s)
	for a, w := range map[string]string{"1.1.1.1": "local", "10.90.1.1": "internet", "10.91.1.1": "local", "8.8.8.8": ""} {
		if v := z.Classify(netip.MustParseAddr(a)); v.Zone != w {
			t.Fatal(a, v)
		}
	}
	if z.Classify(netip.MustParseAddr("10.91.1.1")).LegacyZone != "" {
		t.Fatal("automatic scope broadened legacy")
	}
}
func TestExactCoverageDiff(t *testing.T) {
	a := DefaultNetworkZones()
	b := AutomaticNetworkZones(a, automaticFixture())
	old, new, added, removed, err := ZoneCoverage(a, b, "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(new) <= len(old) || len(added) == 0 || len(removed) != 0 {
		t.Fatal(len(old), len(new), len(added), len(removed))
	}
	contains := func(list []string, ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, p := range list {
			if netip.MustParsePrefix(p).Contains(a) {
				return true
			}
		}
		return false
	}
	for _, ip := range []string{"10.1.2.3", "100.99.1.1", "fd7a:115c:a1e0::1", "9.9.9.5"} {
		if !contains(added, ip) {
			t.Fatal("missing precise coverage", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "127.0.0.1"} {
		if contains(added, ip) {
			t.Fatal("incorrect addition", ip)
		}
	}
}

func TestPublicLANRequiresUsableUnambiguousRoute(t *testing.T) {
	s := automaticFixture()
	s.Routes = nil
	s.seal()
	if got := AutomaticNetworkZones(DefaultNetworkZones(), s).Classify(netip.MustParseAddr("9.9.9.4")); got.State != "unavailable" {
		t.Fatal("missing route guessed", got)
	}
	s = automaticFixture()
	s.Routes = append(s.Routes, NetworkRoute{Prefix: "0.0.0.0/0", Interface: 3, Table: 52, Type: unix.RTN_UNICAST})
	s.seal()
	z := AutomaticNetworkZones(DefaultNetworkZones(), s)
	if got := z.Classify(netip.MustParseAddr("9.9.9.4")); got.State != "unavailable" {
		t.Fatal("ambiguous policy routing guessed", got)
	}
	if got := z.Classify(netip.MustParseAddr("1.1.1.1")); got.Zone != "internet" {
		t.Fatal("public over alternative VPN route became Local", got)
	}
}

func TestPublicLANDoesNotGuessMultipath(t *testing.T) {
	s := automaticFixture()
	s.Routes[0].Options = "unresolved-nexthops"
	s.seal()
	if got := AutomaticNetworkZones(DefaultNetworkZones(), s).Classify(netip.MustParseAddr("9.9.9.4")); got.State != "unavailable" {
		t.Fatal("multipath LAN guessed into automatic permission", got)
	}
}
