package identity

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// Pure models: no kernel, no netlink. The constructor-owned view must be
// invisible (JSON, revision, classification identical) and must never be
// trusted for a value whose prefix texts differ from the view's.

var viewRemotes = []string{"127.0.0.1", "::1", "169.254.9.9", "fe80::1", "10.1.2.3", "10.9.0.1", "192.168.1.20", "172.16.5.5",
	"100.64.1.1", "203.0.113.9", "8.8.8.8", "2001:db8::1", "2a00:1450::1", "fd00::5", "224.0.0.251", "239.1.1.1", "ff02::1", "ff0e::1",
	"255.255.255.255", "0.0.0.0", "::", "::ffff:10.1.2.3", "::ffff:8.8.8.8", "198.18.0.1", "240.0.0.1", "4000::1"}

func viewConfigs() [][2][]string {
	return [][2][]string{
		{nil, nil},
		{{"10.0.0.0/8"}, {"10.9.0.0/16"}},
		{{"192.168.1.0/24", "2001:db8::/32"}, {"203.0.113.0/24"}},
		{{"10.1.2.3/32"}, {"10.0.0.0/8"}},
		{{"0.0.0.0/0"}, nil},
	}
}

func scopesOf(z NetworkZones) []NetworkScope {
	var out []NetworkScope
	for _, r := range viewRemotes {
		out = append(out, z.Classify(netip.MustParseAddr(r)))
	}
	return out
}

func TestZonesViewIsInvisibleToJSONAndRevision(t *testing.T) {
	for _, c := range viewConfigs() {
		z, err := NewNetworkZones(c[0], c[1])
		if err != nil {
			t.Fatal(err)
		}
		if z.view == nil || z.view.revision != z.Revision || len(z.view.local) != len(z.Local) || len(z.view.internet) != len(z.Internet) {
			t.Fatalf("view not owned by constructor: %+v", z)
		}
		b, _ := json.Marshal(z)
		var back NetworkZones
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.view != nil {
			t.Fatal("view leaked through JSON")
		}
		again, _ := json.Marshal(back)
		if string(again) != string(b) {
			t.Fatalf("round trip changed JSON:\n%s\n%s", b, again)
		}
		if back.Revision != z.Revision || !reflect.DeepEqual(back.Local, z.Local) || !reflect.DeepEqual(back.Internet, z.Internet) {
			t.Fatalf("round trip changed fields")
		}
	}
}

// A literal or unmarshalled value (no view) classifies exactly like the
// constructed value, including reason texts.
func TestZonesViewFallbackClassifiesIdentically(t *testing.T) {
	for _, c := range viewConfigs() {
		z, _ := NewNetworkZones(c[0], c[1])
		literal := NetworkZones{Model: z.Model, Revision: z.Revision, Local: z.Local, Internet: z.Internet, Reason: z.Reason}
		b, _ := json.Marshal(z)
		var decoded NetworkZones
		json.Unmarshal(b, &decoded)
		want := scopesOf(z)
		for name, other := range map[string]NetworkZones{"literal": literal, "decoded": decoded} {
			if got := scopesOf(other); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s classification differs for %v:\n%+v\n%+v", name, c, got, want)
			}
		}
		// Legacy of a configured value is the value itself.
		l := z.Legacy()
		if l.Revision != z.Revision || !reflect.DeepEqual(l.Local, z.Local) || !reflect.DeepEqual(l.Internet, z.Internet) || l.Model != z.Model || l.Reason != z.Reason {
			t.Fatalf("Legacy differs: %+v vs %+v", l, z)
		}
	}
}

// A copy whose prefix texts were changed after construction must not reuse the
// stale view; it must classify by its own texts, and the original is untouched.
func TestZonesViewNeverTrustsStaleView(t *testing.T) {
	z, _ := NewNetworkZones([]string{"10.0.0.0/8"}, nil)
	changed := z
	changed.Local = []string{"192.168.0.0/16"}
	if changed.view != z.view {
		t.Fatal("copy should carry the original view pointer for this test")
	}
	peer := netip.MustParseAddr("10.1.2.3")
	if s := changed.Classify(peer); s.State != "unavailable" {
		t.Fatalf("stale view used: %+v", s)
	}
	if s := changed.Classify(netip.MustParseAddr("192.168.1.1")); s.State != "known" || s.Zone != "local" {
		t.Fatalf("own texts not used: %+v", s)
	}
	if s := z.Classify(peer); s.State != "known" || s.Zone != "local" || s.Reason != "Longest matching administrator-configured prefix 10.0.0.0/8" {
		t.Fatalf("original changed: %+v", s)
	}
	// Legacy() of the changed copy recomputes from its texts; the revision
	// follows the texts, not the stale view.
	fresh, _ := NewNetworkZones([]string{"192.168.0.0/16"}, nil)
	if l := changed.Legacy(); l.Revision != fresh.Revision || !reflect.DeepEqual(l.Local, fresh.Local) {
		t.Fatalf("Legacy of changed copy: %+v", l)
	}
	// Uncanonical literal texts canonicalize exactly as before.
	literal := NetworkZones{Model: configuredZoneModel, Local: []string{"10.1.2.3/8"}}
	canon, _ := NewNetworkZones([]string{"10.1.2.3/8"}, nil)
	if l := literal.Legacy(); l.Revision != canon.Revision || !reflect.DeepEqual(l.Local, canon.Local) {
		t.Fatalf("uncanonical literal: %+v", l)
	}
}

func TestZonesViewConfigurationChangeIsANewValue(t *testing.T) {
	a, _ := NewNetworkZones([]string{"10.0.0.0/8"}, nil)
	before := scopesOf(a)
	b, _ := NewNetworkZones([]string{"10.0.0.0/8"}, []string{"10.9.0.0/16"})
	if a.Revision == b.Revision || a.view == b.view {
		t.Fatal("configuration change did not produce a new value/view")
	}
	if !reflect.DeepEqual(scopesOf(a), before) {
		t.Fatal("old value changed after constructing a new one")
	}
	if s := b.Classify(netip.MustParseAddr("10.9.0.1")); s.Zone != "internet" || s.Reason != "Longest matching administrator-configured prefix 10.9.0.0/16" {
		t.Fatalf("%+v", s)
	}
}

// Automatic values: the legacy view comes from the constructor; network
// observations are read live from the value and are never part of the view.
func TestZonesViewAutomaticEqualsRecomputedLegacyAndKeepsNetworkLive(t *testing.T) {
	legacy, _ := NewNetworkZones([]string{"10.0.0.0/8"}, []string{"203.0.113.0/24"})
	lan := NetworkSnapshot{State: "ready", Revision: "net1", NetNS: NetNS(),
		Links:     []NetworkLink{{Index: 2, Name: "eth0", Flags: unix.IFF_UP}},
		Addresses: []NetworkAddress{{Interface: 2, Prefix: "93.184.216.10/24"}},
		Routes:    []NetworkRoute{{Prefix: "93.184.216.0/24", Interface: 2, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST}}}
	a := AutomaticNetworkZones(legacy, lan)
	if a.view != legacy.view || a.Legacy().Revision != legacy.Revision || !reflect.DeepEqual(a.Legacy(), NewOrPanic(legacy.Local, legacy.Internet)) {
		t.Fatalf("automatic legacy view differs: %+v", a.Legacy())
	}
	// Decoded automatic value (no view) classifies identically, legacy fields included.
	b, _ := json.Marshal(a)
	var decoded NetworkZones
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scopesOf(decoded), scopesOf(a)) {
		t.Fatalf("decoded automatic classification differs")
	}
	peer := netip.MustParseAddr("93.184.216.20")
	if s := a.Classify(peer); s.State != "known" || s.Zone != "local" {
		t.Fatalf("LAN peer: %+v", s)
	}
	// A different snapshot with the same legacy shares the view but not the result.
	noLAN := lan
	noLAN.Addresses = nil
	noLAN.Revision = "net2"
	c := AutomaticNetworkZones(legacy, noLAN)
	if c.view != legacy.view {
		t.Fatal("view must be configuration-only")
	}
	if s := c.Classify(peer); s.Zone != "internet" {
		t.Fatalf("network observation was frozen: %+v", s)
	}
	if a.Revision == c.Revision {
		t.Fatal("automatic revision must follow the network revision")
	}
}

func TestZonesViewRegistryPrefixesMatchRecords(t *testing.T) {
	if len(registryPrefixes) != len(addressRegistry.Records) {
		t.Fatal(len(registryPrefixes))
	}
	for i, r := range addressRegistry.Records {
		if registryPrefixes[i] != netip.MustParsePrefix(r.Prefix) {
			t.Fatalf("record %d: %s vs %s", i, registryPrefixes[i], r.Prefix)
		}
	}
	// Classification through the registry is unchanged for every remote.
	z := AutomaticNetworkZones(DefaultNetworkZones(), NetworkSnapshot{State: "ready", NetNS: NetNS()})
	for _, r := range viewRemotes {
		remote := netip.MustParseAddr(r).Unmap()
		var want *registryRecord
		bits := -1
		for i := range addressRegistry.Records {
			p := netip.MustParsePrefix(addressRegistry.Records[i].Prefix)
			if p.Contains(remote) && p.Bits() > bits {
				bits, want = p.Bits(), &addressRegistry.Records[i]
			}
		}
		s := z.Classify(remote)
		if want != nil && want.Local && (s.State != "known" || s.Zone != "local") && !remote.IsLoopback() && !remote.IsLinkLocalUnicast() && !remote.IsMulticast() {
			t.Fatalf("%s: registry local record %s not applied: %+v", r, want.Name, s)
		}
	}
}

func NewOrPanic(local, internet []string) NetworkZones {
	z, err := NewNetworkZones(local, internet)
	if err != nil {
		panic(err)
	}
	return z
}
