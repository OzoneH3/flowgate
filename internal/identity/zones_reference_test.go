package identity

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

// Verbatim copies of the pre-view configured-prefix behaviour, kept as the
// reference the view must reproduce for every kind of value, including ones
// NewNetworkZones rejects.
func referenceClassify(z NetworkZones, remote netip.Addr) NetworkScope {
	out := NetworkScope{State: "unavailable", Revision: z.Revision, Source: "configured-prefix-v1", Reason: "Peer has no explicitly configured zone membership"}
	remote = remote.Unmap().WithZone("")
	if !remote.IsValid() || remote.IsUnspecified() || remote.IsMulticast() || remote == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		out.Reason = "No classifiable unicast peer"
		return out
	}
	if remote.IsLoopback() || remote.IsLinkLocalUnicast() {
		out.State = "known"
		out.Zone = "local"
		out.Reason = "Explicit built-in loopback/link-local policy scope"
		return out
	}
	bits := -1
	for i, parts := range [][]string{z.Local, z.Internet} {
		for _, v := range parts {
			p, e := netip.ParsePrefix(v)
			if e == nil && p.Contains(remote) && p.Bits() > bits {
				bits = p.Bits()
				out.State = "known"
				out.Zone = "local"
				if i == 1 {
					out.Zone = "internet"
				}
				out.Reason = "Longest matching administrator-configured prefix " + v
			}
		}
	}
	return out
}

func referenceLegacy(z NetworkZones) NetworkZones {
	v, _ := NewNetworkZones(z.Local, z.Internet)
	return v
}

func referenceAutomaticLegacyScope(z NetworkZones, remote netip.Addr) NetworkScope {
	return referenceClassify(referenceLegacy(z), remote)
}

// Literal values the constructor would reject or canonicalize differently.
func awkwardLiterals() map[string]NetworkZones {
	many := make([]string, 300)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	return map[string]NetworkZones{
		"malformed":       {Model: configuredZoneModel, Revision: "lit1", Local: []string{"10.0.0.0/8", "not-a-prefix", "10.0.0.0/33"}, Internet: []string{"203.0.113.0/24", ""}},
		"conflicting":     {Model: configuredZoneModel, Revision: "lit2", Local: []string{"10.0.0.0/8"}, Internet: []string{"10.0.0.0/8"}},
		"oversize":        {Model: configuredZoneModel, Revision: "lit3", Local: many},
		"noncanonical":    {Model: configuredZoneModel, Revision: "lit4", Local: []string{"10.1.2.3/8", "192.168.7.7/16"}, Internet: []string{"203.0.113.77/24"}},
		"unsorted":        {Model: configuredZoneModel, Revision: "lit5", Local: []string{"192.168.0.0/16", "10.0.0.0/8"}, Internet: []string{"8.0.0.0/8", "1.0.0.0/8"}},
		"mapped-and-zone": {Model: configuredZoneModel, Revision: "lit6", Local: []string{"::ffff:10.0.0.0/104", "fe80::%eth0/64", "fd00::/8"}},
		"empty":           {},
		"nil-model":       {Local: []string{"10.0.0.0/8"}},
	}
}

func TestZonesViewLiteralsMatchReferenceClassify(t *testing.T) {
	for name, z := range awkwardLiterals() {
		if _, ok := z.matchedView(); ok {
			t.Fatalf("%s: literal must not have a view", name)
		}
		for _, r := range viewRemotes {
			remote := netip.MustParseAddr(r)
			if got, want := z.Classify(remote), referenceClassify(z, remote); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s:\n got %+v\nwant %+v", name, r, got, want)
			}
		}
		if got, want := z.Legacy(), referenceLegacy(z); !reflect.DeepEqual(stripView(got), stripView(want)) {
			t.Fatalf("%s Legacy differs:\n got %+v\nwant %+v", name, got, want)
		}
	}
}

func TestZonesViewAutomaticLiteralsMatchReferenceAndNeverPanic(t *testing.T) {
	for name, lit := range awkwardLiterals() {
		z := lit
		z.Model = AutomaticZoneModel
		z.Network = &NetworkSnapshot{State: "ready", NetNS: NetNS()}
		for _, r := range viewRemotes {
			remote := netip.MustParseAddr(r)
			got := z.Classify(remote) // must not panic for rejected prefix sets
			want := referenceAutomaticLegacyScope(lit, remote)
			if got.LegacyState != want.State || got.LegacyZone != want.Zone || got.LegacyRevision != want.Revision {
				t.Fatalf("%s %s legacy fields: got %+v want %+v", name, r, got, want)
			}
		}
	}
}

// Modified copies of constructed values take the reference path with their own
// texts, including non-canonical ones; the constructed original is unaffected.
func TestZonesViewModifiedCopyMatchesReference(t *testing.T) {
	z, _ := NewNetworkZones([]string{"10.0.0.0/8"}, []string{"203.0.113.0/24"})
	mutations := map[string]func(*NetworkZones){
		"append local":  func(c *NetworkZones) { c.Local = append(append([]string{}, c.Local...), "192.168.9.9/16") },
		"drop internet": func(c *NetworkZones) { c.Internet = nil },
		"reorder": func(c *NetworkZones) {
			c.Local = []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"}
		},
		"malformed replace": func(c *NetworkZones) { c.Local = []string{"garbage"} },
	}
	before := scopesOf(z)
	for name, mutate := range mutations {
		c := z
		mutate(&c)
		if _, ok := c.matchedView(); ok && !reflect.DeepEqual(c.Local, z.Local) {
			t.Fatalf("%s: stale view matched", name)
		}
		for _, r := range viewRemotes {
			remote := netip.MustParseAddr(r)
			if got, want := c.Classify(remote), referenceClassify(c, remote); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s: got %+v want %+v", name, r, got, want)
			}
		}
	}
	if !reflect.DeepEqual(scopesOf(z), before) {
		t.Fatal("original changed")
	}
}

// Constructed values classify identically through the view and the reference.
func TestZonesViewConstructedMatchesReference(t *testing.T) {
	for _, c := range viewConfigs() {
		z, err := NewNetworkZones(c[0], c[1])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := z.matchedView(); !ok {
			t.Fatal("constructed value must carry its view")
		}
		for _, r := range viewRemotes {
			remote := netip.MustParseAddr(r)
			if got, want := z.Classify(remote), referenceClassify(z, remote); !reflect.DeepEqual(got, want) {
				t.Fatalf("%v %s: got %+v want %+v", c, r, got, want)
			}
		}
		a := AutomaticNetworkZones(z, NetworkSnapshot{State: "ready", NetNS: NetNS()})
		for _, r := range viewRemotes {
			remote := netip.MustParseAddr(r)
			got, want := a.Classify(remote), referenceAutomaticLegacyScope(a, remote)
			if got.LegacyState != want.State || got.LegacyZone != want.Zone || got.LegacyRevision != want.Revision {
				t.Fatalf("automatic %v %s: got %+v want %+v", c, r, got, want)
			}
		}
	}
}

func stripView(z NetworkZones) NetworkZones { z.view = nil; return z }

func TestZonesViewPreservesChangedRevision(t *testing.T) {
	z := DefaultNetworkZones()
	z.Revision = "explicit-revision"
	for _, text := range []string{"127.0.0.1", "198.51.100.1", "::1"} {
		got := z.Classify(netip.MustParseAddr(text))
		if got.Revision != z.Revision {
			t.Fatal("stale configured revision", got)
		}
	}
}
