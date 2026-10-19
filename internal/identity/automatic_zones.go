package identity

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/unix"
)

const AutomaticZoneModel = "automatic-peer-v1"

//go:embed data/iana-special.json
var registryJSON []byte

type registryRecord struct {
	Prefix   string `json:"prefix"`
	Name     string `json:"name"`
	Global   bool   `json:"global_reachable"`
	Local    bool   `json:"local"`
	Internet bool   `json:"internet"`
}

// overlayPrefixes are not IANA special blocks but carry a vendor overlay whose
// IPv4 side is RFC6598 shared space. They follow that Internet classification
// so one overlay peer cannot be Local on IPv6 and Internet on IPv4.
var overlayPrefixes = []struct{ Prefix, Name string }{{"fd7a:115c:a1e0::/48", "Tailscale IPv6 overlay"}}

var addressRegistry = func() struct {
	Version string           `json:"version"`
	Records []registryRecord `json:"records"`
} {
	var v struct {
		Version string           `json:"version"`
		Records []registryRecord `json:"records"`
	}
	if err := json.Unmarshal(registryJSON, &v); err != nil {
		panic(err)
	}
	return v
}()

func AutomaticNetworkZones(legacy NetworkZones, s NetworkSnapshot) NetworkZones {
	z := legacy
	z.Model = AutomaticZoneModel
	z.Network = &s
	z.RegistryVersion = addressRegistry.Version
	z.NetworkRevision = s.Revision
	z.NetworkState = s.State
	z.Reason = "Automatic peer scope: IANA private-use/ULA and local scopes; directly connected non-tunnel LAN; shared/CGNAT and overlay peers plus remaining globally reachable unicast Internet. Explicit prefixes are custom classification and override by longest match. Local is not trusted and grants no permission. No geolocation or connectivity claim."
	b, _ := json.Marshal([]any{z.Model, legacy.Revision, z.RegistryVersion, overlayPrefixes, s.Revision})
	h := sha256.Sum256(b)
	z.Revision = hex.EncodeToString(h[:])
	return z
}
func (z NetworkZones) Legacy() NetworkZones { v, _ := NewNetworkZones(z.Local, z.Internet); return v }
func tunnelLink(l NetworkLink) bool {
	switch l.Kind {
	case "tun", "wireguard", "ppp", "ipip", "sit", "gre", "gretap", "ip6gre", "ip6gretap", "ip6tnl", "vti", "vti6", "vxlan", "geneve":
		return true
	}
	return l.Flags&unix.IFF_POINTOPOINT != 0
}
func (s NetworkSnapshot) link(index uint32) NetworkLink {
	for _, l := range s.Links {
		if l.Index == index {
			return l
		}
	}
	return NetworkLink{}
}
func (s NetworkSnapshot) route(remote netip.Addr) *NetworkRoute {
	var best *NetworkRoute
	bits := -1
	for i := range s.Routes {
		r := &s.Routes[i]
		if r.Table != unix.RT_TABLE_MAIN && r.Table != unix.RT_TABLE_LOCAL {
			continue
		}
		p, e := netip.ParsePrefix(r.Prefix)
		if e != nil || !p.Contains(remote) {
			continue
		}
		if p.Bits() > bits || (p.Bits() == bits && best != nil && r.Priority < best.Priority) {
			best = r
			bits = p.Bits()
		}
	}
	return best
}
func (z NetworkZones) classifyAutomatic(remote netip.Addr) NetworkScope {
	legacy := z.Legacy().Classify(remote)
	out := NetworkScope{State: "unavailable", Revision: z.Revision, Source: AutomaticZoneModel, Reason: "No usable unicast peer", LegacyState: legacy.State, LegacyZone: legacy.Zone, LegacyRevision: legacy.Revision}
	remote = remote.Unmap().WithZone("")
	if !remote.IsValid() || remote.IsUnspecified() {
		return out
	}
	known := func(zone, reason string) NetworkScope {
		out.State = "known"
		out.Zone = zone
		out.Basis = "automatic"
		out.Reason = reason + "; classification grants no permission"
		return out
	}
	if remote.IsMulticast() {
		if remote.Is4() {
			if netip.MustParsePrefix("224.0.0.0/24").Contains(remote) || netip.MustParsePrefix("239.0.0.0/8").Contains(remote) {
				return known("local", "Link/administratively scoped IPv4 multicast")
			}
		} else {
			scope := remote.As16()[1] & 15
			if scope == 1 || scope == 2 || scope == 3 || scope == 4 || scope == 5 || scope == 8 {
				return known("local", fmt.Sprintf("Non-global IPv6 multicast scope %d", scope))
			}
		}
		out.Reason = "Global/reserved multicast is outside the unicast Internet/Local policy partition"
		return out
	}
	if remote == netip.MustParseAddr("255.255.255.255") {
		return known("local", "IPv4 limited broadcast")
	}
	// Existing configured prefixes, including protected loopback/link-local builtins,
	// take priority over automatic inference. New destinations need no manual entry.
	if legacy.State == "known" {
		if remote.IsLoopback() || remote.IsLinkLocalUnicast() {
			return known(legacy.Zone, legacy.Reason)
		}
		v := known(legacy.Zone, "Custom classification (explicit override): "+legacy.Reason)
		v.Basis = "custom"
		return v
	}
	// Shared/CGNAT and overlay peers use the public-address topology rule below:
	// Local only on a directly connected non-tunnel LAN, otherwise Internet.
	remoteKind, overlay := "Globally reachable unicast address", false
	for _, o := range overlayPrefixes {
		if netip.MustParsePrefix(o.Prefix).Contains(remote) {
			remoteKind, overlay = o.Name+" "+o.Prefix+" (same as its IPv4 shared-space peers; a custom Local prefix opts in)", true
		}
	}
	var record *registryRecord
	bits := -1
	for i := range addressRegistry.Records {
		r := &addressRegistry.Records[i]
		p, _ := netip.ParsePrefix(r.Prefix)
		if p.Contains(remote) && p.Bits() > bits {
			bits = p.Bits()
			record = r
		}
	}
	if overlay {
		// The overlay /48 lies inside ULA fc00::/7, which would otherwise be Local.
	} else if record != nil && record.Local {
		return known("local", "IANA "+record.Name+" "+record.Prefix+" (private scope, including routed VPN peers)")
	} else if record != nil && record.Internet {
		remoteKind = "IANA " + record.Name + " " + record.Prefix + " (routed shared/CGNAT peers are Internet, as in NetLimiter; a custom Local prefix opts in)"
	} else if record != nil && !record.Global {
		out.Reason = "IANA " + record.Name + " " + record.Prefix + " is not globally reachable; not inferred to be a trusted LAN"
		return out
	} else if remote.Is6() && record == nil && !netip.MustParsePrefix("2000::/3").Contains(remote) {
		out.Reason = "Unallocated/reserved IPv6 address space"
		return out
	}
	if z.Network == nil || z.Network.State != "ready" {
		out.Reason = "Network configuration unavailable; cannot exclude a directly connected public-address LAN"
		return out
	}
	s := z.Network
	r := s.route(remote)
	suffix := "; no matching route (classification is not reachability)"
	if r != nil {
		l := s.link(r.Interface)
		suffix = fmt.Sprintf("; route candidate %s table %d via %s %s", r.Prefix, r.Table, r.Gateway, l.Name)
	}
	for _, a := range s.Addresses {
		p, e := netip.ParsePrefix(a.Prefix)
		if e != nil || !p.Masked().Contains(remote) || p.Bits() == 0 || a.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		l := s.link(a.Interface)
		if l.Index == 0 || l.Flags&unix.IFF_UP == 0 || tunnelLink(l) {
			continue
		}
		if r == nil {
			out.Reason = "Public-address LAN prefix has no agreeing connected route; scope unavailable during route changes"
			return out
		}
		if r.Options != "" {
			out.Reason = "Public-address LAN has multipath/source-specific routing; remote-only scope cannot select a safe path"
			return out
		}
		if r.Interface != l.Index || r.Gateway != "" || r.Type != unix.RTN_UNICAST && r.Type != unix.RTN_LOCAL {
			continue
		}
		// Remote-only scope must not guess a marked/source-specific policy path.
		// Alternative tables can supersede the main-table connected route.
		for _, alternate := range s.Routes {
			p, err := netip.ParsePrefix(alternate.Prefix)
			if err != nil || !p.Contains(remote) || alternate.Table == unix.RT_TABLE_MAIN || alternate.Table == unix.RT_TABLE_LOCAL || alternate.Type == unix.RTN_THROW {
				continue
			}
			if alternate.Interface != l.Index || alternate.Gateway != "" || alternate.Options != "" || alternate.Type != unix.RTN_UNICAST && alternate.Type != unix.RTN_LOCAL {
				out.Reason = "Public-address LAN overlaps an alternative policy-routing table; remote-only scope cannot safely select a marked/source-specific route"
				return out
			}
		}
		return known("local", fmt.Sprintf("Directly connected non-tunnel LAN prefix %s on %s", p.Masked(), l.Name)+suffix)
	}
	return known("internet", remoteKind+"; tunnel/default-route use does not make it Local"+suffix)
}
func (z NetworkZones) ClassifyFlow(f Flow) NetworkScope {
	if z.Model == AutomaticZoneModel && z.Network != nil && f.NetNS != "" && f.NetNS != z.Network.NetNS {
		return NetworkScope{State: "unavailable", Source: AutomaticZoneModel, Revision: z.Revision, Reason: "Flow belongs to a different network namespace; host topology is not applicable"}
	}
	return z.Classify(f.Remote.Addr())
}
func (z NetworkZones) Boundaries() []netip.Prefix {
	texts := append(append([]string{}, z.Local...), z.Internet...)
	texts = append(texts, "0.0.0.0/32", "255.255.255.255/32", "224.0.0.0/4", "::/128", "ff00::/8", "2000::/3")
	if z.Model == AutomaticZoneModel {
		for _, r := range addressRegistry.Records {
			texts = append(texts, r.Prefix)
		}
		for _, o := range overlayPrefixes {
			texts = append(texts, o.Prefix)
		}
		texts = append(texts, "224.0.0.0/24", "239.0.0.0/8")
		for flags := 0; flags < 16; flags++ {
			for _, scope := range []int{1, 2, 3, 4, 5, 8} {
				texts = append(texts, fmt.Sprintf("ff%02x::/16", flags*16+scope))
			}
		}
		if z.Network != nil {
			for _, a := range z.Network.Addresses {
				texts = append(texts, a.Prefix)
			}
			for _, r := range z.Network.Routes {
				texts = append(texts, r.Prefix)
			}
		}
	}
	out := []netip.Prefix{}
	for _, v := range texts {
		if p, e := netip.ParsePrefix(strings.TrimSpace(v)); e == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
