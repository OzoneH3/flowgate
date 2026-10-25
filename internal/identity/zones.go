package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
)

// NetworkZones is immutable privileged configuration, not routing inference.
type NetworkZones struct {
	Model           string           `json:"model"`
	Revision        string           `json:"revision"`
	Local           []string         `json:"local_prefixes"`
	Internet        []string         `json:"internet_prefixes"`
	Reason          string           `json:"reason"`
	RegistryVersion string           `json:"registry_version,omitempty"`
	NetworkRevision string           `json:"network_revision,omitempty"`
	NetworkState    string           `json:"network_state,omitempty"`
	Network         *NetworkSnapshot `json:"network,omitempty"`
	// view is derived only from Model/Local/Internet by the constructors: the
	// configured-prefix revision and the parsed prefixes. It is private, never
	// serialized, never derived from network observations or routes, and is
	// used only while it still matches this value's own prefix texts; literal,
	// unmarshalled or modified values fall back to computing it on demand.
	view *legacyZoneView
}

// legacyZoneView is the immutable configured-prefix view of a zones value.
type legacyZoneView struct {
	revision        string
	localTexts      []string // canonical masked prefixes, same order as parsed
	internetTexts   []string
	local, internet []netip.Prefix
}

const configuredZoneModel = "configured-prefix-v1"
const configuredZoneReason = "Administrator-defined peer-prefix policy zones; not Internet connectivity or physical topology; no zone byte totals"

// matchedView returns the constructor's view only when it still describes this
// value's own prefix texts exactly. Any other value (literal, unmarshalled,
// modified, or one whose prefixes NewNetworkZones rejected) has no view and
// takes the original code paths unchanged.
func (z NetworkZones) matchedView() (*legacyZoneView, bool) {
	if v := z.view; v != nil && slices.Equal(v.localTexts, z.Local) && slices.Equal(v.internetTexts, z.Internet) {
		return v, true
	}
	return nil, false
}

// classify is the configured-prefix classification over the parsed view. Its
// result is identical to Classify on the equivalent constructed value: the
// view's texts are that value's canonical prefixes in the same order.
func (v *legacyZoneView) classify(remote netip.Addr) NetworkScope {
	out := NetworkScope{State: "unavailable", Revision: v.revision, Source: configuredZoneModel, Reason: "Peer has no explicitly configured zone membership"}
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
	for i, parts := range [][]netip.Prefix{v.local, v.internet} {
		texts := v.localTexts
		if i == 1 {
			texts = v.internetTexts
		}
		for j, p := range parts {
			if p.Contains(remote) && p.Bits() > bits {
				bits = p.Bits()
				out.State = "known"
				out.Zone = "local"
				if i == 1 {
					out.Zone = "internet"
				}
				out.Reason = "Longest matching administrator-configured prefix " + texts[j]
			}
		}
	}
	return out
}

func newLegacyZoneView(z NetworkZones) *legacyZoneView {
	v := &legacyZoneView{revision: z.Revision, localTexts: slices.Clone(z.Local), internetTexts: slices.Clone(z.Internet)}
	for _, t := range z.Local {
		v.local = append(v.local, netip.MustParsePrefix(t))
	}
	for _, t := range z.Internet {
		v.internet = append(v.internet, netip.MustParsePrefix(t))
	}
	return v
}

type NetworkScope struct {
	State          string `json:"state"`
	Zone           string `json:"zone,omitempty"`
	Revision       string `json:"revision"`
	Source         string `json:"source"`
	Reason         string `json:"reason"`
	Basis          string `json:"basis,omitempty"` // automatic or custom (explicit prefix) for known automatic scopes
	LegacyState    string `json:"legacy_state,omitempty"`
	LegacyZone     string `json:"legacy_zone,omitempty"`
	LegacyRevision string `json:"legacy_revision,omitempty"`
}

func NewNetworkZones(local, internet []string) (NetworkZones, error) {
	z := NetworkZones{Model: configuredZoneModel, Reason: configuredZoneReason, Local: []string{}, Internet: []string{}}
	seen := map[string]string{}
	for i, parts := range [][]string{append([]string{"127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10"}, local...), internet} {
		zone := "local"
		if i == 1 {
			zone = "internet"
		}
		for _, v := range parts {
			p, e := netip.ParsePrefix(v)
			if e != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				return z, fmt.Errorf("invalid zone prefix %q", v)
			}
			v = p.Masked().String()
			if old := seen[v]; old != "" {
				if old != zone {
					return z, fmt.Errorf("same prefix in conflicting zones: %s", v)
				}
				continue
			}
			seen[v] = zone
			if i == 0 {
				z.Local = append(z.Local, v)
			} else {
				z.Internet = append(z.Internet, v)
			}
		}
	}
	if len(z.Local)+len(z.Internet) > 256 {
		return z, fmt.Errorf("zone prefix limit256")
	}
	sort.Strings(z.Local)
	sort.Strings(z.Internet)
	b, _ := json.Marshal([]any{z.Model, z.Local, z.Internet})
	h := sha256.Sum256(b)
	z.Revision = hex.EncodeToString(h[:])
	z.view = newLegacyZoneView(z)
	return z, nil
}
func DefaultNetworkZones() NetworkZones { z, _ := NewNetworkZones(nil, nil); return z }
func (z NetworkZones) Classify(remote netip.Addr) NetworkScope {
	if z.Model == AutomaticZoneModel {
		return z.classifyAutomatic(remote)
	}
	if v, ok := z.matchedView(); ok {
		out := v.classify(remote)
		out.Revision = z.Revision
		return out
	}
	out := NetworkScope{State: "unavailable", Revision: z.Revision, Source: "configured-prefix-v1", Reason: "Peer has no explicitly configured zone membership"}
	remote = remote.Unmap().WithZone("")
	if !remote.IsValid() || remote.IsUnspecified() || remote.IsMulticast() || remote == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		out.Reason = "No classifiable unicast peer"
		return out
	}
	// These builtin local scopes cannot become Internet through a broader prefix.
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
func (z NetworkZones) SocketScope(s Socket) NetworkScope {
	if s.State == 10 && s.Protocol == "tcp" || s.Remote.Port() == 0 {
		o := z.Classify(netip.Addr{})
		o.Reason = "Listener/unconnected socket has no single peer zone; UDP totals may span peers"
		return o
	}
	return z.ClassifyFlow(Flow{Remote: s.Remote, Local: s.Local, NetNS: s.NetNS, Interface: s.Interface})
}
