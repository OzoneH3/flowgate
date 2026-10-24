package policy

import (
	"flowgate/internal/identity"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// Network endpoint policy is explicit machine authority, independent of an
// application or the availability of attribution. Older rules never acquire it.
const NetworkEndpointSchema = 7
const NetworkEndpointPrecedence = "Explicit network endpoint rules run before application rules and unsafe-attribution refusal: matching endpoint Deny wins over endpoint Allow, then smaller rule ID. Endpoint Allow overrides application Deny/Ask for all matching userspace, kernel and unidentified traffic."

func (r Rule) validateNetworkEndpoint() error {
	f := r.Filter
	addr, err := netip.ParseAddr(f.RemoteAddress)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || addr.String() != f.RemoteAddress || !addr.IsGlobalUnicast() || addr.IsLoopback() {
		return fmt.Errorf("network endpoint requires one canonical non-loopback unicast IP")
	}
	expected := Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "tcp", RemoteAddress: f.RemoteAddress, RemotePort: f.RemotePort}
	if r.Schema != NetworkEndpointSchema || !r.NetworkEndpoint || r.ID == "" || r.Priority != 100 || f.RemotePort == 0 || f != expected || r.Preset != nil || r.Invocation != nil || r.Executable != "" || r.ShareWithRoot || r.RootApplication != "" || (r.Action != "allow" && r.Action != "block") {
		return fmt.Errorf("network endpoint requires explicit schema7 machine outgoing TCP IP/port scope, fixed priority and Allow/Deny only")
	}
	return nil
}

// EvaluateNetworkEndpoint never infers origin from a missing owner. The rule
// explicitly authorizes every matching flow regardless of attribution status.
func EvaluateNetworkEndpoint(rules []Rule, f identity.Flow, now time.Time) (string, string, []string) {
	if f.Direction != "outgoing" || f.Protocol != "tcp" || identity.IsLoopbackFlow(f) {
		return "", "", nil
	}
	matches := []Rule{}
	for _, r := range rules {
		if !r.NetworkEndpoint || r.Schema != NetworkEndpointSchema || r.Disabled || (!r.Expires.IsZero() && !now.Before(r.Expires)) || r.validateNetworkEndpoint() != nil {
			continue
		}
		if f.Remote.Addr().Unmap().String() == r.Filter.RemoteAddress && f.Remote.Port() == r.Filter.RemotePort {
			matches = append(matches, r)
		}
	}
	if len(matches) == 0 {
		return "", "", nil
	}
	sort.Slice(matches, func(i, j int) bool { return Precedes(matches[i], matches[j]) })
	ids := make([]string, len(matches))
	for i, r := range matches {
		ids[i] = r.ID
	}
	return matches[0].Action, matches[0].ID, ids
}
