package policy

import "flowgate/internal/identity"

// FlowCandidates discards only immutable direction/protocol/port mismatches,
// before expensive target and interface validation. It is not authorization.
// All rules in the same ProgramScope agree on these fields, including disabled
// or expired replacements; filtering cannot revive an older program setting.
// Endpoint rules have a separate evaluator and are always retained.
func FlowCandidates(rules []Rule, f identity.Flow) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		x := r.Filter
		if !r.NetworkEndpoint && (x.Direction != f.Direction || !ProtocolMatches(x.Protocol, f.Protocol) ||
			(x.LocalPort != 0 && x.LocalPort != f.Local.Port()) || (x.RemotePort != 0 && x.RemotePort != f.Remote.Port())) {
			continue
		}
		out = append(out, r)
	}
	return out
}
