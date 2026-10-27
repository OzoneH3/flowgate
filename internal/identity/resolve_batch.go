package identity

import (
	"fmt"

	diagnostics "flowgate/internal/serveprofile"
)

// MaxResolveBatch bounds one shared discovery pass. Callers that need more
// must run further passes; the bound keeps one census's wanted set small.
const MaxResolveBatch = 8

// ResolveBatch attributes up to MaxResolveBatch flows with ONE full socket dump,
// ONE shared holder census (which may itself retry once) and ONE recheck dump,
// instead of one of each per flow. Every flow is finalised with the identical
// decision Resolve applies, restricted to that flow's own receiver sockets.
//
// It is a discovery aid: results are hints for candidate selection and never
// binding or permission authority; the caller must re-prove before acting.
// Differences from calling Resolve per flow are deliberate and visible:
//   - all flows share one full dump (Resolve uses a port-filtered dump for
//     concrete UDP; the competitor set is the same, the cost profile differs);
//   - census completeness, retry and time/FD/task budgets are shared, so one
//     flow's inspection failure can make every flow of the batch incomplete
//     (conservative: never less strict than Resolve);
//   - the recheck dump is shared, so "listener changed" is judged per flow on
//     the same snapshot.
//
// Output is positional: out[i] belongs to flows[i]. An empty input performs no
// dump and no census; more than MaxResolveBatch inputs are refused as a whole.
func ResolveBatch(flows []Flow) []Attribution {
	out := make([]Attribution, len(flows))
	for i := range out {
		out[i] = Attribution{Status: "unidentified", Reason: "no visible matching socket", ReasonCode: ReasonNoSocketObserved}
	}
	if len(flows) == 0 {
		return out
	}
	if len(flows) > MaxResolveBatch {
		// Refused as a whole, positionally, before any dump or census. The reply
		// mirrors the caller's own input length; no other memory is bounded here.
		for i := range out {
			out[i].setReason(ReasonSocketCensusUnavailable, fmt.Sprintf("discovery batch exceeds %d flows", MaxResolveBatch))
		}
		return out
	}
	defer diagnostics.Begin(diagnostics.FullResolve).End()
	ns := NetNS()
	var local []int
	for i, f := range flows {
		if f.NetNS != ns {
			out[i].setReason(ReasonNamespaceMismatch, "foreign network namespace is outside this observer")
			continue
		}
		local = append(local, i)
	}
	if len(local) == 0 {
		return out
	}
	sockets, e := socketDumps.full()
	if e != nil {
		for _, i := range local {
			out[i].setReason(ReasonSocketCensusUnavailable, "socket diagnostics unavailable: "+e.Error())
		}
		return out
	}
	wanted := make([]map[string]bool, len(flows))
	union := map[string]bool{}
	var pending []int
	for _, i := range local {
		w := map[string]bool{}
		for _, s := range receivers(sockets, flows[i]) {
			out[i].Sockets = append(out[i].Sockets, s)
			k := fmt.Sprintf("socket:[%d]", s.Inode)
			w[k] = true
			union[k] = true
		}
		if len(w) == 0 {
			continue // no receiver: Resolve returns here without a census
		}
		wanted[i] = w
		pending = append(pending, i)
	}
	if len(pending) == 0 {
		return out
	}
	_, resolved := resolveHolderIdentities(union, inspectWithProvenance, nil)
	// Owners are evidence recorded per flow BEFORE the recheck, restricted to that
	// flow's sockets, exactly as Resolve does for its single flow.
	covered := make([]int, len(flows))
	for _, i := range pending {
		mine := map[string][]Process{}
		for k := range wanted[i] {
			if ps, ok := resolved.Owners[k]; ok {
				mine[k] = ps
			}
		}
		covered[i] = collectOwners(&out[i], wanted[i], mine)
	}
	again, err := socketDumps.full()
	for _, i := range pending {
		if err != nil {
			out[i].setReason(ReasonSocketCensusUnavailable, "socket recheck unavailable")
			continue
		}
		finalizeAttribution(&out[i], wanted[i], covered[i], !resolved.Complete, receivers(again, flows[i]))
	}
	return out
}
