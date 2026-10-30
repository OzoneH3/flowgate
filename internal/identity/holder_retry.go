package identity

import (
	diagnostics "flowgate/internal/serveprofile"
	"slices"
	"time"
)

// Only known topology changes may start a fresh complete observation. A new
// holder is never appended to a member set that was inspected earlier.
func holderTopologyChange(code string) bool {
	switch code {
	case "membership_changed", "table_changed", "group_changed", "descriptor_changed":
		return true
	}
	return false
}

func retryableHolderTopology(c HolderCensus, d HolderRecheck) bool {
	if !c.Complete {
		if len(c.Issues) == 0 {
			return false
		}
		for _, code := range c.Issues {
			if !holderTopologyChange(code) {
				return false
			}
		}
	}
	if d.Err != nil && (d.Err.Error() != "census_incomplete" || c.Complete) {
		return false
	}
	for _, code := range d.Groups {
		if !holderTopologyChange(code) {
			return false
		}
	}
	return !c.Complete || len(d.Groups) > 0 || len(d.Appeared) > 0 || len(d.Reconcilable) > 0
}

// holderSource is the /proc census provider; tests substitute a model so
// Resolve and ResolveBatch can be compared without a live kernel.
var holderSource = procHolders

func resolveHolderIdentities(wanted map[string]bool, inspect func(int) (Process, error), refresh func()) (HolderCensus, holderIdentities) {
	p := holderSource()
	lim := defaultHolderLimits
	return retryHolderIdentities(p.now, lim, refresh, func(b *holderBudget) (HolderCensus, holderIdentities) {
		c := p.censusBudget(wanted, lim, b)
		return c, inspectHolderIdentities(c, inspect)
	})
}

// Both Activity and Resolve discard a failed attempt in full. The second round
// re-enumerates every table and re-inspects every member. No deadline or scan
// counter is reset, and an identity/visibility failure is never retryable.
func retryHolderIdentities(now func() time.Time, lim holderLimits, refresh func(), attempt func(*holderBudget) (HolderCensus, holderIdentities)) (HolderCensus, holderIdentities) {
	budget := &holderBudget{deadline: now().Add(lim.Time)}
	var c HolderCensus
	var out holderIdentities
	var firstIssues []string
	expire := func() {
		out.Complete = false
		out.retryTopology = false
		if !slices.Contains(out.Issues, "time_limit") {
			out.Issues = append(out.Issues, "time_limit")
		}
		if out.SocketIssues == nil {
			out.SocketIssues = map[string]string{}
		}
		for socket := range out.Owners {
			out.SocketIssues[socket] = "time_limit"
		}
	}
	for n := 0; n < 2; n++ {
		if n > 0 && now().After(budget.deadline) {
			expire()
			return c, out
		}
		if n > 0 {
			diagnostics.Count(diagnostics.HolderRetry, 1)
		}
		c, out = attempt(budget)
		if !diagnostics.ObservationTime().IsZero() {
			if n == 0 {
				firstIssues = append([]string(nil), out.Issues...)
			}
			out.diagnosticAttempts = n + 1
			out.diagnosticFirstIssues = firstIssues
		}
		if now().After(budget.deadline) {
			expire()
			return c, out
		}
		if out.Complete || !out.retryTopology || n == 1 || budget.tasks >= lim.Tasks || budget.fds >= lim.FDs {
			return c, out
		}
		if refresh != nil {
			refresh()
		}
	}
	return c, out
}
