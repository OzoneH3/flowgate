package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"sort"
	"time"
)

type ProcessPolicy struct {
	ZoneFallbackRuleIDs []string          `json:"zone_fallback_rule_ids"`
	Ref                 string            `json:"ref"`
	ProcessID           string            `json:"process_id"`
	ApplicationRef      string            `json:"application_ref"`
	Target              identity.Instance `json:"target"`
	State               string            `json:"state"`
	Reason              string            `json:"reason"`
	Incoming            DirectionPolicy   `json:"incoming"`
	Outgoing            DirectionPolicy   `json:"outgoing"`
	ApplicationIncoming DirectionPolicy   `json:"application_incoming"`
	ApplicationOutgoing DirectionPolicy   `json:"application_outgoing"`
	Precedence          string            `json:"precedence"`
}

func (e *Engine) ruleRefLocked(r policy.Rule, now time.Time) PolicyRuleRef {
	v := ruleRef(r, now)
	v.Kind = ruleKind(r.Filter)
	state := e.targetStateLocked(r)
	v.TargetScope = state.TargetScope
	v.TargetState = state.State
	v.TargetReason = state.Reason
	v.Active = v.Active && state.State == "active"
	return v
}
func (e *Engine) processSummaryLocked(a PolicyIdentity, b identity.Instance, direction string, h *EnforcementStatus, rules []policy.Rule, now time.Time, state RuleTargetState) DirectionPolicy {
	selected := []policy.Rule{}
	original := []policy.Rule{}
	for _, r := range rules {
		if r.Filter.Process == b && r.Filter.Direction == direction {
			original = append(original, r)
			r.Filter.Process = identity.Instance{}
			if state.State != "active" {
				r.Disabled = true
			}
			selected = append(selected, r)
		}
	}
	out := summaryFor(a, direction, e.Mode, h, selected, now)
	out.Rules = []PolicyRuleRef{}
	out.Active = 0
	out.Disabled = 0
	out.Expired = 0
	for _, r := range original {
		v := e.ruleRefLocked(r, now)
		out.Rules = append(out.Rules, v)
		if v.Disabled {
			out.Disabled++
		}
		if v.Expired {
			out.Expired++
		}
		if v.Active {
			out.Active++
		}
	}
	if len(original) > 0 && state.State != "active" {
		out.Configured = "inactive_only"
		out.Action = ""
		out.Reason = "Process target inactive: " + state.Reason + "; application fallback remains separate"
	}
	return out
}
func (e *Engine) processViewsLocked(activity identity.ActivitySnapshot, rules []policy.Rule, h *EnforcementStatus, now time.Time) ([]ProcessPolicy, bool) {
	targets := map[identity.Instance]PolicyIdentity{}
	states := map[identity.Instance]RuleTargetState{}
	for _, r := range rules {
		if !r.Filter.Process.IsZero() {
			b := r.Filter.Process
			targets[b] = PolicyIdentity{r.Filter.Application, r.Filter.Revision, r.Filter.UID}
			states[b] = e.targetStateLocked(r)
		}
	}
	if activity.Error == "" && !activity.Collected.IsZero() && now.Sub(activity.Collected) <= 45*time.Second {
		for _, row := range activity.Rows {
			if row.HolderWitness != "" || len(row.Owners) != 1 || row.OwnershipCategory != "visible-holder" {
				continue
			}
			p, ok := activity.Processes[row.Owners[0]]
			if !ok || p.ThreadGroup != 0 || !identity.LiveRuleable(p.Application) {
				continue
			}
			b := identity.Instance{Session: e.Generation, BootID: p.BootID, PID: p.PID, Start: p.Start, UID: p.UID, NetNS: p.NetNS, MountNS: p.MountNS, PIDNS: p.PIDNS, Executable: p.Executable, Revision: p.Application.Revision}
			if p.ExecutableRevision != p.Application.Revision {
				b.ExecutableRevision = p.ExecutableRevision // the runtime file; the bundle is the application
			}
			if b.BootID == "" || b.NetNS == "" || b.MountNS == "" || b.PIDNS == "" || b.Start == "" || b.Check() != nil {
				continue
			}
			// Reuse a server-pinned instance when one exists; otherwise metadata alone
			// advertises a live candidate and still cannot authorize creation.
			for existing, handle := range e.processHandles {
				candidate := b
				candidate.ID = existing.ID
				if candidate == existing && handle.Check() == nil {
					b = existing
					break
				}
			}
			targets[b] = PolicyIdentity{p.Application.Key, p.Application.Revision, p.UID}
			states[b] = RuleTargetState{"process", "active", "Current supported native Activity process; preview must still verify exclusive ownership and pin its lifetime"}
		}
	}
	ordered := make([]identity.Instance, 0, len(targets))
	for b := range targets {
		ordered = append(ordered, b)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].PID != ordered[j].PID {
			return ordered[i].PID < ordered[j].PID
		}
		return ordered[i].ID < ordered[j].ID
	})
	out := []ProcessPolicy{}
	complete := len(ordered) <= 256
	for _, b := range ordered {
		if len(out) >= 256 {
			break
		}
		a := targets[b]
		s := states[b]
		ref := b.ID
		if ref == "" {
			ref = fmt.Sprintf("observed:%s:%d:%s", e.Generation, b.PID, b.Start)
		}
		out = append(out, ProcessPolicy{ZoneFallbackRuleIDs: zoneFallbackIDs(rules, a.UID), Ref: ref, ProcessID: fmt.Sprintf("%d:%s", b.PID, b.Start), ApplicationRef: appPolicyRef(a), Target: b, State: s.State, Reason: s.Reason, Incoming: e.processSummaryLocked(a, b, "incoming", h, rules, now, s), Outgoing: e.processSummaryLocked(a, b, "outgoing", h, rules, now, s), ApplicationIncoming: summaryFor(a, "incoming", e.Mode, h, rules, now), ApplicationOutgoing: summaryFor(a, "outgoing", e.Mode, h, rules, now), Precedence: "matching-process-before-application-before-zone"})
	}
	return out, complete
}
func (e *Engine) RuleInventory(uid uint32, admin bool) ([]policy.Rule, map[string]RuleTargetState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rules := []policy.Rule{}
	states := map[string]RuleTargetState{}
	for _, r := range e.rules {
		if admin || r.Filter.AllUIDs || r.Filter.UID == uid {
			rules = append(rules, r)
			states[r.ID] = e.targetStateLocked(r)
		}
	}
	return rules, states
}
