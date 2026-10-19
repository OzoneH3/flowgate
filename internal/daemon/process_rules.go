package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net"
	"time"
)

const ProcessRuleCapability = "process-instance-rules-v1"

type RuleTargetState struct {
	TargetScope string `json:"target_scope"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
}

func (e *Engine) targetStateLocked(r policy.Rule) RuleTargetState {
	if r.Preset != nil {
		scope := "application"
		if r.Filter.AllPrograms {
			scope = "system"
		}
		if !e.presetActive(r) {
			return RuleTargetState{scope, "inactive", "Preset identity/configuration changed or discovery expired; review refresh required"}
		}
		if r.Preset.Component == "dhcp" {
			return RuleTargetState{scope, "active", "Reviewed persistent interface-scoped DHCP protocol exception shared with boot guard; explicit removal in monitoring required"}
		}
		return RuleTargetState{scope, "active", presetSentence(r)}
	}
	if r.Filter.AllPrograms {
		model := "Legacy configured-prefix scope; automatic coverage is excluded until explicit migration"
		if r.Filter.ZoneModel == identity.AutomaticZoneModel {
			model = "Automatic peer scope follows network/registry revisions; classification itself grants no permission"
		}
		return RuleTargetState{"zone", "active", model + "; process/application tiers override; unsafe attribution still blocks"}
	}
	b := r.Filter.Process
	if b.IsZero() {
		return RuleTargetState{"application", "active", "Application/revision/UID rule, all process instances; enabled and expiry are separate"}
	}
	if b.Session != e.Generation {
		return RuleTargetState{"process", "inactive", "Daemon session ended; process rules never rebind after restart"}
	}
	h := e.processHandles[b]
	if h == nil {
		return RuleTargetState{"process", "inactive", "No pinned process lifetime in this daemon session"}
	}
	if err := h.Check(); err != nil {
		return RuleTargetState{"process", "inactive", err.Error()}
	}
	return RuleTargetState{"process", "active", "Pinned live native process instance; process tier before application fallback"}
}
func (e *Engine) RuleStates(uid uint32, admin bool) map[string]RuleTargetState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]RuleTargetState{}
	for _, r := range e.rules {
		if admin || r.Filter.AllUIDs || r.Filter.UID == uid {
			out[r.ID] = e.targetStateLocked(r)
		}
	}
	return out
}
func (e *Engine) activeRulesLocked(rules []policy.Rule) []policy.Rule {
	out := append([]policy.Rule{}, rules...)
	for i := range out {
		if (out[i].Preset != nil || !out[i].Filter.Process.IsZero()) && e.targetStateLocked(out[i]).State != "active" {
			out[i].Disabled = true
		}
		if out[i].Filter.InterfaceName != "" {
			iface, err := net.InterfaceByName(out[i].Filter.InterfaceName)
			if err != nil {
				out[i].Disabled = true
			} else {
				out[i].Filter.InterfaceIndex = uint32(iface.Index)
			}
		}
	}
	return out
}
func (e *Engine) evaluateLocked(rules []policy.Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	f.NetworkScope = e.Zones.ClassifyFlow(f)
	active := e.activeRulesLocked(rules)
	for i, r := range active {
		if r.Filter.PeerService != (policy.PeerService{}) && policy.ProtocolMatches(r.Filter.Protocol, f.Protocol) && f.Direction == r.Filter.Direction && f.Remote.Port() == r.Filter.RemotePort && f.Remote.Addr().String() == r.Filter.RemoteAddress && !e.peerServiceMatches(f, r.Filter.PeerService) {
			active[i].Disabled = true
		}
		if r.Preset != nil && r.Preset.Component == "dhcp" {
			active[i].Disabled = true
		}
	}
	return policy.EvaluateSession(active, f, a, now, e.Generation)
}
func (e *Engine) pruneHandlesLocked() {
	for b, h := range e.processHandles {
		found := false
		for _, p := range e.creationPreviews {
			if !p.Saved && p.View.Rule.Filter.Process == b {
				found = true
				break
			}
		}
		for _, r := range e.rules {
			if r.Filter.Process == b {
				found = true
				break
			}
		}
		if !found {
			h.Close()
			delete(e.processHandles, b)
		}
	}
}
func (e *Engine) CloseProcessTargets() {
	e.creationMu.Lock()
	defer e.creationMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, h := range e.processHandles {
		h.Close()
	}
	e.processHandles = nil

}
func processScope(d ObservedDraft) string {
	if d.TargetScope == "" {
		return "application"
	}
	return d.TargetScope
}
func validScope(d ObservedDraft) bool {
	return processScope(d) == "application" || processScope(d) == "process"
}
func (e *Engine) attachProcessTarget(current identity.Process, candidate *policy.Rule) (*identity.ProcessHandle, error) {
	for b, h := range e.processHandles {
		if b.Matches(current) && h.Check() == nil {
			candidate.Filter.Process = b
			candidate.Schema = 3
			return h, nil
		}
	}
	b, err := identity.BindInstance(e.Generation, current)
	if err != nil {
		return nil, mutationError("unsupported_process", err.Error())
	}
	b.ID = randomID()
	h, err := identity.PinInstance(b)
	if err != nil {
		return nil, mutationError("unsupported_process", err.Error())
	}
	if e.processHandles == nil {
		e.processHandles = map[identity.Instance]*identity.ProcessHandle{}
	}
	e.processHandles[b] = h
	candidate.Filter.Process = b
	candidate.Schema = 3
	return h, nil
}
func processLabel(b identity.Instance) string {
	return fmt.Sprintf("only process PID %d, start %s, boot %s, daemon session %s; no siblings/children; inactive on exit/identity change/session end", b.PID, b.Start, b.BootID, b.Session)
}

func (e *Engine) verifyProcessEditLocked(b identity.Instance) error {
	if e.Activity == nil {
		return mutationError("target_inactive", "Live Activity required for process edit")
	}
	s := e.Activity()
	id := fmt.Sprintf("%d:%s", b.PID, b.Start)
	p, ok := s.Processes[id]
	if !ok {
		return mutationError("target_inactive", "Process no longer observed")
	}
	for _, row := range s.Rows {
		if len(row.Owners) == 1 && row.Owners[0] == id && row.OwnershipCategory == "visible-holder" {
			current, err := e.verifyCreation(ObservedTarget{row.ID, id}, p, b.UID, true)
			if err != nil {
				continue // a sampled transient socket may already have closed; verify another exact current row
			}
			if !b.Matches(current) {
				return mutationError("target_inactive", "Process identity changed")
			}
			return nil
		}
	}
	return mutationError("unsupported_process", "No current exclusive native socket ownership for this process")
}
