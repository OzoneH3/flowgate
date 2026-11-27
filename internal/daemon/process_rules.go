package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"net"
	"reflect"
	"time"
)

const ProcessRuleCapability = "process-instance-rules-v1"

type RuleTargetState struct {
	TargetScope string `json:"target_scope"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
}

func (e *Engine) targetStateLocked(r policy.Rule) RuleTargetState {
	if r.NetworkEndpoint {
		return RuleTargetState{"network-endpoint", "active", policy.NetworkEndpointPrecedence + " Existing admitted TCP may continue after removal or expiry."}
	}
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
		if r.RootApplication != "" {
			return RuleTargetState{"application", "active", "Saved native executable/revision rule shared between its user and root (UID 0); other users remain separate"}
		}
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
	return e.activeRulesWithLinksLocked(rules, net.Interfaces)
}

func (e *Engine) activeRulesWithLinksLocked(rules []policy.Rule, lookup func() ([]net.Interface, error)) []policy.Rule {
	out := append([]policy.Rule{}, rules...)
	for i := range out {
		if (out[i].Preset != nil || !out[i].Filter.Process.IsZero()) && e.targetStateLocked(out[i]).State != "active" {
			out[i].Disabled = true
		}
	}
	resolveRuleInterfaces(out, lookup)
	return out
}

// Resolve interface names from one fresh link snapshot for this evaluation only.
// A failed snapshot disables all name-scoped rules for this evaluation. No result
// survives into another packet evaluation or policy read. Stored rules stay intact.
func resolveRuleInterfaces(rules []policy.Rule, lookup func() ([]net.Interface, error)) {
	var indices map[string]uint32
	for i := range rules {
		name := rules[i].Filter.InterfaceName
		if name == "" {
			continue
		}
		if indices == nil {
			indices = make(map[string]uint32)
			interfaces, err := lookup()
			if err == nil {
				for _, iface := range interfaces {
					if iface.Index > 0 {
						indices[iface.Name] = uint32(iface.Index)
					}
				}
			}
		}
		if index := indices[name]; index != 0 {
			rules[i].Filter.InterfaceIndex = index
		} else {
			rules[i].Disabled = true
		}
	}
}
func (e *Engine) evaluateLocked(rules []policy.Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	f.NetworkScope = e.Zones.ClassifyFlow(f)
	return e.evaluateClassifiedLocked(rules, f, a, now)
}

// evaluateClassifiedLocked is evaluateLocked for a flow value the caller has
// already classified within the same locked decision.
func (e *Engine) evaluateClassifiedLocked(rules []policy.Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	action, rule, conflicts, _ := e.evaluateClassifiedLinkLocked(rules, f, a, now, nil)
	return action, rule, conflicts
}

// The fourth result proves a non-loopback device for this packet only. The peer
// resolver can skip its duplicate kernel link query on that same observation.
type packetLinkObservation struct{ loopback, known bool }

func (e *Engine) evaluateClassifiedLinkLocked(rules []policy.Rule, f identity.Flow, a identity.Attribution, now time.Time, link *packetLinkObservation) (string, string, []string, bool) {
	defer diagnostics.Begin(diagnostics.PolicyEvaluate).End()
	// Do not validate process/preset targets and resolve interfaces for scopes
	// which cannot match this packet. Equal program scopes share these fields,
	// so newest-setting/disabled-setting precedence is preserved.
	rules = policy.FlowCandidates(rules, f)
	var links []net.Interface
	linksOK := false
	active := e.activeRulesWithLinksLocked(rules, func() ([]net.Interface, error) {
		var err error
		links, err = identity.InterfacesForFlow(f)
		linksOK = err == nil
		return links, err
	})
	for i, r := range active {
		if r.Filter.PeerService != (policy.PeerService{}) && policy.ProtocolMatches(r.Filter.Protocol, f.Protocol) && f.Direction == r.Filter.Direction && f.Remote.Port() == r.Filter.RemotePort && f.Remote.Addr().String() == r.Filter.RemoteAddress && !e.peerServiceMatches(f, r.Filter.PeerService) {
			active[i].Disabled = true
		}
		if r.Preset != nil && r.Preset.Component == "dhcp" {
			active[i].Disabled = true
		}
	}
	nonLoopback := false
	action, rule, conflicts := policy.EvaluateSessionObserved(active, f, a, now, e.Generation, func(f identity.Flow) bool {
		var device, known bool
		if linksOK {
			device, known = identity.LoopbackDeviceOnInterfaces(f, links)
		} else if link != nil {
			device, known = link.loopback, link.known
		} else {
			device, known = observeLoopbackDevice(f)
		}
		nonLoopback = known && !device
		return identity.IsLoopbackFlowOnDevice(f, device)
	})
	return action, rule, conflicts, nonLoopback
}

var observeLoopbackDevice = identity.ObserveLoopbackDevice

func (e *Engine) pruneHandlesLocked() {
	for b, h := range e.processHandles {
		found := false
		for _, p := range e.creationPreviews {
			if p.View.Rule.Filter.Process == b {
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

// Release the engine lock for the Activity/socket census, then reject any
// concurrent policy/network change before callers reuse their captured rule/index.
func (e *Engine) verifyProcessEditLocked(b identity.Instance) error {
	rules := append([]policy.Rule(nil), e.rules...)
	generation, zoneRevision := e.Generation, e.Zones.Revision
	prefetched, sink := e.prefetched, e.settledSink
	e.prefetched, e.settledSink = nil, nil
	e.mu.Unlock()
	err := e.verifyProcessEdit(b)
	e.mu.Lock()
	e.prefetched, e.settledSink = prefetched, sink
	if generation != e.Generation || zoneRevision != e.Zones.Revision || !reflect.DeepEqual(rules, e.rules) {
		return mutationError("version_conflict", "Policy or network changed during process verification; retry")
	}
	if err != nil {
		return err
	}
	h := e.processHandles[b]
	if h == nil || h.Check() != nil {
		return mutationError("target_inactive", "Pinned process ended during verification")
	}
	return nil
}

func (e *Engine) verifyProcessEdit(b identity.Instance) error {
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
