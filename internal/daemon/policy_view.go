package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const PolicyExplanationCapability = "policy-explanations-v1"

type PolicyIdentity struct {
	Key      string `json:"key"`
	Revision string `json:"revision"`
	UID      uint32 `json:"uid"`
}
type PolicyRuleRef struct {
	TargetScope  string        `json:"target_scope"`
	TargetState  string        `json:"target_state"`
	TargetReason string        `json:"target_reason"`
	ID           string        `json:"id"`
	Version      string        `json:"version"` // exact decimal uint64; never JSON floating point
	Action       string        `json:"action"`
	Priority     int           `json:"priority"`
	Scope        policy.Filter `json:"scope"`
	Disabled     bool          `json:"disabled"`
	Expired      bool          `json:"expired"`
	Active       bool          `json:"active"`
	Expires      time.Time     `json:"expires"`
}
type PolicyDefault struct {
	Known  bool   `json:"known"`
	Action string `json:"action,omitempty"`
	Reason string `json:"reason"`
}
type PolicyCoverage struct {
	State   string `json:"state"`
	Covered bool   `json:"covered"`
	Reason  string `json:"reason"`
}
type DirectionPolicy struct {
	Direction          string          `json:"direction"`
	Configured         string          `json:"configured"`       // absent, inactive_only, scoped, mixed, uniform
	Action             string          `json:"action,omitempty"` // only a proven uniform action
	Reason             string          `json:"reason"`
	Rules              []PolicyRuleRef `json:"rules"`
	Active             int             `json:"active_rules"`
	Disabled           int             `json:"disabled_rules"`
	Expired            int             `json:"expired_rules"`
	OverlappingActions bool            `json:"potential_overlapping_actions"`
	Default            PolicyDefault   `json:"configured_default"`
	RuntimeDefault     PolicyDefault   `json:"runtime_default"`
	Enforcement        PolicyCoverage  `json:"enforcement"`
}
type ApplicationPolicy struct {
	ZoneFallbackRuleIDs []string        `json:"zone_fallback_rule_ids"`
	Ref                 string          `json:"ref"`
	Identity            PolicyIdentity  `json:"identity"`
	ProcessIDs          []string        `json:"process_ids"`
	Incoming            DirectionPolicy `json:"incoming"`
	Outgoing            DirectionPolicy `json:"outgoing"`
}
type PolicyAssociation struct {
	RowID             string `json:"row_id"`
	Status            string `json:"status"`
	Reason            string `json:"reason"`
	ApplicationRef    string `json:"application_ref,omitempty"`
	DecisionAuthority bool   `json:"decision_authority"`
}
type PolicySnapshot struct {
	Generation  string     `json:"generation"`
	Token       string     `json:"token"`
	Sequence    string     `json:"sequence"`
	EvaluatedAt time.Time  `json:"evaluated_at"`
	ValidUntil  *time.Time `json:"valid_until,omitempty"` // next visible rule expiry, not a lease
	Meaning     string     `json:"meaning"`
}
type PolicyView struct {
	NetworkZones      identity.NetworkZones `json:"network_zones"`
	Zones             []ZonePolicy          `json:"zones"`
	Processes         []ProcessPolicy       `json:"processes"`
	Snapshot          PolicySnapshot        `json:"snapshot"`
	ActivitySequence  string                `json:"activity_sequence"`
	ActivityCollected time.Time             `json:"activity_collected"`
	ActivityAvailable bool                  `json:"activity_available"`
	Complete          bool                  `json:"complete"`
	Reason            string                `json:"reason,omitempty"`
	Applications      []ApplicationPolicy   `json:"applications"`
	Rows              []PolicyAssociation   `json:"rows"`
}
type PolicyExplanation struct {
	EventID            string          `json:"event_id"`
	Status             string          `json:"status"`
	Reason             string          `json:"reason"`
	Flow               *identity.Flow  `json:"flow,omitempty"`
	Identity           *PolicyIdentity `json:"identity,omitempty"`
	ConfiguredAction   string          `json:"configured_action,omitempty"`
	SelectedRule       string          `json:"selected_rule,omitempty"`
	Matching           []PolicyRuleRef `json:"matching_rules,omitempty"`
	Enforcement        PolicyCoverage  `json:"enforcement"`
	RuntimeDefault     PolicyDefault   `json:"runtime_default"`
	HistoricalDecision bool            `json:"historical_decision"`
}
type PolicyExplanations struct {
	Snapshot PolicySnapshot      `json:"snapshot"`
	Contexts []PolicyExplanation `json:"contexts"`
}

func ruleRef(r policy.Rule, now time.Time) PolicyRuleRef {
	expired := !r.Expires.IsZero() && !now.Before(r.Expires)
	return PolicyRuleRef{TargetScope: "application", TargetState: "active", TargetReason: "Application/revision/UID rule; enabled/expiry are separate", ID: r.ID, Version: strconv.FormatUint(r.Version, 10), Action: r.Action, Priority: r.Priority, Scope: r.Filter, Disabled: r.Disabled, Expired: expired, Active: !r.Disabled && !expired, Expires: r.Expires}
}
func appPolicyRef(a PolicyIdentity) string {
	b, _ := json.Marshal(a)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ask is not inferred from a missing inventory entry: ask the actual pure
// evaluator about supported, rule-free contexts. Different protocol defaults
// would require more context rather than a fabricated application-wide default.
func evaluatorDefault(direction string) PolicyDefault {
	a := identity.Attribution{Application: &identity.Application{Key: "default-context", Revision: "default-context"}, Owners: []identity.Process{{UID: 0}}}
	action := ""
	for _, protocol := range []string{"tcp", "udp"} {
		next, _, _ := policy.Evaluate(nil, identity.Flow{Direction: direction, Protocol: protocol}, a, time.Time{})
		if action != "" && next != action {
			return PolicyDefault{Reason: "Protocol-specific evaluator defaults require context"}
		}
		action = next
	}
	return PolicyDefault{true, action, "Pure evaluator default for supported attribution without active matches; unsafe attribution is evaluated separately. Not a connection outcome"}
}
func coverage(mode, direction string, h *EnforcementStatus) (PolicyCoverage, PolicyDefault) {
	c := PolicyCoverage{State: "unknown", Reason: "No interception health/profile evidence"}
	d := PolicyDefault{Reason: "No active profile default is established"}
	if mode == "host-monitor" || (mode == "daemon-monitor" && (h == nil || h.State != "active")) {
		c.State = "stopped"
		c.Reason = "Observation/stored policy only; no application enforcement"
		return c, d
	}
	if h == nil {
		return c, d
	}
	if h.State != "active" {
		c.State = h.State
		c.Reason = "Interception is not confirmed active; configured rules are not an effective verdict"
		return c, d
	}
	if mode != "host-enforcement" && mode != "daemon-monitor" {
		return c, d
	}
	if h.Profile != "incoming" && h.Profile != "both" {
		c.Reason = "Unsupported or missing enforcement profile"
		return c, d
	}
	if direction == "outgoing" && h.Profile == "incoming" {
		c.State = "bypassed"
		c.Reason = "Incoming-only profile permits new outgoing traffic without application policy"
		d = PolicyDefault{true, "allow", "Profile bypass, not a stored application rule"}
		return c, d
	}
	c = PolicyCoverage{"active", true, "Profile covers new attributable TCP/UDP initiations; existing admission, bootstrap exceptions and other firewalls are separate"}
	d = evaluatorDefault(direction)
	return c, d
}
func summaryFor(a PolicyIdentity, direction, mode string, h *EnforcementStatus, rules []policy.Rule, now time.Time) DirectionPolicy {
	c, d := coverage(mode, direction, h)
	out := DirectionPolicy{Direction: direction, Configured: "absent", Reason: "No explicit stored rule for this application/revision/UID and direction", Rules: []PolicyRuleRef{}, Default: evaluatorDefault(direction), RuntimeDefault: d, Enforcement: c}
	actions := map[string]bool{}
	broad := map[string]bool{}
	active := []policy.Rule{}
	for _, r := range rules {
		f := r.Filter
		if !f.Process.IsZero() || f.AllPrograms {
			continue
		}
		if f.Application != a.Key || f.Revision != a.Revision || f.UID != a.UID || f.Direction != direction {
			continue
		}
		ref := ruleRef(r, now)
		out.Rules = append(out.Rules, ref)
		if ref.Disabled {
			out.Disabled++
		}
		if ref.Expired {
			out.Expired++
		}
		if !ref.Active {
			continue
		}
		out.Active++
		actions[r.Action] = true
		active = append(active, r)
		if f.NetworkZone == "" && f.Remote == "" && (f.RemoteAddress == "" || f.RemoteAddress == "*") && f.LocalPort == 0 && f.RemotePort == 0 {
			broad[f.Protocol] = true
			if f.Protocol == "*" {
				broad["tcp"], broad["udp"] = true, true
			}
		}
	}
	if len(out.Rules) == 0 {
		return out
	}
	switch {
	case out.Active == 0:
		out.Configured = "inactive_only"
		out.Reason = "Only disabled or expired rules; they do not participate in matching"
	case len(actions) > 1:
		out.Configured = "mixed"
		out.Reason = "Different configured actions across scopes; a concrete protocol/endpoints context is needed. Mixed does not itself prove an overlap"
	case broad["tcp"] && broad["udp"]:
		out.Configured = "uniform"
		for action := range actions {
			out.Action = action
		}
		out.Reason = "All active actions agree and unrestricted rules cover both TCP and UDP for this exact application identity/direction; not evidence of actual admission"
	default:
		out.Configured = "scoped"
		out.Reason = "Configured rules cover only selected protocols/endpoints; no whole-application action is asserted"
	}
	for i, r := range active {
		for _, other := range active[i+1:] {
			if r.Action != other.Action && filtersOverlap(r.Filter, other.Filter) {
				out.OverlappingActions = true
			}
		}
	}
	return out
}

// snapshotLocked captures one coherent authorized policy. Sequence orders read
// responses only; it is not a new policy version or a mutation precondition.
func (e *Engine) snapshotLocked(uid uint32, admin bool, h *EnforcementStatus, expected string) (PolicySnapshot, []policy.Rule, error) {
	now := e.Now()
	rules := []policy.Rule{}
	for _, r := range e.rules {
		if admin || r.Filter.AllUIDs || r.Filter.UID == uid {
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	refs := make([]PolicyRuleRef, 0, len(rules))
	var expiry *time.Time
	for _, r := range rules {
		refs = append(refs, e.ruleRefLocked(r, now))
		if now.Before(r.Expires) && (expiry == nil || r.Expires.Before(*expiry)) {
			t := r.Expires
			expiry = &t
		}
	}
	// Hash only authorized policy: foreign edits must not leak through a token.
	state, profile := "unknown", ""
	if h != nil {
		state, profile = h.State, h.Profile
	}
	encoded, _ := json.Marshal(struct {
		Generation, Mode, State, Profile, ZoneRevision string
		UID                                            uint32
		Admin                                          bool
		Rules                                          []PolicyRuleRef
	}{e.Generation, e.Mode, state, profile, e.Zones.Revision, uid, admin, refs})
	if len(encoded) > 256*1024 {
		return PolicySnapshot{}, nil, mutationError("limit_exceeded", "Policy metadata exceeds bounded explanation size")
	}
	sum := sha256.Sum256(encoded)
	token := hex.EncodeToString(sum[:])
	if expected != "" && expected != token {
		return PolicySnapshot{}, nil, mutationError("policy_conflict", "Policy/expiry/profile changed; fetch a fresh explanation")
	}
	if e.policyReadSequence == ^uint64(0) {
		return PolicySnapshot{}, nil, mutationError("unavailable", "Policy response sequence exhausted")
	}
	e.policyReadSequence++
	return PolicySnapshot{e.Generation, token, strconv.FormatUint(e.policyReadSequence, 10), now, expiry, "Current configured policy; not historical Allow/Block, continuous ownership authority or proof of delivery"}, rules, nil
}
func (e *Engine) PolicyView(generation, expected string, uid uint32, admin bool, h *EnforcementStatus) (PolicyView, error) {
	var activity identity.ActivitySnapshot
	if e.Activity != nil {
		activity = e.Activity()
		if !admin {
			activity = activityFor(activity, uid, false)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if generation == "" || generation != e.Generation {
		return PolicyView{}, mutationError("generation_conflict", "Backend generation changed or missing; reload")
	}
	snapshot, rules, err := e.snapshotLocked(uid, admin, h, expected)
	if err != nil {
		return PolicyView{}, err
	}
	out := PolicyView{NetworkZones: e.Zones, Zones: e.zoneViews(rules, h, snapshot.EvaluatedAt), Snapshot: snapshot, ActivitySequence: strconv.FormatUint(activity.Sequence, 10), ActivityCollected: activity.Collected, Applications: []ApplicationPolicy{}, Rows: []PolicyAssociation{}, Complete: activity.Complete}
	now := snapshot.EvaluatedAt
	var processComplete bool
	out.Processes, processComplete = e.processViewsLocked(activity, rules, h, now)
	if !processComplete {
		out.Complete = false
		out.Reason = "Process summary limit reached"
	}
	if e.Activity == nil || activity.Error != "" || activity.Collected.IsZero() || now.Sub(activity.Collected) > 45*time.Second || activity.Collected.After(now.Add(5*time.Second)) {
		out.Complete = false
		out.Reason = "Activity unavailable or stale; no supported observed identity supplied"
		return out, nil
	}
	out.ActivityAvailable = true
	groups := map[string]*ApplicationPolicy{}
	for i, row := range activity.Rows {
		if i >= 2048 {
			out.Complete = false
			out.Reason = "Row summary limit reached"
			break
		}
		assoc := PolicyAssociation{RowID: row.ID, Status: "unavailable", Reason: "Unknown, shared or display-only ownership is not an application policy association"}
		if len(row.Owners) != 1 || row.OwnershipCategory != "visible-holder" {
			out.Rows = append(out.Rows, assoc)
			continue
		}
		p, ok := activity.Processes[row.Owners[0]]
		if !ok || p.Start == "" || p.Application.Kind != "native" || p.Application.Key == "" || p.Application.Revision == "" || (!admin && p.UID != uid) {
			assoc.Reason = "Supported authorized native process identity unavailable"
			out.Rows = append(out.Rows, assoc)
			continue
		}
		a := PolicyIdentity{p.Application.Key, p.Application.Revision, p.UID}
		ref := appPolicyRef(a)
		group := groups[ref]
		if group == nil {
			if len(groups) >= 256 {
				assoc.Reason = "Application summary limit reached"
				out.Complete = false
				out.Rows = append(out.Rows, assoc)
				continue
			}
			group = &ApplicationPolicy{Ref: ref, Identity: a, ZoneFallbackRuleIDs: zoneFallbackIDs(rules, a.UID), ProcessIDs: []string{}, Incoming: summaryFor(a, "incoming", e.Mode, h, rules, now), Outgoing: summaryFor(a, "outgoing", e.Mode, h, rules, now)}
			groups[ref] = group
		}
		seen := false
		for _, id := range group.ProcessIDs {
			if id == p.ID {
				seen = true
			}
		}
		if !seen {
			group.ProcessIDs = append(group.ProcessIDs, p.ID)
		}
		assoc.Status = "observed_native"
		assoc.Reason = "Single visible process association in this Activity snapshot; not enforcement ownership authority"
		assoc.ApplicationRef = ref
		out.Rows = append(out.Rows, assoc)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sort.Strings(groups[k].ProcessIDs)
		out.Applications = append(out.Applications, *groups[k])
	}
	return out, nil
}
func (e *Engine) PolicyExplain(generation, expected string, eventIDs []string, uid uint32, admin bool, h *EnforcementStatus) (PolicyExplanations, error) {
	if len(eventIDs) == 0 || len(eventIDs) > 8 {
		return PolicyExplanations{}, mutationError("invalid_request", "Supply 1..8 distinct event_ids")
	}
	seen := map[string]bool{}
	for _, id := range eventIDs {
		if id == "" || len(id) > 128 || seen[id] {
			return PolicyExplanations{}, mutationError("invalid_request", "Invalid or duplicate event IDs")
		}
		seen[id] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if generation == "" || generation != e.Generation {
		return PolicyExplanations{}, mutationError("generation_conflict", "Backend generation changed or missing; reload")
	}
	snapshot, rules, err := e.snapshotLocked(uid, admin, h, expected)
	if err != nil {
		return PolicyExplanations{}, err
	}
	out := PolicyExplanations{Snapshot: snapshot, Contexts: []PolicyExplanation{}}
	for _, id := range eventIDs {
		result := PolicyExplanation{EventID: id, Status: "unavailable", Reason: "Event not available in authorized current-session history", Enforcement: PolicyCoverage{State: "unknown", Reason: "No authorized context"}, RuntimeDefault: PolicyDefault{Reason: "No authorized context"}}
		var found *Event
		for _, v := range e.events {
			if v.ID == id && (admin || owned(v.Attribution, uid)) {
				found = v
				break
			}
		}
		if found == nil {
			out.Contexts = append(out.Contexts, result)
			continue
		}
		flow := found.Flow
		result.Flow = &flow
		result.Enforcement, result.RuntimeDefault = coverage(e.Mode, flow.Direction, h)
		// No Resolve/Observe/expire/RetainedState: read explanation of recorded context
		// against current stored policy, not an admission or fresh ownership assertion.
		action, rule, ids := e.evaluateLocked(rules, flow, found.Attribution, snapshot.EvaluatedAt)
		result.Status = "evaluated"
		result.ConfiguredAction = action
		result.SelectedRule = rule
		result.Reason = "Current stored policy evaluated for recorded event identity/endpoints; ownership not revalidated; no historical verdict or live delivery claim. Matching process tier overrides application tier, which overrides all-program zone tier; within each tier highest priority wins, then smallest rule ID"
		if a := found.Attribution.Application; a != nil && found.Attribution.Principal() != nil {
			result.Identity = &PolicyIdentity{a.Key, a.Revision, found.Attribution.Principal().UID}
		}
		for _, id := range ids {
			for _, r := range rules {
				if r.ID == id {
					result.Matching = append(result.Matching, e.ruleRefLocked(r, snapshot.EvaluatedAt))
					break
				}
			}
		}
		if rule == "default-ask" {
			result.Reason += "; no active stored filter matched, so evaluator default " + action
		}
		if rule == "unsafe-attribution" {
			result.Reason += "; recorded attribution lacks a supported application/principal, so evaluator blocks"
		}
		out.Contexts = append(out.Contexts, result)
	}
	return out, nil
}
func boundedPolicyResponse(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 2*1024*1024 {
		return fmt.Errorf("explanation response exceeds 2 MiB")
	}
	return nil
}
