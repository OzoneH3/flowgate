package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

const ObservedRuleCapability = "observed-rule-create-v1"
const ObservedAnyProtocolCapability = "observed-rule-any-protocol-v1"

// ApplicationPolicyCapability: an Activity application/process setter sets the
// ONE canonical whole-target rule (TCP+UDP, any address/ports, optional zone)
// for a direction, creating it or updating it in place. Scoped rules are never
// selected as its target (NetLimiter Blocker: Allow = all connections).
const ApplicationPolicyCapability = "application-policy-v1"

// StoredAskCapability: Ask is a persisted Blocker action (NetLimiter Ask) for
// application, process, scoped and zone rules; a winning Ask rule prompts and is
// recorded as the request's source rule. Equal weight: Deny, Allow, then Ask.
const StoredAskCapability = "stored-ask-v1"

// RuleVersionRef identifies the exact stored rule a preview will update.
type RuleVersionRef struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type ObservedTarget struct {
	RowID     string `json:"row_id"`
	ProcessID string `json:"process_id"`
}

// Pointers require explicit wildcard ports/expiry rather than omitted fields
// silently becoming an application-wide persistent permission.
type ObservedDraft struct {
	NetworkZone   string     `json:"network_zone,omitempty"`
	ZoneRevision  string     `json:"zone_revision,omitempty"`
	TargetScope   string     `json:"target_scope,omitempty"`
	Direction     string     `json:"direction"`
	Protocol      string     `json:"protocol"`
	Action        string     `json:"action"`
	RemoteAddress string     `json:"remote_address"`
	LocalPort     *uint16    `json:"local_port"`
	RemotePort    *uint16    `json:"remote_port"`
	Disabled      bool       `json:"disabled"`
	Expires       *time.Time `json:"expires"`
	// ApplicationPolicy requests the canonical whole-application (or whole-
	// process) policy for this direction instead of a scoped rule.
	ApplicationPolicy bool `json:"application_policy,omitempty"`
}
type ObservedPreview struct {
	Token        string               `json:"token"`
	ExpiresAt    time.Time            `json:"expires_at"`
	Rule         policy.Rule          `json:"rule"`
	Application  identity.Application `json:"application"`
	ProcessID    string               `json:"process_id"`
	PID          int                  `json:"pid"`
	PrincipalUID uint32               `json:"principal_uid"`
	ScopePreview string               `json:"scope_preview"`
	Enforcement  PolicyCoverage       `json:"enforcement"`
	// Replaces is the exact canonical rule this application policy updates.
	Replaces *RuleVersionRef `json:"replaces"`
}
type creationPreview struct {
	View         ObservedPreview
	Target       ObservedTarget
	Process      identity.ActivityProcess
	Verified     identity.Process
	Draft        string
	UID          uint32
	Admin        bool
	Saved        bool
	ReceiptUntil time.Time
	// Settled: waiting requests this save settled (queue-reconcile-v1).
	Settled []SettledRequest
}

func draftBytes(d ObservedDraft) (string, error) {
	if !validScope(d) {
		return "", mutationError("invalid_request", "target_scope must be application or process")
	}
	d.TargetScope = processScope(d)
	if d.LocalPort == nil || d.RemotePort == nil || d.Expires == nil || d.RemoteAddress == "" || len(d.RemoteAddress) > 128 || (d.Direction != "incoming" && d.Direction != "outgoing") || (d.Protocol != "tcp" && d.Protocol != "udp" && d.Protocol != "*") || (d.Action != "allow" && d.Action != "block" && d.Action != "ask") {
		return "", mutationError("invalid_request", "Explicit direction, protocol (tcp, udp, or * for TCP+UDP only), action, remote_address, local_port, remote_port and expires required; zero ports/zero expiry are deliberate wildcard/persistent choices")
	}
	if d.ApplicationPolicy && (d.Protocol != "*" || d.RemoteAddress != "*" || *d.LocalPort != 0 || *d.RemotePort != 0) {
		return "", mutationError("invalid_request", "application_policy requires the whole-target scope: protocol *, remote_address *, ports 0 (zone optional)")
	}
	b, _ := json.Marshal(d)
	return string(b), nil
}
func (e *Engine) checkCreationLocked(generation string) error {
	if generation == "" || generation != e.Generation {
		return mutationError("generation_conflict", "Backend generation changed or missing; reload before creation")
	}
	if e.SaveRules == nil {
		return mutationError("unavailable", "Durable rule storage unavailable")
	}
	return nil
}
func (e *Engine) verifyCreation(target ObservedTarget, p identity.ActivityProcess, uid uint32, admin bool) (identity.Process, error) {
	if !admin && p.UID != uid {
		return identity.Process{}, mutationError("forbidden", "Target outside authorized UID scope")
	}
	if p.Application.Kind == "wine" {
		return e.verifyRuntimeCreation(target, p)
	}
	verify := e.verifyObserved
	if verify == nil {
		verify = identity.VerifyObservedNative
	}
	current, err := verify(target.RowID, p)
	if err != nil {
		return identity.Process{}, mutationError("stale_target", err.Error())
	}
	// Check the verifier's principal/identity even in tests; no metadata provided by caller.
	if current.PID != p.PID || current.Start != p.Start || current.UID != p.UID || !identity.LiveRuleable(current.Application) || current.Application.Kind != p.Application.Kind || current.Application.Key == "" || current.Application.Key != p.Application.Key || current.Application.Revision == "" || current.Application.Revision != p.Application.Revision || current.NetNS == "" || current.MountNS == "" {
		return identity.Process{}, mutationError("stale_target", "Verified process generation/identity/namespace changed")
	}
	return current, nil
}
func (e *Engine) pruneCreationLocked(now time.Time) {
	for token, p := range e.creationPreviews {
		deadline := p.View.ExpiresAt
		if p.Saved {
			deadline = p.ReceiptUntil
		}
		if !now.Before(deadline) {
			delete(e.creationPreviews, token)
		}
	}
	e.pruneHandlesLocked()
}
func (e *Engine) PreviewObservedRule(generation string, target ObservedTarget, draft ObservedDraft, uid uint32, admin bool, h *EnforcementStatus) (ObservedPreview, error) {
	if err := e.zoneRevision(draft.NetworkZone, draft.ZoneRevision); err != nil {
		return ObservedPreview{}, err
	}
	raw, err := draftBytes(draft)
	if err != nil {
		return ObservedPreview{}, err
	}
	if target.RowID == "" || len(target.RowID) > 1024 || target.ProcessID == "" || len(target.ProcessID) > 64 {
		return ObservedPreview{}, mutationError("invalid_request", "Observed row_id/process_id required")
	}
	e.creationMu.Lock()
	defer e.creationMu.Unlock()
	e.mu.Lock()
	err = e.checkCreationLocked(generation)
	now := e.Now()
	e.mu.Unlock()
	if err != nil {
		return ObservedPreview{}, err
	}
	if e.Activity == nil {
		return ObservedPreview{}, mutationError("unavailable", "Activity unavailable")
	}
	s := e.Activity()
	if s.Error != "" || s.Collected.IsZero() || now.Sub(s.Collected) > 45*time.Second || s.Collected.After(now.Add(5*time.Second)) {
		return ObservedPreview{}, mutationError("stale_target", "Activity unavailable/stale; refresh")
	}
	p, ok := s.Processes[target.ProcessID]
	// Do not disclose foreign process details in either success or errors.
	if ok && !admin && p.UID != uid {
		return ObservedPreview{}, mutationError("forbidden", "Target outside authorized UID scope")
	}
	found := false
	runtimeTarget := false
	for _, row := range s.Rows {
		if row.ID == target.RowID && len(row.Owners) == 1 && row.Owners[0] == target.ProcessID && row.OwnershipCategory == "visible-holder" {
			found = true
			if r := row.RuntimeApplication; r != nil && r.UID == p.UID && r.Application.Kind == "wine" && r.Application.Key != "" && r.Application.Revision != "" {
				if processScope(draft) == "process" {
					return ObservedPreview{}, mutationError("unsupported_process", "Windows socket owner does not establish a Linux process rule target")
				}
				p.Application = r.Application
				runtimeTarget = true
			}
			break
		}
	}
	if !ok || !found || p.ID != target.ProcessID || p.PID <= 0 || p.Start == "" || (!runtimeTarget && !identity.LiveRuleable(p.Application)) {
		if why := identity.RuntimeRuleBlocked(&p.Application); ok && found && why != "" {
			return ObservedPreview{}, mutationError(identity.CodeIdentityUnverifiable, why)
		}
		return ObservedPreview{}, mutationError("unsupported_target", "Supported single-holder native Activity context required; unknown/shared/runtime/display-only targets cannot create rules")
	}
	current, err := e.verifyCreation(target, p, uid, admin)
	if err != nil {
		return ObservedPreview{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = e.checkCreationLocked(generation); err != nil {
		return ObservedPreview{}, err
	}
	now = e.Now()
	e.pruneCreationLocked(now)
	defer e.pruneHandlesLocked()
	if e.creationPreviews == nil {
		e.creationPreviews = map[string]*creationPreview{}
	}
	own := 0
	for _, v := range e.creationPreviews {
		if v.UID == uid {
			own++
		}
	}
	if len(e.creationPreviews) >= 256 || own >= 16 {
		return ObservedPreview{}, mutationError("limit_exceeded", "Outstanding preview/receipt capacity reached; wait for expiry")
	}
	if len(e.rules) >= 256 {
		return ObservedPreview{}, mutationError("limit_exceeded", "Rule capacity reached")
	}
	candidate := policy.Rule{ID: "user:" + randomID(), Version: 1, Created: now, Executable: current.Application.Executable, Priority: 100, Action: draft.Action, Disabled: draft.Disabled, Expires: *draft.Expires, Filter: policy.Filter{NetworkZone: draft.NetworkZone, Application: current.Application.Key, Revision: current.Application.Revision, UID: current.UID, Direction: draft.Direction, Protocol: draft.Protocol, RemoteAddress: draft.RemoteAddress, LocalPort: *draft.LocalPort, RemotePort: *draft.RemotePort}}
	if processScope(draft) == "process" {
		if _, err = e.attachProcessTarget(current, &candidate); err != nil {
			return ObservedPreview{}, err
		}
	}
	if !candidate.Expires.IsZero() && !now.Before(candidate.Expires) {
		return ObservedPreview{}, mutationError("invalid_request", "Expiry must be in future, or explicit zero for persistent")
	}
	e.bindZoneModel(&candidate)
	var replaces *RuleVersionRef
	if draft.ApplicationPolicy {
		if old := e.canonicalPolicyRuleLocked(candidate); old != nil {
			if old.Version == ^uint64(0) {
				return ObservedPreview{}, mutationError("limit_exceeded", "Rule version exhausted")
			}
			candidate.ID, candidate.Created, candidate.Priority, candidate.Version = old.ID, old.Created, old.Priority, old.Version+1
			replaces = &RuleVersionRef{old.ID, old.Version}
		}
	}
	candidate, sentence, err := e.reviewRuleLocked(candidate, now, false)
	if err != nil {
		return ObservedPreview{}, mutationError("invalid_rule", err.Error())
	}
	c, _ := coverage(e.Mode, draft.Direction, h)
	if replaces != nil {
		sentence = fmt.Sprintf("Updates the existing whole-%s rule %s (version %d). ", processScope(draft), replaces.ID, replaces.Version) + sentence
	}
	v := ObservedPreview{Token: randomID(), ExpiresAt: now.Add(30 * time.Second), Rule: candidate, Application: current.Application, ProcessID: p.ID, PID: p.PID, PrincipalUID: p.UID, ScopePreview: sentence + " Stored rule only; matching pending requests are re-evaluated; existing connections unchanged.", Enforcement: c, Replaces: replaces}
	e.creationPreviews[v.Token] = &creationPreview{View: v, Target: target, Process: p, Verified: current, Draft: raw, UID: uid, Admin: admin}
	return v, nil
}

// ObservedSettled returns the requests settled by the save of this preview
// token (empty when unknown or not saved). Same answer for a replayed save.
func (e *Engine) ObservedSettled(token string) []SettledRequest {
	e.creationMu.Lock()
	defer e.creationMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if p := e.creationPreviews[token]; p != nil && p.Saved {
		return p.Settled
	}
	return nil
}

func (e *Engine) SaveObservedRule(generation, token string, draft ObservedDraft, uid uint32, admin bool) (policy.Rule, string, bool, error) {
	if err := e.zoneRevision(draft.NetworkZone, draft.ZoneRevision); err != nil {
		return policy.Rule{}, "", false, err
	}
	raw, err := draftBytes(draft)
	if err != nil {
		return policy.Rule{}, "", false, err
	}
	e.creationMu.Lock()
	defer e.creationMu.Unlock()
	e.mu.Lock()
	if err = e.checkCreationLocked(generation); err != nil {
		e.mu.Unlock()
		return policy.Rule{}, "", false, err
	}
	now := e.Now()
	e.pruneCreationLocked(now)
	p := e.creationPreviews[token]
	if p == nil || p.UID != uid || p.Admin != admin {
		e.mu.Unlock()
		return policy.Rule{}, "", false, mutationError("preview_expired", "Preview unavailable/expired for this principal; inspect rules before creating again")
	}
	if raw != p.Draft {
		e.mu.Unlock()
		return policy.Rule{}, "", false, mutationError("preview_mismatch", "Draft changed; obtain and review fresh preview")
	}
	if p.Saved {
		for _, r := range e.rules {
			if r.ID == p.View.Rule.ID && r.Version == p.View.Rule.Version {
				e.mu.Unlock()
				return p.View.Rule, p.View.ScopePreview, true, nil
			}
		}
		e.mu.Unlock()
		return policy.Rule{}, "", false, mutationError("replay_conflict", "Previously created rule changed/deleted; inspect authoritative list, do not recreate automatically")
	}
	e.mu.Unlock()
	if !p.View.Rule.Filter.Process.IsZero() {
		e.mu.Lock()
		h := e.processHandles[p.View.Rule.Filter.Process]
		e.mu.Unlock()
		if h == nil {
			return policy.Rule{}, "", false, mutationError("target_inactive", "Process preview lifetime ended")
		}
		if err := h.Check(); err != nil {
			return policy.Rule{}, "", false, mutationError("target_inactive", err.Error())
		}
	}
	current, err := e.verifyCreation(p.Target, p.Process, uid, admin)
	if err != nil {
		return policy.Rule{}, "", false, err
	}
	if current.NetNS != p.Verified.NetNS || current.MountNS != p.Verified.MountNS || current.ExecutableRevision != p.Verified.ExecutableRevision || current.Application.Executable != p.Verified.Application.Executable {
		return policy.Rule{}, "", false, mutationError("stale_target", "Namespace or executable changed since preview")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = e.checkCreationLocked(generation); err != nil {
		return policy.Rule{}, "", false, err
	}
	now = e.Now()
	if !now.Before(p.View.ExpiresAt) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Preview expired during verification; refresh")
	}
	candidate := p.View.Rule
	if b := candidate.Filter.Process; !b.IsZero() {
		h := e.processHandles[b]
		if h == nil {
			return policy.Rule{}, "", false, mutationError("target_inactive", "Pinned process handle unavailable during save validation")
		}
		if err := h.Check(); err != nil {
			return policy.Rule{}, "", false, mutationError("target_inactive", err.Error())
		}
		if !b.Matches(current) {
			return policy.Rule{}, "", false, mutationError("target_inactive", "Pinned process binding changed during save validation")
		}
	}
	at := -1
	if ref := p.View.Replaces; ref != nil {
		for i, r := range e.rules {
			if r.ID == ref.ID {
				at = i
				if r.Version != ref.Version || e.canonicalPolicyRuleLocked(candidate) == nil {
					at = -2
				}
			}
		}
		if at < 0 {
			return policy.Rule{}, "", false, mutationError("policy_conflict", "The application rule changed or was removed since preview; refresh")
		}
	} else if len(e.rules) >= 256 {
		return policy.Rule{}, "", false, mutationError("limit_exceeded", "Rule capacity reached")
	}
	if p.View.Replaces == nil && candidate.Version == 1 && p.Draft != "" {
		var d ObservedDraft
		if json.Unmarshal([]byte(p.Draft), &d) == nil && d.ApplicationPolicy && e.canonicalPolicyRuleLocked(candidate) != nil {
			return policy.Rule{}, "", false, mutationError("policy_conflict", "An application rule for this scope was created since preview; refresh")
		}
	}
	if !candidate.Expires.IsZero() && !now.Before(candidate.Expires) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Reviewed rule expiry elapsed")
	}
	_, sentence, err := e.reviewRuleLocked(candidate, now, false)
	if err != nil {
		return policy.Rule{}, "", false, mutationError("policy_conflict", err.Error())
	}
	// Overlap text is part of the reviewed scope. New conflicting policy requires review.
	if ref := p.View.Replaces; ref != nil {
		sentence = fmt.Sprintf("Updates the existing whole-%s rule %s (version %d). ", map[bool]string{true: "process", false: "application"}[!candidate.Filter.Process.IsZero()], ref.ID, ref.Version) + sentence
	}
	sentence += " Stored rule only; matching pending requests are re-evaluated; existing connections unchanged."
	if sentence != p.View.ScopePreview {
		return policy.Rule{}, "", false, mutationError("policy_conflict", "Overlapping policy changed since preview; review again")
	}
	next := append(append([]policy.Rule{}, e.rules...), candidate)
	if at >= 0 {
		next = append([]policy.Rule{}, e.rules...)
		next[at] = candidate
	}
	if err = e.publishRulesLocked(next); err != nil {
		return policy.Rule{}, "", false, err
	}
	restore := e.collectSettledLocked()
	e.settlePendingLocked("rule " + candidate.ID + " saved")
	p.Settled = e.settledLocked()
	restore()
	// Existing pending/Once decisions are not consumed or approved. New initiations
	// evaluate the published rule; retained remembered grants already recheck policy.
	p.Saved = true
	p.ReceiptUntil = now.Add(5 * time.Minute)
	return candidate, p.View.ScopePreview, false, nil
}

// canonicalPolicyRuleLocked returns the stored user rule with exactly the same
// whole-target scope (identity, direction, zone, process binding, TCP+UDP, any
// address/ports). Scoped, preset and zone-wide rules never qualify.
func (e *Engine) canonicalPolicyRuleLocked(c policy.Rule) *policy.Rule {
	want := canonicalFilter(c.Filter)
	if want.Protocol != "*" || want.RemoteAddress != "*" || want.LocalPort != 0 || want.RemotePort != 0 || want.AllPrograms {
		return nil
	}
	for i := range e.rules {
		r := &e.rules[i]
		if r.Preset == nil && canonicalFilter(r.Filter) == want {
			return r
		}
	}
	return nil
}

// Runtime application creation never assigns the broker a Windows process identity.
// The returned Process retains the broker generation solely as a namespace/file
// witness; callers prohibit process scope before reaching this path.
func (e *Engine) verifyRuntimeCreation(target ObservedTarget, expected identity.ActivityProcess) (identity.Process, error) {
	fail := func() (identity.Process, error) {
		return identity.Process{}, mutationError("stale_target", "Windows socket owner or broker generation changed; refresh Activity")
	}
	if e.Activity == nil {
		return fail()
	}
	s := e.Activity()
	if s.Error != "" || s.Collected.IsZero() || e.Now().Sub(s.Collected) > 45*time.Second {
		return fail()
	}
	for _, r := range s.Rows {
		if r.ID != target.RowID || len(r.Owners) != 1 || r.Owners[0] != target.ProcessID || r.RuntimeApplication == nil {
			continue
		}
		a := e.Resolve(identity.Flow{Protocol: r.Socket.Protocol, Direction: "outgoing", NetNS: r.Socket.NetNS, Local: r.Socket.Local, Remote: r.Socket.Remote})
		if a.Status != "corroborated-runtime-table" || a.Application == nil || a.Table == nil || len(a.Sockets) != 1 || a.Sockets[0].Cookie != r.Socket.Cookie || a.Table.UID != expected.UID || a.Application.Key != expected.Application.Key || a.Application.Revision != expected.Application.Revision {
			return fail()
		}
		for _, p := range a.Owners {
			if p.PID == expected.PID && p.Start == expected.Start && p.UID == expected.UID && p.PID == a.Table.BrokerPID && p.Start == a.Table.BrokerStart {
				p.Application = *a.Application
				return p, nil
			}
		}
	}
	return fail()
}
