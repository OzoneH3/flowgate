package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

// RequestApplicationRuleCapability: a prompted request's application identity,
// captured from its verified owner, is retained after the request ends so an
// application rule for future connections can be saved without the original
// PID, socket or another live instance. It never decides or releases the
// original request.
const RequestApplicationRuleCapability = "request-application-rule-v1"

// RequestSandboxIdentityCapability: while a prompted process is alive its
// executable evidence is retained (opened-file device/inode/stamp, SHA-256 and
// a host-visible backing path proven by device+inode), so a rule can be saved
// after it exited even from another mount namespace (Steam pressure-vessel,
// Flatpak). Without a host-visible backing file the refusal is
// identity_unverifiable. request_rule.executable_identity reports the state.
const RequestSandboxIdentityCapability = "request-sandbox-identity-v1"

// identityUnverifiableHint is the actionable part of identity_unverifiable.
const identityUnverifiableHint = "Start the app again and choose Remember while its request is open."

// retainedEvidenceWait bounds how long a review waits for a pending digest.
const retainedEvidenceWait = 10 * time.Second

// requestRuleRetention keeps the captured identity this long after the deadline.
const requestRuleRetention = 10 * time.Minute

type retainedRequest struct {
	EventID     string
	Application identity.Application
	UID         uint32
	Filter      policy.Filter // exact remembered filter of the request
	MountNS     string
	PID         int
	Start       string
	FirstSeen   time.Time
	Until       time.Time
	// Owner is the single verified owning process (complete visibility) the
	// request was captured from; nil when For a while could never bind to it.
	Owner *identity.Process
	// Decided is set once the request was decided or settled by policy; only
	// an undecided ended request may start For a while for its live process.
	Decided bool
	// Exe is the executable evidence captured while the process was alive
	// (nil when capture failed: ExeError). Its open reference is released on
	// digest completion, prune, eviction and save.
	Exe      *identity.RetainedExecutable
	ExeError string
	// Provenance is the owner's launch provenance at request time (display
	// only), kept for ended cards beyond the event's lifetime.
	Provenance *identity.Provenance
}

func (r *retainedRequest) release() {
	if r != nil {
		r.Exe.Release()
	}
}

// RequestRuleSource tells clients whether an application rule can be saved from
// this request and whether its process instance is still running.
type RequestRuleSource struct {
	Available    bool      `json:"available"`
	ProcessState string    `json:"process_state"` // running, ended or unknown
	Until        time.Time `json:"until"`
	// ProcessLeaseAvailable (request-for-a-while-v1): the request is undecided,
	// had one verified owning process and that exact instance is still running,
	// so For a while can create a lease for it although this request ended.
	// Presentation only; request-for-a-while re-verifies everything.
	ProcessLeaseAvailable bool `json:"process_lease_available"`
	PID                   int  `json:"pid,omitempty"`
	// ExecutableIdentity (request-sandbox-identity-v1): verified (host-visible
	// backing file with digest), pending (digest in progress), sandbox-only
	// (no persistent identity once the process exits) or unavailable.
	ExecutableIdentity string               `json:"executable_identity,omitempty"`
	Provenance         *identity.Provenance `json:"provenance,omitempty"`
}

type RequestRulePreview struct {
	Token           string               `json:"token"`
	ExpiresAt       time.Time            `json:"expires_at"`
	Generation      string               `json:"generation"`
	EventID         string               `json:"event_id"`
	Action          string               `json:"action"`
	Scope           string               `json:"scope"`
	NetworkZone     string               `json:"network_zone"`
	ZoneRevision    string               `json:"zone_revision"`
	Remember        RememberFields       `json:"remember"`
	DurationSeconds int64                `json:"duration_seconds,omitempty"`
	Application     identity.Application `json:"application"`
	Rule            policy.Rule          `json:"rule"`
	ScopePreview    string               `json:"scope_preview"`
	Summary         string               `json:"summary"`
	Replaces        *RuleVersionRef      `json:"replaces"`
}

type requestRulePreview struct {
	View         RequestRulePreview
	UID          uint32
	Admin        bool
	Saved        bool
	ReceiptUntil time.Time
}

func (e *Engine) retainRequestLocked(v *Event, a identity.Attribution) {
	app := a.Application
	if v.State != "awaiting-decision" || app == nil || app.Key == "" || app.Revision == "" || a.Principal() == nil || v.RememberedFilter == nil || identity.RuntimeRuleBlocked(app) != "" {
		return
	}
	r := &retainedRequest{EventID: v.ID, Application: *app, UID: a.Principal().UID, Filter: *v.RememberedFilter, FirstSeen: v.FirstSeen, Until: v.Deadline.Add(requestRuleRetention)}
	for i, o := range a.Owners {
		if i == 0 {
			r.MountNS = o.MountNS
		} else if o.MountNS != r.MountNS {
			r.MountNS = ""
		}
	}
	if len(a.Owners) == 1 && a.Table == nil {
		r.PID, r.Start = a.Owners[0].PID, a.Owners[0].Start
	}
	if p, err := leaseOwner(a); err == nil {
		r.Owner = &p
	}
	// Executable evidence from an owner running exactly this application
	// revision, while it is alive (bounded; see identity.CaptureExecutable).
	capture := e.captureExecutable
	if capture == nil {
		capture = identity.CaptureExecutable
	}
	for _, o := range a.Owners {
		if o.Application.Key != app.Key || o.Application.Revision != app.Revision || o.UID != r.UID {
			continue
		}
		if r.Provenance == nil {
			r.Provenance = o.Provenance
		}
		x, err := capture(o, *app)
		if err == nil {
			r.Exe, r.ExeError = x, ""
			break
		}
		r.ExeError = err.Error()
	}
	if e.requestRules == nil {
		e.requestRules = map[string]*retainedRequest{}
	}
	if old := e.requestRules[v.ID]; old != nil {
		old.release()
	}
	if len(e.requestRules) >= 256 {
		var oldest *retainedRequest
		for _, x := range e.requestRules {
			if oldest == nil || x.FirstSeen.Before(oldest.FirstSeen) {
				oldest = x
			}
		}
		oldest.release()
		delete(e.requestRules, oldest.EventID)
	}
	e.requestRules[v.ID] = r
}

func (e *Engine) pruneRequestRulesLocked(now time.Time) {
	for id, r := range e.requestRules {
		if !now.Before(r.Until) {
			r.release()
			delete(e.requestRules, id)
		}
	}
	for token, p := range e.requestRulePreviews {
		until := p.View.ExpiresAt
		if p.Saved {
			until = p.ReceiptUntil
		}
		if !now.Before(until) {
			delete(e.requestRulePreviews, token)
		}
	}
}

func (e *Engine) processStateLocked(r *retainedRequest) string {
	if r.PID == 0 {
		return "unknown"
	}
	running := e.instanceRunning
	if running == nil {
		running = identity.InstanceRunning
	}
	if running(r.PID, r.Start) {
		return "running"
	}
	return "ended"
}

func (e *Engine) requestRuleSourceLocked(id string) *RequestRuleSource {
	r := e.requestRules[id]
	if r == nil || !e.Now().Before(r.Until) {
		return nil
	}
	state := e.processStateLocked(r)
	src := &RequestRuleSource{Available: true, ProcessState: state, Until: r.Until, PID: r.PID}
	src.ProcessLeaseAvailable = r.Owner != nil && !r.Decided && state == "running"
	src.Provenance = r.Provenance
	src.ExecutableIdentity = "unavailable"
	if r.Exe != nil {
		switch ev := r.Exe.Evidence(); {
		case ev.Visibility != identity.VisibilityHost:
			src.ExecutableIdentity = identity.VisibilitySandboxOnly
		case ev.DigestState == "pending":
			src.ExecutableIdentity = "pending"
		case ev.SHA256 != "":
			src.ExecutableIdentity = "verified"
		}
	}
	return src
}

// verifyRetainedLocked re-validates the retained identity without trusting a
// path string: through the executable evidence captured while the process ran
// (host-visible backing file: device, inode, stamp and SHA-256), else the
// same-namespace path check, else the still-running exact instance. A
// sandbox-only executable of an exited process has no persistent identity.
func (e *Engine) verifyRetainedLocked(r *retainedRequest) error {
	var err error
	switch ev := r.Exe.Evidence(); {
	case e.verifyRetained != nil: // tests
		err = e.verifyRetained(r.Application, r.UID, r.MountNS)
	case r.Exe != nil && ev.Visibility == identity.VisibilityHost:
		err = identity.VerifyRetainedEvidence(r.Application, r.UID, ev)
	case r.MountNS != "" && r.MountNS == identity.SelfMountNS():
		err = identity.VerifyRetainedExecutable(r.Application, r.UID, r.MountNS)
	case e.processStateLocked(r) == "running":
		err = identity.VerifyInstanceExecutable(r.PID, r.Start, r.Application)
	case r.Exe != nil:
		err = identity.UnverifiableEvidence(r.MountNS, &ev, "")
	default:
		why := "no executable evidence was retained while it ran"
		if r.ExeError != "" {
			why += " (" + r.ExeError + ")"
		}
		err = identity.UnverifiableEvidence(r.MountNS, nil, why)
	}
	if err == nil {
		return nil
	}
	var re *identity.RetainedError
	if errors.As(err, &re) && re.Code == identity.CodeIdentityUnverifiable {
		return mutationError(identity.CodeIdentityUnverifiable, "No reusable application identity: "+err.Error()+". No rule saved. "+identityUnverifiableHint)
	}
	return mutationError(identity.CodeExecutableChanged, "Application identity cannot be validated: "+err.Error()+"; no rule saved")
}

// awaitRetainedEvidence waits (without holding e.mu) for a pending digest of
// the request's retained executable, so a review never races its capture.
func (e *Engine) awaitRetainedEvidence(id string) {
	e.mu.Lock()
	r := e.requestRules[id]
	var x *identity.RetainedExecutable
	if r != nil {
		x = r.Exe
	}
	e.mu.Unlock()
	x.Wait(retainedEvidenceWait)
}

// requestRuleLocked validates the shared preview/save inputs and returns the
// retained identity. The original request must not still be decidable.
func (e *Engine) requestRuleLocked(generation, id, action, scope, zone, revision string, uid uint32, admin bool, o *RememberOptions) (*retainedRequest, error) {
	if generation == "" || generation != e.Generation {
		return nil, mutationError("generation_conflict", "Backend changed; reload")
	}
	if e.SaveRules == nil {
		return nil, mutationError("unavailable", "Durable rule storage unavailable")
	}
	if (action != "allow" && action != "block" && action != "ask") || (scope != "application" && scope != "persistent") || (zone != "any" && zone != "local" && zone != "internet") {
		return nil, mutationError("invalid_request", "Explicit action (allow, block or ask), scope (application or persistent) and network zone required")
	}
	if o.Fields == nil {
		return nil, mutationError("invalid_request", "Explicit remember fields required; unchecked properties mean any")
	}
	n, err := o.normalized(scope)
	if err != nil {
		return nil, err
	}
	*o = n
	if zone != "any" {
		if err := e.zoneRevision(zone, revision); err != nil {
			return nil, err
		}
	}
	now := e.Now()
	e.expire(now)
	e.pruneRequestRulesLocked(now)
	r := e.requestRules[id]
	if r == nil {
		return nil, mutationError("request_unavailable", fmt.Sprintf("This request's captured application identity is no longer retained (kept %s after its deadline); create the rule from Activity or Rules", requestRuleRetention))
	}
	if !admin && r.UID != uid {
		return nil, mutationError("forbidden", "Request belongs to another principal")
	}
	if o.Fields.Process {
		if e.processStateLocked(r) == "ended" {
			return nil, mutationError("process_scope_unavailable", "This process instance has ended, so a process-only rule could never match. Uncheck Process to save an application rule for future launches.")
		}
		return nil, mutationError("process_scope_unavailable", "Saving from a request creates application rules for future launches; uncheck Process, or use Remember while the request is pending")
	}
	for _, v := range e.events {
		if v.ID != id || v.State != "awaiting-decision" || !now.Before(v.Deadline) {
			continue
		}
		a := e.Resolve(v.Flow)
		if a.Application != nil && a.Principal() != nil && a.Fingerprint == v.Attribution.Fingerprint {
			return nil, mutationError("request_pending", "This request is still pending; use Allow or Deny with Remember")
		}
		// The binding is gone: end the request first (held packets drop), exactly
		// as a failed decision review does. Only the future rule continues.
		_ = e.rejectPendingBindingLocked(v, a)
	}
	return r, e.verifyRetainedLocked(r)
}

func (e *Engine) requestRuleSentence(rule policy.Rule, replaces *RuleVersionRef, sentence string) string {
	if replaces != nil {
		sentence = fmt.Sprintf("Updates existing rule %s (version %d). ", replaces.ID, replaces.Version) + sentence
	}
	return "Future connections only: " + sentence + " The ended request was not allowed and stays ended; no held packet is released."
}

func (e *Engine) PreviewRequestRule(generation, id, action, scope, zone, revision string, uid uint32, admin bool, o RememberOptions) (RequestRulePreview, error) {
	e.awaitRetainedEvidence(id)
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.requestRuleLocked(generation, id, action, scope, zone, revision, uid, admin, &o)
	if err != nil {
		return RequestRulePreview{}, err
	}
	n := 0
	for _, p := range e.requestRulePreviews {
		if p.UID == uid {
			n++
		}
	}
	if n >= 16 || len(e.requestRulePreviews) >= 256 {
		return RequestRulePreview{}, mutationError("capacity", "Rule preview capacity reached; wait for expiry")
	}
	now := e.Now()
	rule := policy.Rule{Version: 1, Schema: 2, ID: "user:" + randomID(), Executable: r.Application.Executable, Priority: 100, Action: action, Created: now, Filter: r.Filter}
	if scope == "application" {
		rule.Expires = now.Add(time.Duration(o.DurationSeconds) * time.Second)
	}
	if !o.Fields.Address {
		rule.Filter.RemoteAddress = "*"
	}
	if !o.Fields.Port {
		rule.Filter.LocalPort, rule.Filter.RemotePort = 0, 0
	}
	if !o.Fields.Protocol {
		rule.Filter.Protocol = "*"
	}
	if zone != "any" {
		rule.Schema = 4
		rule.Filter.NetworkZone = zone
		e.bindZoneModel(&rule)
	}
	// The same scope updates its existing user rule in place: repeated saves
	// never add duplicate rules.
	var replaces *RuleVersionRef
	for _, old := range e.rules {
		if old.Preset == nil && canonicalFilter(old.Filter) == canonicalFilter(rule.Filter) {
			if old.Version == ^uint64(0) {
				return RequestRulePreview{}, mutationError("capacity", "Rule version exhausted")
			}
			rule.ID, rule.Created, rule.Priority, rule.Version = old.ID, old.Created, old.Priority, old.Version+1
			replaces = &RuleVersionRef{old.ID, old.Version}
			break
		}
	}
	if replaces == nil && len(e.rules) >= 256 {
		return RequestRulePreview{}, mutationError("capacity", "Rule capacity reached")
	}
	rule, sentence, err := e.reviewRuleLocked(rule, now, false)
	if err != nil {
		return RequestRulePreview{}, mutationError("invalid_rule", err.Error())
	}
	duration := int64(0)
	if scope == "application" {
		duration = o.DurationSeconds
	}
	name := r.Application.DisplayName
	if name == "" {
		name = r.Application.Name
	}
	view := RequestRulePreview{Token: randomID(), ExpiresAt: now.Add(30 * time.Second), Generation: generation, EventID: id, Action: action, Scope: scope, NetworkZone: zone, ZoneRevision: revision, Remember: *o.Fields, DurationSeconds: duration, Application: r.Application, Rule: rule, ScopePreview: e.requestRuleSentence(rule, replaces, sentence), Summary: rememberSummary(name, rule, scope, duration), Replaces: replaces}
	if e.requestRulePreviews == nil {
		e.requestRulePreviews = map[string]*requestRulePreview{}
	}
	e.requestRulePreviews[view.Token] = &requestRulePreview{View: view, UID: uid, Admin: admin}
	return view, nil
}

// SaveRequestRule commits exactly the reviewed rule. Repeating a completed save
// with the same token returns the same receipt (replayed) and never creates a
// second rule; a later edit/delete of that rule is a replay conflict.
func (e *Engine) SaveRequestRule(generation, token, id, action, scope, zone, revision string, uid uint32, admin bool, o RememberOptions) (policy.Rule, string, bool, error) {
	r, s, replayed, _, err := e.SaveRequestRuleSettled(generation, token, id, action, scope, zone, revision, uid, admin, o)
	return r, s, replayed, err
}

// SaveRequestRuleSettled also returns the waiting requests the new rule settled.
func (e *Engine) SaveRequestRuleSettled(generation, token, id, action, scope, zone, revision string, uid uint32, admin bool, o RememberOptions) (policy.Rule, string, bool, []SettledRequest, error) {
	e.awaitRetainedEvidence(id)
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.collectSettledLocked()()
	r, s, replayed, err := e.saveRequestRuleLocked(generation, token, id, action, scope, zone, revision, uid, admin, o)
	return r, s, replayed, e.settledLocked(), err
}

func (e *Engine) saveRequestRuleLocked(generation, token, id, action, scope, zone, revision string, uid uint32, admin bool, o RememberOptions) (policy.Rule, string, bool, error) {
	if generation == "" || generation != e.Generation {
		return policy.Rule{}, "", false, mutationError("generation_conflict", "Backend changed; reload")
	}
	now := e.Now()
	e.pruneRequestRulesLocked(now)
	p := e.requestRulePreviews[token]
	if p == nil || p.UID != uid || p.Admin != admin {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Preview unavailable/expired for this principal; inspect rules before saving again")
	}
	v := p.View
	if o.Fields == nil {
		return policy.Rule{}, "", false, mutationError("invalid_request", "Explicit remember fields required")
	}
	if n, err := o.normalized(scope); err == nil {
		o = n
	}
	if scope != "application" {
		o.DurationSeconds = 0
	}
	if id != v.EventID || action != v.Action || scope != v.Scope || zone != v.NetworkZone || revision != v.ZoneRevision || *o.Fields != v.Remember || o.DurationSeconds != v.DurationSeconds {
		return policy.Rule{}, "", false, mutationError("preview_mismatch", "Rule fields differ from the reviewed scope; review again")
	}
	if p.Saved {
		for _, x := range e.rules {
			if x.ID == v.Rule.ID && x.Version == v.Rule.Version {
				return v.Rule, v.ScopePreview, true, nil
			}
		}
		return policy.Rule{}, "", false, mutationError("replay_conflict", "The saved rule changed or was deleted since; inspect Rules, do not recreate automatically")
	}
	if !now.Before(v.ExpiresAt) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Review expired; review again")
	}
	r, err := e.requestRuleLocked(generation, id, action, scope, zone, revision, uid, admin, &o)
	if err != nil {
		return policy.Rule{}, "", false, err
	}
	if r.Application.Key != v.Application.Key || r.Application.Revision != v.Application.Revision {
		return policy.Rule{}, "", false, mutationError("executable_changed", "Retained identity differs from the reviewed one")
	}
	candidate := v.Rule
	at := -1
	for i, x := range e.rules {
		if v.Replaces != nil && x.ID == v.Replaces.ID {
			at = i
			if x.Version != v.Replaces.Version {
				at = -2
			}
		} else if x.Preset == nil && canonicalFilter(x.Filter) == canonicalFilter(candidate.Filter) {
			return policy.Rule{}, "", false, mutationError("policy_conflict", "A rule for this scope was created or changed since review; review again")
		}
	}
	if v.Replaces != nil && at < 0 {
		return policy.Rule{}, "", false, mutationError("policy_conflict", "The existing rule changed or was removed since review; review again")
	}
	if v.Replaces == nil && len(e.rules) >= 256 {
		return policy.Rule{}, "", false, mutationError("capacity", "Rule capacity reached")
	}
	if !candidate.Expires.IsZero() && !now.Before(candidate.Expires) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Reviewed rule expiry elapsed")
	}
	_, sentence, err := e.reviewRuleLocked(candidate, now, false)
	if err != nil || e.requestRuleSentence(candidate, v.Replaces, sentence) != v.ScopePreview {
		return policy.Rule{}, "", false, mutationError("policy_conflict", "Overlapping policy changed since review; review again")
	}
	next := append(append([]policy.Rule{}, e.rules...), candidate)
	if at >= 0 {
		next = append([]policy.Rule{}, e.rules...)
		next[at] = candidate
	}
	if err = e.publishRulesLocked(next); err != nil {
		return policy.Rule{}, "", false, err
	}
	// Pending requests from new launches are re-evaluated; the ended source
	// request is not pending and is never approved.
	e.settlePendingLocked("rule " + candidate.ID + " saved from request " + id)
	r.release() // evidence stays for repeat reviews; no open reference remains
	p.Saved = true
	p.ReceiptUntil = now.Add(5 * time.Minute)
	return candidate, v.ScopePreview, false, nil
}
