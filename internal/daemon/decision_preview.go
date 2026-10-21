package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

const DecisionZoneCapability = "decision-zone-remember-v1"

// DecisionRememberFieldsCapability: NetLimiter Remember chooses which connection
// properties (source application always; remote address, port, protocol) the
// remembered rule keeps, and how long a temporary rule lives.
const DecisionRememberFieldsCapability = "decision-remember-fields-v1"

// RememberFields true = keep that property exactly; false = any.
type RememberFields struct {
	Address  bool `json:"address"`
	Port     bool `json:"port"`
	Protocol bool `json:"protocol"`
	// Process binds the rule to the requesting process instance (session-bound).
	Process bool `json:"process"`
}

// RememberOptions are bound to the decision preview token.
type RememberOptions struct {
	Fields          *RememberFields `json:"remember,omitempty"`
	DurationSeconds int64           `json:"duration_seconds,omitempty"`
}

func (o RememberOptions) normalized(scope string) (RememberOptions, error) {
	if o.Fields == nil {
		o.Fields = &RememberFields{Address: true, Port: true, Protocol: true}
	}
	if scope == "persistent" && o.DurationSeconds != 0 {
		return o, mutationError("invalid_request", "Persistent remember has no duration")
	}
	if scope == "application" {
		if o.DurationSeconds == 0 {
			o.DurationSeconds = 3600
		}
		if o.DurationSeconds < 60 || o.DurationSeconds > 365*24*3600 {
			return o, mutationError("invalid_request", "duration_seconds must be 60..31536000")
		}
	}
	return o, nil
}
func (o RememberOptions) equal(p RememberOptions) bool {
	return o.DurationSeconds == p.DurationSeconds && (o.Fields == nil) == (p.Fields == nil) && (o.Fields == nil || *o.Fields == *p.Fields)
}

type DecisionPreview struct {
	Token             string                `json:"token"`
	ExpiresAt         time.Time             `json:"expires_at"`
	Generation        string                `json:"generation"`
	EventID           string                `json:"event_id"`
	Action            string                `json:"action"`
	Scope             string                `json:"scope"`
	NetworkZone       string                `json:"network_zone"`
	ZoneRevision      string                `json:"zone_revision"`
	ConnectionNetwork identity.NetworkScope `json:"connection_network"`
	Rule              policy.Rule           `json:"rule"`
	ScopePreview      string                `json:"scope_preview"`
	Remember          RememberFields        `json:"remember"`
	DurationSeconds   int64                 `json:"duration_seconds,omitempty"`
	// Summary is the compact scope shown before submission.
	Summary  string          `json:"summary"`
	Replaces *RuleVersionRef `json:"replaces"`
}
type DecisionReceipt struct {
	State     string          `json:"state"`
	Preview   DecisionPreview `json:"preview"`
	Decision  *Event          `json:"decision,omitempty"`
	SavedRule *policy.Rule    `json:"saved_rule,omitempty"`
}
type decisionPreview struct {
	View        DecisionPreview
	UID         uint32
	Admin       bool
	Fingerprint string
	Flow        identity.Flow
	Until       time.Time
	Committed   *Event
	Settled     []SettledRequest
	// settledDone closes once Settled is final for a committed decision; the
	// committing call may still be settling other requests outside e.mu.
	settledDone chan struct{}
}

func (e *Engine) pruneDecisionPreviews(now time.Time) {
	for token, p := range e.decisionPreviews {
		if !now.Before(p.Until) {
			delete(e.decisionPreviews, token)
		}
	}
}
func (e *Engine) pendingDecision(id string, uid uint32, admin bool) (*Event, error) {
	for _, v := range e.events {
		if v.ID != id {
			continue
		}
		if !admin && !owned(v.Attribution, uid) {
			return nil, mutationError("forbidden", "Pending request belongs to another principal")
		}
		// Ownership is resolved before this lookup, so a deadline that passed during
		// that resolution is reported as such, not as a generic stale request.
		if !e.Now().Before(v.Deadline) {
			if v.State == "awaiting-decision" {
				return nil, e.rejectPendingDeadlineLocked(v)
			}
			return nil, mutationError("stale_decision", "Request deadline passed during revalidation; no decision or rule saved")
		}
		if v.State != "awaiting-decision" {
			return nil, mutationError("stale_decision", "Request is no longer pending; do not replay")
		}
		return v, nil
	}
	return nil, mutationError("stale_decision", "Pending request no longer available")
}
func (e *Engine) decisionClassification(v *Event, revision, zone string) (identity.NetworkScope, error) {
	e.refreshZonesLocked()
	if revision != "" && revision != e.Zones.Revision {
		return identity.NetworkScope{}, mutationError("zone_conflict", "Network definition changed; review again")
	}
	if revision == "" {
		return identity.NetworkScope{}, mutationError("zone_conflict", "Explicit current zone revision required")
	}
	current := e.Zones.ClassifyFlow(v.Flow)
	if current != v.Flow.NetworkScope {
		return current, mutationError("zone_conflict", "Held request classification changed; fresh request/review required")
	}
	if zone != "any" && (current.State != "known" || current.Zone != zone) {
		return current, mutationError("zone_mismatch", "Selected zone does not match this held request; no decision or rule saved")
	}
	return current, nil
}
func (e *Engine) PreviewDecision(generation, id, action, scope, zone, revision string, uid uint32, admin bool, opts ...RememberOptions) (DecisionPreview, error) {
	var o RememberOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	e.lockResolved(e.requestSelection(id, uid, admin, false))
	defer e.unlockResolved()
	if generation != e.Generation {
		return DecisionPreview{}, mutationError("generation_conflict", "Backend changed; reload")
	}
	if (action != "allow" && action != "block") || (scope != "application" && scope != "persistent") || (zone != "any" && zone != "local" && zone != "internet") {
		return DecisionPreview{}, mutationError("invalid_request", "Explicit remembered action/scope/network zone required; Once uses legacy decide")
	}
	if scope == "persistent" && e.SaveRules == nil {
		return DecisionPreview{}, mutationError("unavailable", "Persistent storage unavailable")
	}
	o, err := o.normalized(scope)
	if err != nil {
		return DecisionPreview{}, err
	}
	now := e.Now()
	e.pruneDecisionPreviews(now)
	n := 0
	for _, p := range e.decisionPreviews {
		if p.UID == uid {
			n++
		}
	}
	if n >= 16 || len(e.decisionPreviews) >= 256 {
		return DecisionPreview{}, mutationError("capacity", "Decision preview capacity reached; wait for expiry")
	}
	v, err := e.pendingDecision(id, uid, admin)
	if err != nil {
		return DecisionPreview{}, err
	}
	network, err := e.decisionClassification(v, revision, zone)
	if err != nil {
		return DecisionPreview{}, err
	}
	a, ok := e.resolvedEventLocked(v)
	if !ok {
		return DecisionPreview{}, retryChangedRequest()
	}
	if !e.Now().Before(v.Deadline) {
		return DecisionPreview{}, e.rejectPendingDeadlineLocked(v)
	}
	if a.Application == nil || a.Application.Key == "" || a.Application.Revision == "" || a.Principal() == nil || a.Fingerprint != v.Attribution.Fingerprint {
		return DecisionPreview{}, e.rejectPendingBindingLocked(v, a)
	}
	// Never an application-wide rule for a shared runtime whose app is unverified.
	if why := identity.RuntimeRuleBlocked(a.Application); why != "" {
		return DecisionPreview{}, mutationError(identity.CodeIdentityUnverifiable, why)
	}
	rule := policy.Rule{Version: 1, Schema: 2, ID: "user:" + randomID(), Executable: a.Application.Executable, Invocation: attributionInvocation(a), Priority: 100, Action: action, Created: now, Expires: now.Add(time.Duration(o.DurationSeconds) * time.Second), Filter: policy.Remembered(v.Flow, a)}
	if scope == "persistent" {
		rule.Expires = time.Time{}
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
	if o.Fields.Process {
		if zone != "any" {
			return DecisionPreview{}, mutationError("invalid_request", "Process remember has no zone choice")
		}
		if !a.VisibilityComplete || len(a.Owners) != 1 {
			return DecisionPreview{}, mutationError("unsupported_process", "Process remember needs one verified owning process")
		}
		if _, err := e.attachProcessTarget(a.Owners[0], &rule); err != nil {
			return DecisionPreview{}, err
		}
	}
	if zone != "any" {
		rule.Schema = 4
		rule.Filter.NetworkZone = zone
		e.bindZoneModel(&rule)
	}
	// Remembering a scope that already has a user rule updates that exact rule
	// (same ID, version+1) instead of failing or adding a duplicate.
	var replaces *RuleVersionRef
	for _, old := range e.rules {
		if old.Preset == nil && canonicalFilter(old.Filter) == canonicalFilter(rule.Filter) {
			if old.Version == ^uint64(0) {
				return DecisionPreview{}, mutationError("capacity", "Rule version exhausted")
			}
			rule.ID, rule.Created, rule.Priority, rule.Version = old.ID, old.Created, old.Priority, old.Version+1
			replaces = &RuleVersionRef{old.ID, old.Version}
			break
		}
	}
	expiry := now.Add(30 * time.Second)
	if v.Deadline.Before(expiry) {
		expiry = v.Deadline
	}
	zoneLabel := map[string]string{"any": "Any network", "local": "Local Network", "internet": "Internet"}[zone]
	lifetime := "one hour"
	if scope == "persistent" {
		lifetime = "persistent until disabled/deleted"
	}
	sentence := fmt.Sprintf("Remember %s; rule applies to %s; application %s revision %s UID %d, %s %s, peer %s local service %d remote service %d; expiry %s. Current held request decided separately; existing admissions unchanged.", lifetime, zoneLabel, rule.Filter.Application, rule.Filter.Revision, rule.Filter.UID, rule.Filter.Direction, rule.Filter.Protocol, rule.Filter.RemoteAddress, rule.Filter.LocalPort, rule.Filter.RemotePort, rule.Expires.Format(time.RFC3339Nano))
	if replaces != nil {
		sentence = fmt.Sprintf("Updates existing rule %s (version %d). ", replaces.ID, replaces.Version) + sentence
	}
	// The remembered rule must actually decide this request; otherwise (for
	// example a higher-weight Ask/Deny keeps winning) it would be a silent no-op.
	simulated := append([]policy.Rule{}, e.rules...)
	if replaces != nil {
		for i := range simulated {
			if simulated[i].ID == replaces.ID {
				simulated[i] = rule
			}
		}
	} else {
		simulated = append(simulated, rule)
	}
	if _, winner, _ := e.evaluateLocked(simulated, v.Flow, a, now); winner != rule.ID {
		w := e.ruleLocked(winner)
		why := winner
		if w != nil {
			why = fmt.Sprintf("%s (%s, weight %d)", w.ID, w.Action, w.Weight())
		}
		return DecisionPreview{}, mutationError("policy_conflict", "Remembered rule would not decide this request: "+why+" still wins; change that rule or remember a higher-weight scope")
	}
	duration := int64(0)
	if scope == "application" {
		duration = o.DurationSeconds
	}
	view := DecisionPreview{Token: randomID(), ExpiresAt: expiry, Generation: generation, EventID: id, Action: action, Scope: scope, NetworkZone: zone, ZoneRevision: revision, ConnectionNetwork: network, Rule: rule, ScopePreview: sentence, Remember: *o.Fields, DurationSeconds: duration, Summary: rememberSummary(a.Application.Name, rule, scope, duration), Replaces: replaces}
	if e.decisionPreviews == nil {
		e.decisionPreviews = map[string]*decisionPreview{}
	}
	e.decisionPreviews[view.Token] = &decisionPreview{View: view, UID: uid, Admin: admin, Fingerprint: a.Fingerprint, Flow: v.Flow, Until: expiry}
	return view, nil
}
func (e *Engine) decisionPreviewFor(generation, token string, uid uint32, admin bool) (*decisionPreview, error) {
	if generation != e.Generation {
		return nil, mutationError("generation_conflict", "Backend changed; reload")
	}
	p := e.decisionPreviews[token]
	if p == nil {
		return nil, mutationError("preview_missing", "Decision receipt unavailable; inspect current status, never blindly replay")
	}
	if p.UID != uid || p.Admin != admin {
		return nil, mutationError("forbidden", "Decision preview belongs to another principal/role")
	}
	if !e.Now().Before(p.Until) {
		delete(e.decisionPreviews, token)
		return nil, mutationError("preview_expired", "Preview/receipt expired; fresh review required")
	}
	return p, nil
}
func (e *Engine) DecideReviewed(generation, id, action, scope, zone, revision, token string, uid uint32, admin bool, opts ...RememberOptions) (Event, policy.Rule, bool, error) {
	v, r, replayed, _, err := e.DecideReviewedSettled(generation, id, action, scope, zone, revision, token, uid, admin, opts...)
	return v, r, replayed, err
}

// DecideReviewedSettled also returns the waiting requests the remembered rule
// settled. A replayed (already committed) decision reports the same list.
func (e *Engine) DecideReviewedSettled(generation, id, action, scope, zone, revision, token string, uid uint32, admin bool, opts ...RememberOptions) (Event, policy.Rule, bool, []SettledRequest, error) {
	e.lockResolved(e.requestSelection(id, uid, admin, true))
	defer e.unlockResolved()
	defer e.collectSettledLocked()()
	v, r, replayed, err := e.decideReviewedLocked(generation, id, action, scope, zone, revision, token, uid, admin, opts...)
	p := e.decisionPreviews[token]
	if replayed && p != nil && p.settledDone != nil && !e.awaitUnlocked(p.settledDone) {
		return v, r, true, nil, mutationError("receipt_pending", "Decision committed; its settlement receipt is still being completed. Refresh the list; do not resubmit")
	}
	e.followUpSettleLocked()
	settled := e.settledLocked()
	if p != nil && err == nil {
		if replayed {
			settled = p.Settled
		} else if p.settledDone != nil {
			p.Settled = settled
			close(p.settledDone)
		}
	}
	return v, r, replayed, settled, err
}

func (e *Engine) decideReviewedLocked(generation, id, action, scope, zone, revision, token string, uid uint32, admin bool, opts ...RememberOptions) (Event, policy.Rule, bool, error) {
	var o RememberOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	p, err := e.decisionPreviewFor(generation, token, uid, admin)
	if err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	v := p.View
	o, nerr := o.normalized(scope)
	if nerr != nil {
		return Event{}, policy.Rule{}, false, nerr
	}
	if scope != "application" {
		o.DurationSeconds = 0
	}
	if id != v.EventID || action != v.Action || scope != v.Scope || zone != v.NetworkZone || revision != v.ZoneRevision || *o.Fields != v.Remember || o.DurationSeconds != v.DurationSeconds {
		return Event{}, policy.Rule{}, false, mutationError("preview_mismatch", "Decision fields differ from reviewed scope")
	}
	if p.Committed != nil {
		return *p.Committed, v.Rule, true, nil
	}
	current, err := e.pendingDecision(id, uid, admin)
	if err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	if current.Flow != p.Flow || current.Attribution.Fingerprint != p.Fingerprint {
		return Event{}, policy.Rule{}, false, mutationError("identity_changed", "Pending request binding changed")
	}
	if _, err = e.decisionClassification(current, revision, zone); err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	out, err := e.decideLocked(id, action, scope, uid, admin, &v.Rule, v.ScopePreview, v.ExpiresAt, ForAWhileDuration)
	if err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	p.Committed = &out
	p.settledDone = make(chan struct{})
	p.Until = e.Now().Add(5 * time.Minute)
	return out, v.Rule, false, nil
}
func (e *Engine) DecisionStatus(generation, token string, uid uint32, admin bool) (DecisionReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, err := e.decisionPreviewFor(generation, token, uid, admin)
	if err != nil {
		return DecisionReceipt{}, err
	}
	r := DecisionReceipt{State: "pending", Preview: p.View}
	if p.Committed != nil {
		r.State = "committed"
		r.Decision = p.Committed
		rule := p.View.Rule
		r.SavedRule = &rule
	}
	return r, nil
}

// rememberSummary is the compact scope shown before a Remember is submitted.
func rememberSummary(app string, r policy.Rule, scope string, duration int64) string {
	f := r.Filter
	dir := map[string]string{"incoming": "In", "outgoing": "Out"}[f.Direction]
	addr := "any address"
	if f.RemoteAddress != "*" && f.RemoteAddress != "" {
		addr = f.RemoteAddress
	}
	port := "any port"
	if f.Direction == "incoming" && f.LocalPort != 0 {
		port = fmt.Sprintf("local port %d", f.LocalPort)
	} else if f.Direction == "outgoing" && f.RemotePort != 0 {
		port = fmt.Sprintf("port %d", f.RemotePort)
	}
	proto := map[string]string{"*": "TCP+UDP", "tcp": "TCP", "udp": "UDP"}[f.Protocol]
	zone := "all zones"
	if f.NetworkZone != "" {
		zone = map[string]string{"local": "Local Network", "internet": "Internet"}[f.NetworkZone] + " only"
	}
	life := "persistent"
	if scope == "application" {
		life = "for " + (time.Duration(duration) * time.Second).String()
	}
	act := map[string]string{"allow": "Allow", "block": "Deny", "ask": "Ask"}[r.Action]
	return fmt.Sprintf("%s %s · %s · %s · %s · %s · %s · %s", act, app, dir, addr, port, proto, zone, life)
}
