package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

const DecisionZoneCapability = "decision-zone-remember-v1"

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
		if v.State != "awaiting-decision" || !e.Now().Before(v.Deadline) {
			return nil, mutationError("stale_decision", "Request is no longer pending; do not replay")
		}
		return v, nil
	}
	return nil, mutationError("stale_decision", "Pending request no longer available")
}
func (e *Engine) decisionClassification(v *Event, revision, zone string) (identity.NetworkScope, error) {
	if revision != "" && revision != e.Zones.Revision {
		return identity.NetworkScope{}, mutationError("zone_conflict", "Network definition changed; review again")
	}
	if revision == "" {
		return identity.NetworkScope{}, mutationError("zone_conflict", "Explicit current zone revision required")
	}
	current := e.Zones.Classify(v.Flow.Remote.Addr())
	if current != v.Flow.NetworkScope {
		return current, mutationError("zone_conflict", "Held request classification changed; fresh request/review required")
	}
	if zone != "any" && (current.State != "known" || current.Zone != zone) {
		return current, mutationError("zone_mismatch", "Selected zone does not match this held request; no decision or rule saved")
	}
	return current, nil
}
func (e *Engine) PreviewDecision(generation, id, action, scope, zone, revision string, uid uint32, admin bool) (DecisionPreview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if generation != e.Generation {
		return DecisionPreview{}, mutationError("generation_conflict", "Backend changed; reload")
	}
	if (action != "allow" && action != "block") || (scope != "application" && scope != "persistent") || (zone != "any" && zone != "local" && zone != "internet") {
		return DecisionPreview{}, mutationError("invalid_request", "Explicit remembered action/scope/network zone required; Once uses legacy decide")
	}
	if scope == "persistent" && e.SaveRules == nil {
		return DecisionPreview{}, mutationError("unavailable", "Persistent storage unavailable")
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
	a := e.Resolve(v.Flow)
	if a.Application == nil || a.Application.Key == "" || a.Application.Revision == "" || a.Principal() == nil || a.Fingerprint != v.Attribution.Fingerprint {
		return DecisionPreview{}, mutationError("identity_changed", "Pending identity changed; fresh request required")
	}
	rule := policy.Rule{Version: 1, Schema: 2, ID: "user:" + randomID(), Executable: a.Application.Executable, Priority: 100, Action: action, Created: now, Expires: now.Add(time.Hour), Filter: policy.Remembered(v.Flow, a)}
	if scope == "persistent" {
		rule.Expires = time.Time{}
	}
	if zone != "any" {
		rule.Schema = 4
		rule.Filter.NetworkZone = zone
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
	view := DecisionPreview{Token: randomID(), ExpiresAt: expiry, Generation: generation, EventID: id, Action: action, Scope: scope, NetworkZone: zone, ZoneRevision: revision, ConnectionNetwork: network, Rule: rule, ScopePreview: sentence}
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
func (e *Engine) DecideReviewed(generation, id, action, scope, zone, revision, token string, uid uint32, admin bool) (Event, policy.Rule, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, err := e.decisionPreviewFor(generation, token, uid, admin)
	if err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	v := p.View
	if id != v.EventID || action != v.Action || scope != v.Scope || zone != v.NetworkZone || revision != v.ZoneRevision {
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
	out, err := e.decideLocked(id, action, scope, uid, admin, &v.Rule, v.ScopePreview, v.ExpiresAt)
	if err != nil {
		return Event{}, policy.Rule{}, false, err
	}
	p.Committed = &out
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
