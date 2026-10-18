package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"time"
)

const NetworkZoneCapability = "network-zone-policy-v1"

type ZoneTarget struct {
	Zone  string `json:"zone"`
	Scope string `json:"scope"`
}
type ZonePreview struct {
	Token        string                `json:"token"`
	ExpiresAt    time.Time             `json:"expires_at"`
	Rule         policy.Rule           `json:"rule"`
	ScopePreview string                `json:"scope_preview"`
	Enforcement  PolicyCoverage        `json:"enforcement"`
	NetworkZones identity.NetworkZones `json:"network_zones"`
}
type zonePreview struct {
	View  ZonePreview
	UID   uint32
	Admin bool
	Draft string
	Saved bool
	Until time.Time
}

func (e *Engine) zoneRevision(zone, revision string) error {
	if zone != "" && zone != "local" && zone != "internet" {
		return mutationError("invalid_request", "network_zone must be local or internet, or omitted for Any")
	}
	if zone != "" && (revision == "" || revision != e.Zones.Revision) {
		return mutationError("zone_conflict", "Network zone definition changed/missing; review current generation and zone revision")
	}
	return nil
}
func (e *Engine) PreviewZoneRule(generation, revision string, target ZoneTarget, d ObservedDraft, uid uint32, admin bool, h *EnforcementStatus) (ZonePreview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkCreationLocked(generation); err != nil {
		return ZonePreview{}, err
	}
	if err := e.zoneRevision(target.Zone, revision); err != nil {
		return ZonePreview{}, err
	}
	if target.Zone == "" || target.Scope != "machine" && target.Scope != "self" {
		return ZonePreview{}, mutationError("invalid_request", "Explicit local/internet zone and machine/self principal required")
	}
	if target.Scope == "machine" && !admin {
		return ZonePreview{}, mutationError("forbidden", "Machine all-program rules require administrator authority")
	}
	if d.TargetScope != "" || d.NetworkZone != "" || d.ZoneRevision != "" {
		return ZonePreview{}, mutationError("invalid_request", "Zone target supplied separately; no process/application or duplicate zone draft target")
	}
	if _, err := draftBytes(d); err != nil {
		return ZonePreview{}, err
	}
	now := e.Now()
	if d.Expires != nil && !d.Expires.IsZero() && !now.Before(*d.Expires) {
		return ZonePreview{}, mutationError("invalid_rule", "expiry elapsed")
	}
	if e.zonePreviews == nil {
		e.zonePreviews = map[string]*zonePreview{}
	}
	own := 0
	for k, v := range e.zonePreviews {
		if !now.Before(v.Until) {
			delete(e.zonePreviews, k)
		} else if v.UID == uid {
			own++
		}
	}
	if len(e.zonePreviews) >= 256 || own >= 16 || len(e.rules) >= 256 {
		return ZonePreview{}, mutationError("limit_exceeded", "Rule/preview capacity reached")
	}
	r := policy.Rule{ID: "user:" + randomID(), Version: 1, Created: now, Schema: 4, Priority: 100, Action: d.Action, Disabled: d.Disabled, Expires: *d.Expires, Filter: policy.Filter{AllPrograms: true, AllUIDs: target.Scope == "machine", UID: uid, NetworkZone: target.Zone, Direction: d.Direction, Protocol: d.Protocol, RemoteAddress: d.RemoteAddress, LocalPort: *d.LocalPort, RemotePort: *d.RemotePort}}
	if r.Filter.AllUIDs {
		r.Filter.UID = 0
	}
	r, sentence, err := e.reviewRuleLocked(r, now, false)
	if err != nil {
		return ZonePreview{}, mutationError("invalid_rule", err.Error())
	}
	c, _ := coverage(e.Mode, d.Direction, h)
	v := ZonePreview{randomID(), now.Add(30 * time.Second), r, sentence, c, e.Zones}
	raw, _ := json.Marshal([]any{target, d, revision})
	e.zonePreviews[v.Token] = &zonePreview{View: v, UID: uid, Admin: admin, Draft: string(raw), Until: v.ExpiresAt}
	return v, nil
}
func (e *Engine) SaveZoneRule(generation, revision, token string, target ZoneTarget, d ObservedDraft, uid uint32, admin bool) (policy.Rule, string, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.checkCreationLocked(generation); err != nil {
		return policy.Rule{}, "", false, err
	}
	if err := e.zoneRevision(target.Zone, revision); err != nil {
		return policy.Rule{}, "", false, err
	}
	now := e.Now()
	p := e.zonePreviews[token]
	if p == nil || p.UID != uid || p.Admin != admin || !now.Before(p.Until) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Preview unavailable/expired; reconcile reserved rule ID before creating again")
	}
	raw, _ := json.Marshal([]any{target, d, revision})
	if string(raw) != p.Draft {
		return policy.Rule{}, "", false, mutationError("preview_mismatch", "Reviewed zone/principal/draft changed")
	}
	if p.Saved {
		for _, r := range e.rules {
			if r.ID == p.View.Rule.ID && r.Version == p.View.Rule.Version {
				return r, p.View.ScopePreview, true, nil
			}
		}
		return policy.Rule{}, "", false, mutationError("replay_conflict", "Previously created rule changed/deleted; inspect inventory")
	}
	if len(e.rules) >= 256 {
		return policy.Rule{}, "", false, mutationError("limit_exceeded", "Rule capacity reached")
	}
	_, sentence, err := e.reviewRuleLocked(p.View.Rule, now, false)
	if err != nil {
		return policy.Rule{}, "", false, mutationError("policy_conflict", err.Error())
	}
	if sentence != p.View.ScopePreview {
		return policy.Rule{}, "", false, mutationError("policy_conflict", "Overlaps changed; obtain a new preview")
	}
	if !p.View.Rule.Expires.IsZero() && !now.Before(p.View.Rule.Expires) {
		return policy.Rule{}, "", false, mutationError("preview_expired", "Rule expiry elapsed")
	}
	if err = e.publishRulesLocked(append(append([]policy.Rule{}, e.rules...), p.View.Rule)); err != nil {
		return policy.Rule{}, "", false, err
	}
	p.Saved = true
	p.Until = now.Add(5 * time.Minute)
	// Clear previous Once/decided caches. Do not approve or release retained requests.
	e.discardPendingLocked("zone creation invalidated pending attempts; held packets drop")
	e.events = map[string]*Event{}
	return p.View.Rule, p.View.ScopePreview, false, nil
}
