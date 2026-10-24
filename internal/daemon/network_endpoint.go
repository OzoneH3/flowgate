package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net/netip"
	"time"
)

const NetworkEndpointCapability = "network-endpoint-policy-v1"

type EndpointDraft struct {
	Action        string     `json:"action"`
	RemoteAddress string     `json:"remote_address"`
	RemotePort    uint16     `json:"remote_port"`
	Expires       *time.Time `json:"expires"`
}
type EndpointPreview struct {
	Token        string         `json:"token"`
	ExpiresAt    time.Time      `json:"expires_at"`
	Rule         policy.Rule    `json:"rule"`
	ScopePreview string         `json:"scope_preview"`
	Enforcement  PolicyCoverage `json:"enforcement"`
}
type endpointPreview struct {
	View   EndpointPreview
	UID    uint32
	Draft  string
	Policy string
	Saved  bool
	Until  time.Time
}

func endpointSentence(r policy.Rule) string {
	until := "until explicitly deleted"
	if !r.Expires.IsZero() {
		until = "until " + r.Expires.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s outgoing TCP to %s for all users and programs, including kernel and unidentified traffic; %s. %s Same-host traffic retains existing localhost policy. This is not a CIFS-service, share or application permission. Removal/expiry affects new admissions and reconnects; already admitted TCP connections may continue. Saved to disk.", r.Action, netip.AddrPortFrom(netip.MustParseAddr(r.Filter.RemoteAddress), r.Filter.RemotePort), until, policy.NetworkEndpointPrecedence)
}
func endpointDraft(d EndpointDraft, now time.Time) (EndpointDraft, string, error) {
	if d.Expires == nil || (d.Action != "allow" && d.Action != "block") || d.RemotePort == 0 || len(d.RemoteAddress) > 64 {
		return d, "", mutationError("invalid_request", "Explicit Allow/Deny, IP, TCP port and expiry (zero for persistent) required")
	}
	a, err := netip.ParseAddr(d.RemoteAddress)
	if err != nil || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsLoopback() {
		return d, "", mutationError("invalid_request", "One non-loopback unicast IP required; no hostname, CIDR, wildcard or zone ID")
	}
	d.RemoteAddress = a.Unmap().String()
	expiry := d.Expires.UTC()
	d.Expires = &expiry
	if !expiry.IsZero() && (!now.Before(expiry) || expiry.After(now.Add(365*24*time.Hour))) {
		return d, "", mutationError("invalid_request", "Expiry must be future within 365 days, or zero for persistent")
	}
	b, _ := json.Marshal(d)
	return d, string(b), nil
}

// Policy hash binds the entire configured rule set, including foreign and
// disabled rules. This admin-only protocol discloses no foreign-policy token.
func (e *Engine) endpointPolicyLocked() string {
	b, _ := json.Marshal(e.rules)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (e *Engine) PreviewEndpointRule(generation string, d EndpointDraft, uid uint32, admin bool, h *EnforcementStatus) (EndpointPreview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !admin {
		return EndpointPreview{}, mutationError("forbidden", "Network endpoint authority requires configured administrator")
	}
	if err := e.checkCreationLocked(generation); err != nil {
		return EndpointPreview{}, err
	}
	now := e.Now()
	d, raw, err := endpointDraft(d, now)
	if err != nil {
		return EndpointPreview{}, err
	}
	if e.endpointPreviews == nil {
		e.endpointPreviews = map[string]*endpointPreview{}
	}
	own := 0
	for k, p := range e.endpointPreviews {
		if !now.Before(p.Until) {
			delete(e.endpointPreviews, k)
		} else if p.UID == uid {
			own++
		}
	}
	if len(e.endpointPreviews) >= 256 || own >= 16 || len(e.rules) >= 256 {
		return EndpointPreview{}, mutationError("limit_exceeded", "Endpoint preview/rule capacity reached")
	}
	for _, r := range e.rules {
		if r.NetworkEndpoint && r.Filter.RemoteAddress == d.RemoteAddress && r.Filter.RemotePort == d.RemotePort {
			return EndpointPreview{}, mutationError("duplicate_scope", "Endpoint already configured; conditionally delete it before recreating")
		}
	}
	r := policy.Rule{NetworkEndpoint: true, Schema: policy.NetworkEndpointSchema, ID: "endpoint:" + randomID(), Version: 1, Created: now, Priority: 100, Action: d.Action, Expires: *d.Expires, Filter: policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "tcp", RemoteAddress: d.RemoteAddress, RemotePort: d.RemotePort}}
	if err := r.Validate(); err != nil {
		return EndpointPreview{}, mutationError("invalid_rule", err.Error())
	}
	c, _ := coverage(e.Mode, "outgoing", h)
	v := EndpointPreview{randomID(), now.Add(30 * time.Second), r, endpointSentence(r), c}
	e.endpointPreviews[v.Token] = &endpointPreview{View: v, UID: uid, Draft: raw, Policy: e.endpointPolicyLocked(), Until: v.ExpiresAt}
	return v, nil
}
func (e *Engine) SaveEndpointRule(generation, token string, d EndpointDraft, uid uint32, admin bool) (policy.Rule, string, bool, error) {
	e.mu.Lock()
	defer e.unlockAndSettle()
	fail := func(err error) (policy.Rule, string, bool, error) { return policy.Rule{}, "", false, err }
	if !admin {
		return fail(mutationError("forbidden", "Network endpoint authority requires configured administrator"))
	}
	if err := e.checkCreationLocked(generation); err != nil {
		return fail(err)
	}
	now := e.Now()
	_, raw, err := endpointDraft(d, now)
	if err != nil {
		return fail(err)
	}
	p := e.endpointPreviews[token]
	if p == nil || p.UID != uid || !now.Before(p.Until) {
		return fail(mutationError("preview_expired", "Preview unavailable or expired; inspect reserved rule ID before retrying creation"))
	}
	if raw != p.Draft {
		return fail(mutationError("preview_mismatch", "Endpoint draft changed since review"))
	}
	if p.Saved {
		for _, r := range e.rules {
			if r.ID == p.View.Rule.ID {
				a, _ := json.Marshal(r)
				b, _ := json.Marshal(p.View.Rule)
				if string(a) == string(b) {
					return r, p.View.ScopePreview, true, nil
				}
				break
			}
		}
		return fail(mutationError("replay_conflict", "Previously created endpoint changed or was deleted"))
	}
	if e.endpointPolicyLocked() != p.Policy {
		return fail(mutationError("policy_conflict", "Configured policy changed; obtain a new endpoint preview"))
	}
	if len(e.rules) >= 256 {
		return fail(mutationError("limit_exceeded", "Rule capacity reached"))
	}
	if err := p.View.Rule.Validate(); err != nil {
		return fail(mutationError("invalid_rule", err.Error()))
	}
	if err := e.publishRulesLocked(append(append([]policy.Rule{}, e.rules...), p.View.Rule)); err != nil {
		return fail(mutationError("persistence_failed", err.Error()))
	}
	p.Saved = true
	p.Until = now.Add(5 * time.Minute)
	// Clear cached ordinary rule verdicts. Once/lease admissions remain bounded by
	// the current pure evaluator's endpoint result before any cached reuse.
	e.resetCachedLocked("network endpoint rule created")
	return p.View.Rule, p.View.ScopePreview, false, nil
}

// Endpoint policy does not depend on process attribution. Evaluate it before
// potentially slow or unavailable ownership collectors, using the same locked
// decision path and current policy as every other observation. Queue and
// interception capacity/deadline bounds still apply; this is not delivery proof.
func (e *Engine) tryNetworkEndpoint(f identity.Flow, token string) (Event, bool) {
	if f.Protocol != "tcp" || f.Direction != "outgoing" {
		return Event{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	present := false
	for _, r := range e.rules {
		if r.NetworkEndpoint {
			present = true
			break
		}
	}
	if !present {
		return Event{}, false
	}
	if _, id, _ := policy.EvaluateNetworkEndpoint(e.rules, f, e.Now()); id == "" {
		return Event{}, false
	}
	a := identity.Attribution{Status: "not-requested", ReasonCode: identity.ReasonAttributionNotRequired, Reason: "Explicit administrator network endpoint policy applies without application attribution; kernel origin and userspace ownership were not observed"}
	return e.observeResolvedLocked(f, token, a), true
}
