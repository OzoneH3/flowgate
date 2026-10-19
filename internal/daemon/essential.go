package daemon

import (
	"context"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

const EssentialCapability = "essential-system-networking-v1"

type EssentialPreview struct {
	Token      string                `json:"token"`
	ExpiresAt  time.Time             `json:"expires_at"`
	Revision   string                `json:"revision"`
	Operation  string                `json:"operation"`
	Options    essential.Options     `json:"options"`
	Components []essential.Component `json:"components"`
	Rules      []policy.Rule         `json:"rules"`
	Preserved  []string              `json:"preserved_rule_ids"`
	Issues     []string              `json:"issues"`
}
type EssentialReceipt struct {
	Token     string        `json:"token"`
	Operation string        `json:"operation"`
	RuleIDs   []string      `json:"rule_ids"`
	Rules     []policy.Rule `json:"rules"`
	Removed   []string      `json:"removed_rule_ids"`
}
type EssentialStatus struct {
	Revision   string                `json:"revision"`
	Components []essential.Component `json:"components"`
	RuleIDs    []string              `json:"rule_ids"`
	Issues     []string              `json:"issues"`
}
type essentialPreview struct {
	View      EssentialPreview
	Inventory string
	UID       uint32
	Until     time.Time
	Saved     *EssentialReceipt
}

func (e *Engine) ConfigureEssential(ctx context.Context, env essential.Environment) {
	m := essential.NewManager(env)
	e.Essential = m
	m.Refresh(ctx)
	go m.Run(ctx)
}
func (e *Engine) EssentialStatus() (EssentialStatus, error) {
	if e.Essential == nil {
		return EssentialStatus{}, mutationError("unavailable", "Essential discovery unavailable")
	}
	s := e.Essential.Snapshot()
	out := EssentialStatus{s.Revision, s.Components, []string{}, s.Issues}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rules {
		if r.Preset != nil && r.Preset.Name == essential.Name {
			out.RuleIDs = append(out.RuleIDs, r.ID)
		}
	}
	return out, nil
}
func (e *Engine) essentialSnapshot() (essential.Snapshot, error) {
	if e.Essential == nil {
		return essential.Snapshot{}, mutationError("unavailable", "Essential discovery unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := e.Essential.Refresh(ctx)
	if s.Revision == "" {
		return s, mutationError("unavailable", "Configuration discovery unavailable")
	}
	return s, nil
}
func (e *Engine) PreviewEssential(gen, operation string, o essential.Options, uid uint32) (EssentialPreview, error) {
	if gen != e.Generation {
		return EssentialPreview{}, mutationError("generation_conflict", "Daemon changed")
	}
	if operation != "apply" && operation != "remove" {
		return EssentialPreview{}, mutationError("invalid_request", "Unknown essential operation")
	}
	s, err := e.essentialSnapshot()
	if err != nil {
		return EssentialPreview{}, err
	}
	now := e.Now()
	candidates, issues, err := s.Rules(o, now)
	if err != nil {
		return EssentialPreview{}, mutationError("invalid_request", err.Error())
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.SaveRules == nil {
		return EssentialPreview{}, mutationError("unavailable", "Durable storage required")
	}
	if e.essentialPreviews == nil {
		e.essentialPreviews = map[string]*essentialPreview{}
	}
	own := 0
	for token, p := range e.essentialPreviews {
		if !now.Before(p.Until) {
			delete(e.essentialPreviews, token)
		} else if p.UID == uid {
			own++
		}
	}
	if own >= 16 || len(e.essentialPreviews) >= 256 {
		return EssentialPreview{}, mutationError("limit_exceeded", "Preset preview limit")
	}
	v := EssentialPreview{Token: randomID(), ExpiresAt: now.Add(30 * time.Second), Revision: s.Revision, Operation: operation, Options: o, Components: s.Components, Rules: []policy.Rule{}, Preserved: []string{}, Issues: issues}
	if operation == "remove" {
		for _, r := range e.rules {
			if r.Preset != nil && r.Preset.Name == essential.Name {
				if policy.UneditedPreset(r) {
					v.Rules = append(v.Rules, r)
				} else {
					v.Preserved = append(v.Preserved, r.ID)
					v.Issues = append(v.Issues, "User-edited preset record preserved: "+r.ID)
				}
			}
		}
	} else {
		for _, r := range candidates {
			var old *policy.Rule
			for i := range e.rules {
				other := &e.rules[i]
				if other.ID == r.ID || canonicalFilter(other.Filter) == canonicalFilter(r.Filter) {
					old = other
					break
				}
			}
			if old != nil {
				if old.ID == r.ID && policy.UneditedPreset(*old) && old.Preset.Revision != r.Preset.Revision {
					r.Created = old.Created
					if old.Version == ^uint64(0) {
						return EssentialPreview{}, mutationError("limit_exceeded", "Rule version exhausted")
					}
					r.Version = old.Version + 1
					r.Preset.Digest = policy.PresetDigest(r)
					v.Rules = append(v.Rules, r)
				} else {
					v.Preserved = append(v.Preserved, old.ID)
					if old.Disabled || old.Action != "allow" {
						v.Issues = append(v.Issues, "Existing user/disabled policy preserved; review effective policy: "+old.ID)
					}
				}
				continue
			}
			v.Rules = append(v.Rules, r)
		}
	}
	size := len(e.rules)
	for _, r := range v.Rules {
		found := false
		for _, old := range e.rules {
			if old.ID == r.ID {
				found = true
				break
			}
		}
		if !found {
			size++
		}
	}
	if size > 256 && operation == "apply" {
		return EssentialPreview{}, mutationError("limit_exceeded", "Rule inventory capacity")
	}
	e.essentialPreviews[v.Token] = &essentialPreview{View: v, Inventory: essential.Hash(e.rules), UID: uid, Until: v.ExpiresAt}
	return v, nil
}
func (e *Engine) EssentialReceipt(gen, token string, uid uint32) (EssentialReceipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if gen != e.Generation {
		return EssentialReceipt{}, mutationError("generation_conflict", "Daemon changed")
	}
	p := e.essentialPreviews[token]
	if p == nil || p.UID != uid || p.Saved == nil || !e.Now().Before(p.Until) {
		return EssentialReceipt{}, mutationError("receipt_unknown", "No committed receipt for this token; inspect reserved IDs, never blindly retry")
	}
	if !e.essentialReceiptMatchesLocked(*p.Saved) {
		return EssentialReceipt{}, mutationError("replay_conflict", "Committed preset records changed/removed; no replay")
	}
	return *p.Saved, nil
}
func (e *Engine) essentialReceiptMatchesLocked(r EssentialReceipt) bool {
	for _, saved := range r.Rules {
		found := false
		for _, actual := range e.rules {
			if actual.ID == saved.ID && essential.Hash(actual) == essential.Hash(saved) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	for _, id := range r.Removed {
		for _, actual := range e.rules {
			if actual.ID == id {
				return false
			}
		}
	}
	return true
}
func (e *Engine) ApplyEssential(gen, token, operation string, o essential.Options, uid uint32) (EssentialReceipt, bool, error) {
	if operation != "apply" && operation != "remove" {
		return EssentialReceipt{}, false, mutationError("invalid_request", "Unknown essential operation")
	}
	if e.Enforcement != nil {
		state := e.Enforcement()
		if state.State != "stopped" {
			return EssentialReceipt{}, false, mutationError("protection_active", "Stop protection before changing essential protocol/preset permissions")
		}
	}
	e.creationMu.Lock()
	defer e.creationMu.Unlock()
	if gen != e.Generation {
		return EssentialReceipt{}, false, mutationError("generation_conflict", "Daemon changed")
	}
	e.mu.Lock()
	p := e.essentialPreviews[token]
	if p == nil || p.UID != uid || !e.Now().Before(p.Until) {
		e.mu.Unlock()
		return EssentialReceipt{}, false, mutationError("preview_expired", "Preset preview expired; review again")
	}
	if p.View.Options != o || p.View.Operation != operation {
		e.mu.Unlock()
		return EssentialReceipt{}, false, mutationError("preview_mismatch", "Options or operation changed")
	}
	if p.Saved != nil {
		r := *p.Saved
		ok := e.essentialReceiptMatchesLocked(r)
		e.mu.Unlock()
		if !ok {
			return r, false, mutationError("replay_conflict", "Saved records changed; no replay")
		}
		return r, true, nil
	}
	e.mu.Unlock()
	if operation == "apply" {
		s, err := e.essentialSnapshot()
		if err != nil {
			return EssentialReceipt{}, false, err
		}
		if s.Revision != p.View.Revision {
			return EssentialReceipt{}, false, mutationError("preset_stale", "Service identity/configuration changed; obtain fresh review")
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if essential.Hash(e.rules) != p.Inventory {
		return EssentialReceipt{}, false, mutationError("policy_conflict", "Rule inventory changed; refresh review")
	}
	if !e.Now().Before(p.View.ExpiresAt) {
		return EssentialReceipt{}, false, mutationError("preview_expired", "Review expired")
	}
	receipt := EssentialReceipt{Token: token, Operation: operation, RuleIDs: []string{}, Rules: []policy.Rule{}, Removed: []string{}}
	next := append([]policy.Rule{}, e.rules...)
	for _, r := range p.View.Rules {
		if operation == "remove" {
			for i, old := range next {
				if old.ID == r.ID {
					if old.Version != r.Version || !policy.UneditedPreset(old) {
						return receipt, false, mutationError("policy_conflict", "Owned record edited")
					}
					next = append(next[:i], next[i+1:]...)
					break
				}
			}
			receipt.Removed = append(receipt.Removed, r.ID)
		} else {
			replaced := false
			for i, old := range next {
				if old.ID == r.ID {
					next[i] = r
					replaced = true
					break
				}
			}
			if !replaced {
				next = append(next, r)
			}
			receipt.RuleIDs = append(receipt.RuleIDs, r.ID)
			receipt.Rules = append(receipt.Rules, r)
		}
	}
	if err := e.publishRulesLocked(next); err != nil {
		return receipt, false, err
	}
	e.discardPendingLocked("preset policy changed; held requests drop, no automatic approval")
	e.events = map[string]*Event{}
	p.Saved = &receipt
	p.Until = e.Now().Add(5 * time.Minute)
	return receipt, false, nil
}
func (e *Engine) presetActive(r policy.Rule) bool {
	if r.Preset == nil {
		return true
	}
	// DHCP is a durable reviewed interface/protocol exception shared with the
	// pre-daemon guard, not a sampled executable permission. It remains limited
	// to the approved interface and client port pair until explicit removal.
	if r.Preset.Component == "dhcp" {
		return policy.UneditedPreset(r) && r.Validate() == nil
	}
	if e.Essential == nil {
		return false
	}
	s := e.Essential.Snapshot()
	if !e.Now().Before(s.ValidUntil) {
		return false
	}
	return s.EntryActive(r)
}
func (e *Engine) peerServiceMatches(f identity.Flow, p policy.PeerService) bool {
	reverse := f
	reverse.Direction = "incoming"
	reverse.Local = f.Remote
	reverse.Remote = f.Local
	a := identity.Resolve(reverse)
	return a.VisibilityComplete && a.Application != nil && a.Application.Key == p.Application && a.Application.Revision == p.Revision && a.Principal() != nil && a.Principal().UID == p.UID
}
func presetSentence(r policy.Rule) string {
	return fmt.Sprintf("Essential %s: %s %s %s:%d local%s:%d interface%s; exact application/revision or verified local-service aggregate", r.Preset.Component, r.Filter.Direction, r.Filter.Protocol, r.Filter.RemoteAddress, r.Filter.RemotePort, r.Filter.LocalAddress, r.Filter.LocalPort, r.Filter.InterfaceName)
}

func (e *Engine) ApprovedBootstrap() []policy.BootstrapInterface {
	e.mu.Lock()
	defer e.mu.Unlock()
	return policy.BootstrapFrom(e.rules, e.Now())
}

func (e *Engine) hasPresetRules() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.rules {
		if r.Schema == 5 {
			return true
		}
	}
	return false
}
