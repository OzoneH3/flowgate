package daemon

import (
	"flowgate/internal/policy"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func canonicalFilter(f policy.Filter) policy.Filter {
	if f.Remote != "" {
		if ep, err := netip.ParseAddrPort(f.Remote); err == nil {
			f.RemoteAddress = ep.Addr().Unmap().String()
			f.RemotePort = ep.Port()
			f.Remote = ""
		}
	}
	if f.RemoteAddress == "" {
		f.RemoteAddress = "*"
	}
	if a, err := netip.ParseAddr(f.RemoteAddress); err == nil {
		f.RemoteAddress = a.Unmap().String()
	} else if p, err := netip.ParsePrefix(f.RemoteAddress); err == nil {
		f.RemoteAddress = p.Masked().String()
		if p.Bits() == p.Addr().BitLen() {
			f.RemoteAddress = p.Addr().Unmap().String()
		}
	}
	return f
}
func duplicate(rules []policy.Rule, r policy.Rule) string {
	for _, other := range rules {
		if other.ID != r.ID && canonicalFilter(other.Filter) == canonicalFilter(r.Filter) {
			return other.ID
		}
	}
	return ""
}

func RuleSentence(r policy.Rule) string {
	f := r.Filter
	target := "all process instances"
	if f.AllPrograms {
		target = "all programs for principal UID " + fmt.Sprint(f.UID)
		if f.AllUIDs {
			target = "all programs/all principal UIDs (administrator machine scope)"
		}
	}
	if !f.Process.IsZero() {
		target = processLabel(f.Process)
	}
	port := func(p uint16) string {
		if p == 0 {
			return "any"
		}
		return fmt.Sprint(p)
	}
	address := f.RemoteAddress
	if address == "" || address == "*" {
		address = "any address"
	}
	expiry := "until disabled/deleted"
	if !f.Process.IsZero() {
		expiry = "until process exit/identity change or daemon session ends (not persistent)"
	}
	if !r.Expires.IsZero() {
		if f.Process.IsZero() {
			expiry = "until " + r.Expires.UTC().Format(time.RFC3339)
		} else {
			expiry += "; no later than " + r.Expires.UTC().Format(time.RFC3339)
		}
	}
	state := "enabled"
	if r.Disabled {
		state = "disabled"
	}
	zone := "Any network zone"
	if f.NetworkZone != "" {
		zone = "configured " + f.NetworkZone + " zone"
	}
	identityText := fmt.Sprintf("application %s, revision %s, UID %d", f.Application, f.Revision, f.UID)
	if f.AllPrograms {
		identityText = target
	}
	return zone + ". " + fmt.Sprintf("Target: %s. Matching process rules override application rules, which override all-program zone rules; within each tier highest priority then smallest ID. %s %s %s for %s; remote %s, local port %s, remote port %s; any local address/interface; %s (%s). Priority %d; highest priority wins, then smallest rule ID. Approved TCP connections continue.", target, strings.ToUpper(r.Action), f.Direction, protocolLabel(f.Protocol), identityText, address, port(f.LocalPort), port(f.RemotePort), expiry, state, r.Priority)
}

// EditRule is used for both authoritative preview and commit. Creation derives
// immutable identity from a currently attributable pending request. Edits require
// a version and preserve application/revision/UID/direction, ID and creation time.
func (e *Engine) EditRule(id, eventID string, expected *uint64, candidate policy.Rule, uid uint32, admin, commit bool) (policy.Rule, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.SaveRules == nil {
		return policy.Rule{}, "", fmt.Errorf("durable rule editing unavailable")
	}
	now := e.Now()
	e.expire(now)
	index := -1
	expiryUnchanged := false
	if id != "" {
		for i, r := range e.rules {
			if r.ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			return policy.Rule{}, "", mutationError("not_found", "rule no longer exists")
		}
		old := e.rules[index]
		expiryUnchanged = candidate.Expires.Equal(old.Expires)
		if !admin && (old.Filter.AllUIDs || old.Filter.UID != uid) {
			return policy.Rule{}, "", mutationError("forbidden", "not authorized")
		}
		if expected == nil || *expected != old.Version {
			return policy.Rule{}, "", mutationError("version_conflict", "stale rule version; reload before editing")
		}
		if old.Filter.Protocol == "*" && candidate.Filter.Protocol != "*" {
			return policy.Rule{}, "", mutationError("protocol_scope_changed", "Existing TCP+UDP rule must preserve protocol *; use a fresh observed preview to create a different protocol scope")
		}
		if candidate.Filter.NetworkZone != old.Filter.NetworkZone || candidate.Filter.AllPrograms != old.Filter.AllPrograms || candidate.Filter.AllUIDs != old.Filter.AllUIDs {
			return policy.Rule{}, "", mutationError("zone_scope_changed", "Zone and principal scope are immutable on edit; create a fresh reviewed target to change scope")
		}
		if candidate.Filter.Process != old.Filter.Process {
			return policy.Rule{}, "", mutationError("immutable_target", "Process/application target is immutable; obtain a new creation preview")
		}
		if !old.Filter.Process.IsZero() && !candidate.Disabled {
			if e.targetStateLocked(old).State != "active" {
				return policy.Rule{}, "", mutationError("target_inactive", "Process target inactive; cannot enable or edit an active permission")
			}
			if err := e.verifyProcessEditLocked(old.Filter.Process); err != nil {
				return policy.Rule{}, "", err
			}
		}
		if candidate.Filter.Application != old.Filter.Application || candidate.Filter.Revision != old.Filter.Revision || candidate.Filter.UID != old.Filter.UID || candidate.Filter.Direction != old.Filter.Direction || candidate.Filter.Process != old.Filter.Process {
			return policy.Rule{}, "", fmt.Errorf("application/revision/UID/direction/process target are immutable")
		}
		if candidate.ID != "" && candidate.ID != id {
			return policy.Rule{}, "", fmt.Errorf("immutable rule ID")
		}
		candidate.ID = id
		candidate.Created = old.Created
		candidate.Executable = old.Executable
		if old.Version == ^uint64(0) {
			return policy.Rule{}, "", fmt.Errorf("rule version exhausted; delete and create a new rule")
		}
		candidate.Version = old.Version + 1
		if candidate.Expires.Before(now) && !candidate.Expires.IsZero() && !candidate.Expires.Equal(old.Expires) {
			return policy.Rule{}, "", fmt.Errorf("changed expiry must be in the future; unchanged expired rules remain expired")
		}
	} else {
		if len(e.rules) >= 256 {
			return policy.Rule{}, "", fmt.Errorf("rule capacity reached")
		}
		var found *Event
		for _, v := range e.events {
			if v.ID == eventID {
				found = v
				break
			}
		}
		if found == nil || found.State != "awaiting-decision" || !now.Before(found.Deadline) {
			return policy.Rule{}, "", fmt.Errorf("stale pending request; create from a new attempt")
		}
		if !admin && !owned(found.Attribution, uid) {
			return policy.Rule{}, "", mutationError("forbidden", "not authorized")
		}
		a := e.Resolve(found.Flow)
		if !e.Now().Before(found.Deadline) || a.Application == nil || a.Principal() == nil || a.Fingerprint != found.Attribution.Fingerprint {
			return policy.Rule{}, "", fmt.Errorf("pending application identity changed")
		}
		if !candidate.Filter.Process.IsZero() {
			return policy.Rule{}, "", mutationError("unsupported_process", "Create process rules through verified Activity preview")
		}
		basis := policy.Remembered(found.Flow, a)
		if candidate.Filter.AllPrograms || candidate.Filter.AllUIDs {
			return policy.Rule{}, "", mutationError("invalid_request", "All-program creation requires a zone preview")
		}
		if candidate.Filter.Application != basis.Application || candidate.Filter.Revision != basis.Revision || candidate.Filter.UID != basis.UID || candidate.Filter.Direction != basis.Direction {
			return policy.Rule{}, "", fmt.Errorf("identity must match the pending application/revision/UID/direction")
		}
		candidate.ID = "user:" + randomID()
		candidate.Created = now
		candidate.Version = 1
		candidate.Executable = a.Application.Executable
		if !candidate.Expires.IsZero() && !now.Before(candidate.Expires) {
			return policy.Rule{}, "", fmt.Errorf("expiry must be in the future")
		}
	}
	candidate, sentence, err := e.reviewRuleLocked(candidate, now, expiryUnchanged)
	if err != nil {
		return policy.Rule{}, "", err
	}
	if !commit {
		return candidate, sentence, nil
	}
	next := append([]policy.Rule{}, e.rules...)
	if index < 0 {
		next = append(next, candidate)
	} else {
		next[index] = candidate
	}
	if err := e.publishRulesLocked(next); err != nil {
		return policy.Rule{}, "", err
	}
	// Keep pending IDs so a newly created scoped rule can release the selected
	// retained packet. Re-evaluate each pending attempt under current identity;
	// final release still revalidates the fingerprint and original deadline.
	for key, v := range e.events {
		if v.State != "awaiting-decision" {
			delete(e.events, key)
			continue
		}
		a := e.Resolve(v.Flow)
		if a.Fingerprint != v.Attribution.Fingerprint || a.Application == nil {
			e.recordFinal(v, "block", "identity_changed", "", "identity changed during rule edit; held packets drop", nil, nil, "deferred", "")
			delete(e.events, key)
			continue
		}
		action, effective, conflicts := e.evaluateLocked(e.rules, v.Flow, a, e.Now())
		v.Conflicts = conflicts
		if action == "allow" || action == "block" {
			v.Rule = effective
			v.Reason = "decided by committed rule edit; FlowGate permission is not proof of delivery"
			v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
			e.recordFinal(v, action, "rule_edit", "", "pending request decided by a committed rule edit", e.ruleLocked(effective), nil, "deferred", "")
		}
	}
	return candidate, sentence, nil
}

// reviewRuleLocked is shared by pending/editor and observed-application creation.
// The caller supplies independently verified immutable identity and holds e.mu.
func (e *Engine) reviewRuleLocked(candidate policy.Rule, now time.Time, expiryUnchanged bool) (policy.Rule, string, error) {
	if candidate.Action != "allow" && candidate.Action != "block" {
		return policy.Rule{}, "", fmt.Errorf("editor action must be allow or block")
	}
	if candidate.Priority < -1000 || candidate.Priority > 1000 {
		return policy.Rule{}, "", fmt.Errorf("priority must be -1000..1000")
	}
	if !expiryUnchanged && candidate.Expires.After(now.Add(365*24*time.Hour)) {
		return policy.Rule{}, "", fmt.Errorf("expiry must be within 365 days, or persistent")
	}
	if candidate.Filter.Remote != "" {
		return policy.Rule{}, "", fmt.Errorf("use explicit remote address and port fields")
	}
	if candidate.Filter.RemoteAddress == "" {
		return policy.Rule{}, "", fmt.Errorf("remote address must be an IP, CIDR, or explicit * for any")
	}
	candidate.Schema = 2
	if !candidate.Filter.Process.IsZero() {
		candidate.Schema = 3
	}
	if candidate.Filter.NetworkZone != "" || candidate.Filter.AllPrograms {
		candidate.Schema = 4
	}
	candidate.Filter = canonicalFilter(candidate.Filter)
	if err := candidate.Validate(); err != nil {
		return policy.Rule{}, "", err
	}
	if other := duplicate(e.rules, candidate); other != "" {
		return policy.Rule{}, "", fmt.Errorf("duplicate scope already exists as %s; edit that rule explicitly", other)
	}
	sentence := RuleSentence(candidate)
	if candidate.Filter.NetworkZone != "" {
		sentence += " Zone definition " + e.Zones.Model + " revision " + e.Zones.Revision + "; rules follow explicitly configured definitions after daemon restart; unknown peers do not match. Zone classification is not zone byte accounting."
	}
	count := 0
	for _, other := range e.rules {
		if other.ID == candidate.ID || other.Disabled || (!other.Expires.IsZero() && !now.Before(other.Expires)) {
			continue
		}
		if filtersOverlap(candidate.Filter, other.Filter) {
			count++
			if count <= 8 {
				sentence += fmt.Sprintf(" Overlap: %s (%s, priority %d).", other.ID, other.Action, other.Priority)
			}
		}
	}
	if count > 8 {
		sentence += fmt.Sprintf(" And %d more overlapping rules.", count-8)
	}
	return candidate, sentence, nil
}

func filtersOverlap(a, b policy.Filter) bool {
	a = canonicalFilter(a)
	b = canonicalFilter(b)
	if (!a.AllPrograms && !b.AllPrograms && (a.Application != b.Application || a.Revision != b.Revision)) || (!a.AllUIDs && !b.AllUIDs && a.UID != b.UID) || (a.NetworkZone != "" && b.NetworkZone != "" && a.NetworkZone != b.NetworkZone) || a.Direction != b.Direction || !policy.ProtocolsOverlap(a.Protocol, b.Protocol) {
		return false
	}
	if !a.Process.IsZero() && !b.Process.IsZero() && a.Process != b.Process {
		return false
	}
	if a.LocalPort != 0 && b.LocalPort != 0 && a.LocalPort != b.LocalPort {
		return false
	}
	if a.RemotePort != 0 && b.RemotePort != 0 && a.RemotePort != b.RemotePort {
		return false
	}
	if a.RemoteAddress == "*" || b.RemoteAddress == "*" {
		return true
	}
	prefix := func(s string) netip.Prefix {
		if p, e := netip.ParsePrefix(s); e == nil {
			return p
		}
		addr, _ := netip.ParseAddr(s)
		if addr.IsValid() {
			return netip.PrefixFrom(addr, addr.BitLen())
		}
		return netip.Prefix{}
	}
	pa, pb := prefix(a.RemoteAddress), prefix(b.RemoteAddress)
	return pa.IsValid() && pb.IsValid() && (pa.Contains(pb.Addr()) || pb.Contains(pa.Addr()))
}

// Caller holds e.mu: durable transaction completes before policy publication.
func (e *Engine) publishRulesLocked(next []policy.Rule) error {
	if err := e.SaveRules(next); err != nil {
		return mutationError("persistence_failed", fmt.Sprintf("transaction failed; old policy retained: %v", err))
	}
	e.rules = next
	e.pruneHandlesLocked()
	return nil
}

func protocolLabel(p string) string {
	if p == "*" {
		return "TCP+UDP only"
	}
	return p
}
