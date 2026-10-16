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
	if !r.Expires.IsZero() {
		expiry = "until " + r.Expires.UTC().Format(time.RFC3339)
	}
	state := "enabled"
	if r.Disabled {
		state = "disabled"
	}
	return fmt.Sprintf("%s %s %s for application %s, revision %s, UID %d; remote %s, local port %s, remote port %s; any local address/interface; %s (%s). Priority %d; highest priority wins, then smallest rule ID. Approved TCP connections continue.", strings.ToUpper(r.Action), f.Direction, f.Protocol, f.Application, f.Revision, f.UID, address, port(f.LocalPort), port(f.RemotePort), expiry, state, r.Priority)
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
			return policy.Rule{}, "", fmt.Errorf("rule no longer exists")
		}
		old := e.rules[index]
		expiryUnchanged = candidate.Expires.Equal(old.Expires)
		if !admin && old.Filter.UID != uid {
			return policy.Rule{}, "", fmt.Errorf("not authorized")
		}
		if expected == nil || *expected != old.Version {
			return policy.Rule{}, "", fmt.Errorf("stale rule version; reload before editing")
		}
		if candidate.Filter.Application != old.Filter.Application || candidate.Filter.Revision != old.Filter.Revision || candidate.Filter.UID != old.Filter.UID || candidate.Filter.Direction != old.Filter.Direction {
			return policy.Rule{}, "", fmt.Errorf("application/revision/UID/direction are immutable")
		}
		if candidate.ID != "" && candidate.ID != id {
			return policy.Rule{}, "", fmt.Errorf("immutable rule ID")
		}
		candidate.ID = id
		candidate.Created = old.Created
		candidate.Executable = old.Executable
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
			return policy.Rule{}, "", fmt.Errorf("not authorized")
		}
		a := e.Resolve(found.Flow)
		if !e.Now().Before(found.Deadline) || a.Application == nil || a.Principal() == nil || a.Fingerprint != found.Attribution.Fingerprint {
			return policy.Rule{}, "", fmt.Errorf("pending application identity changed")
		}
		basis := policy.Remembered(found.Flow, a)
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
	candidate.Filter = canonicalFilter(candidate.Filter)
	if err := candidate.Validate(); err != nil {
		return policy.Rule{}, "", err
	}
	if other := duplicate(e.rules, candidate); other != "" {
		return policy.Rule{}, "", fmt.Errorf("duplicate scope already exists as %s; edit that rule explicitly", other)
	}
	sentence := RuleSentence(candidate)
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
	if !commit {
		return candidate, sentence, nil
	}
	next := append([]policy.Rule{}, e.rules...)
	if index < 0 {
		next = append(next, candidate)
	} else {
		next[index] = candidate
	}
	if err := e.SaveRules(next); err != nil {
		return policy.Rule{}, "", fmt.Errorf("transaction failed; old policy retained: %w", err)
	}
	e.rules = next
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
			delete(e.events, key)
			continue
		}
		action, effective, conflicts := policy.Evaluate(e.rules, v.Flow, a, e.Now())
		v.Conflicts = conflicts
		if action == "allow" || action == "block" {
			v.Rule = effective
			v.Reason = "decided by committed rule edit; FlowGate permission is not proof of delivery"
			v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		}
	}
	return candidate, sentence, nil
}

func filtersOverlap(a, b policy.Filter) bool {
	a = canonicalFilter(a)
	b = canonicalFilter(b)
	if a.Application != b.Application || a.Revision != b.Revision || a.UID != b.UID || a.Direction != b.Direction || a.Protocol != b.Protocol {
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
