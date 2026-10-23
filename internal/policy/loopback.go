package policy

import (
	"flowgate/internal/identity"
	"net/netip"
	"time"
)

const DefaultLoopback = "default-localhost-allow"

// TargetsLoopback distinguishes an explicit localhost address scope from a
// broad application, local-zone, port-only or Internet-wide rule.
func (f Filter) TargetsLoopback() bool {
	if f.Remote != "" {
		a, e := netip.ParseAddrPort(f.Remote)
		return e == nil && a.Addr().Unmap().IsLoopback()
	}
	if a, e := netip.ParseAddr(f.RemoteAddress); e == nil {
		return a.Unmap().IsLoopback()
	}
	p, e := netip.ParsePrefix(f.RemoteAddress)
	if e != nil {
		return false
	}
	p = p.Masked()
	return (p.Addr().Is4() && p.Bits() >= 8 && p.Addr().IsLoopback()) || (p.Addr().Is6() && p.Bits() == 128 && p.Addr().IsLoopback())
}

// LoopbackRules is conservative about identity: possible explicit targets must
// still undergo ordinary ownership checks. No application permission is inferred.
func LoopbackRules(rules []Rule, f identity.Flow, now time.Time) []Rule {
	out := []Rule{}
	for _, r := range CurrentProgramRules(rules, now) {
		x := r.Filter
		if r.Disabled || (!r.Expires.IsZero() && !now.Before(r.Expires)) || !x.TargetsLoopback() || x.Direction != f.Direction || !ProtocolMatches(x.Protocol, f.Protocol) {
			continue
		}
		if x.Remote != "" && x.Remote != f.Remote.String() {
			continue
		}
		if x.LocalPort != 0 && x.LocalPort != f.Local.Port() || x.RemotePort != 0 && x.RemotePort != f.Remote.Port() {
			continue
		}
		if x.RemoteAddress != "" {
			if p, e := netip.ParsePrefix(x.RemoteAddress); e == nil {
				if !p.Contains(f.Remote.Addr()) {
					continue
				}
			} else if a, e := netip.ParseAddr(x.RemoteAddress); e != nil || a != f.Remote.Addr() {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
