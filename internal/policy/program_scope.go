package policy

import (
	"net/netip"
	"time"
)

func CanonicalFilter(f Filter) Filter {
	if f.InterfaceName != "" {
		f.InterfaceIndex = 0
	}
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

// ProgramScope is the exact configured scope, excluding the historical stamp.
func (r Rule) ProgramScope() Filter {
	f := CanonicalFilter(r.Filter)
	if r.FollowsUpdates() {
		f.Revision = ""
	}
	return f
}

// LatestProgramRules removes only choices superseded for their whole remaining
// lifetime. A temporary setting must not erase a persistent permission.
func LatestProgramRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		superseded := false
		if r.FollowsUpdates() {
			for _, newer := range rules {
				if newer.FollowsUpdates() && newer.ProgramScope() == r.ProgramScope() && newer.Created.After(r.Created) && (newer.Expires.IsZero() || (!r.Expires.IsZero() && !newer.Expires.Before(r.Expires))) {
					superseded = true
					break
				}
			}
		}
		if !superseded {
			out = append(out, r)
		}
	}
	return out
}

// CurrentProgramRules gives the newest unexpired setting precedence within
// one exact program scope. Disabling it does not revive an older choice.
func CurrentProgramRules(rules []Rule, now time.Time) []Rule {
	latest := map[Filter]time.Time{}
	for _, r := range rules {
		if !r.FollowsUpdates() || (!r.Expires.IsZero() && !now.Before(r.Expires)) {
			continue
		}
		k := r.ProgramScope()
		if t, ok := latest[k]; !ok || r.Created.After(t) {
			latest[k] = r.Created
		}
	}
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if !r.FollowsUpdates() || !r.Created.Before(latest[r.ProgramScope()]) {
			out = append(out, r)
		}
	}
	return out
}
