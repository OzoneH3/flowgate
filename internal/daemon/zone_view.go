package daemon

import (
	"flowgate/internal/policy"
	"time"
)

type ZonePolicy struct {
	Zone     string          `json:"zone"`
	Incoming DirectionPolicy `json:"incoming"`
	Outgoing DirectionPolicy `json:"outgoing"`
}

func zoneFallbackIDs(rules []policy.Rule, uid uint32) []string {
	out := []string{}
	for _, r := range rules {
		if r.Filter.AllPrograms && (r.Filter.AllUIDs || r.Filter.UID == uid) {
			out = append(out, r.ID)
		}
	}
	return out
}
func (e *Engine) zoneViews(rules []policy.Rule, h *EnforcementStatus, now time.Time) []ZonePolicy {
	out := []ZonePolicy{}
	for _, zone := range []string{"local", "internet"} {
		v := ZonePolicy{Zone: zone}
		for _, direction := range []string{"incoming", "outgoing"} {
			c, d := coverage(e.Mode, direction, h)
			p := DirectionPolicy{Direction: direction, Configured: "absent", Reason: "All-program zone inventory; process and application overrides are separate; unknown peers do not match", Rules: []PolicyRuleRef{}, Default: evaluatorDefault(direction), RuntimeDefault: d, Enforcement: c}
			actions := map[string]bool{}
			broad := map[string]bool{}
			for _, r := range rules {
				f := r.Filter
				if !f.AllPrograms || f.NetworkZone != zone || f.Direction != direction {
					continue
				}
				ref := e.ruleRefLocked(r, now)
				p.Rules = append(p.Rules, ref)
				if ref.Disabled {
					p.Disabled++
				}
				if ref.Expired {
					p.Expired++
				}
				if ref.Active {
					p.Active++
					actions[r.Action] = true
					if (f.RemoteAddress == "*" || f.RemoteAddress == "") && f.LocalPort == 0 && f.RemotePort == 0 {
						broad[f.Protocol] = true
						if f.Protocol == "*" {
							broad["tcp"], broad["udp"] = true, true
						}
					}
				}
			}
			if len(p.Rules) > 0 {
				p.Configured = "scoped"
				if p.Active == 0 {
					p.Configured = "inactive_only"
				} else if len(actions) > 1 {
					p.Configured = "mixed"
				} else if broad["tcp"] && broad["udp"] {
					p.Configured = "uniform"
					for a := range actions {
						p.Action = a
					}
				}
			}
			// Machine+UID rules can coexist: aggregate action never asserts one result for all principals.
			for _, r := range p.Rules {
				if !r.Scope.AllUIDs && p.Configured == "uniform" {
					p.Configured = "scoped"
					p.Action = ""
				}
			}
			if direction == "incoming" {
				v.Incoming = p
			} else {
				v.Outgoing = p
			}
		}
		out = append(out, v)
	}
	return out
}
