package uploadshape

import (
	"fmt"
	"net/netip"

	"flowgate/internal/identity"
)

func zoned(c Config) bool {
	for _, v := range c.Caps {
		if v.Scope != "" {
			return true
		}
	}
	return false
}
func knownZone(s identity.NetworkScope) string {
	if s.State == "known" && (s.Zone == "local" || s.Zone == "internet") {
		return s.Zone
	}
	return ""
}
func bindingFlow(b Binding) (identity.Flow, bool) {
	l, e := netip.ParseAddrPort(b.Descriptor.Local)
	r, e2 := netip.ParseAddrPort(b.Descriptor.Remote)
	return identity.Flow{Local: l, Remote: r, NetNS: b.Descriptor.NetNS, Interface: uint32(b.Descriptor.Interface)}, e == nil && e2 == nil
}
func groupedCaps(caps []Cap) map[string]map[string]Cap {
	out := map[string]map[string]Cap{}
	for _, c := range caps {
		if out[c.key()] == nil {
			out[c.key()] = map[string]Cap{}
		}
		out[c.key()][c.Scope] = c
	}
	return out
}

// The parent preserves the legacy all-application allocation. A zone-only
// application participates as Normal in a budgeted direction, without an
// invented aggregate cap.
func directionRelevant(zs map[string]Cap, budget uint64, download bool) bool {
	for scope, c := range zs {
		rate := c.BitsPerSecond
		if download {
			rate = c.DownloadBitsPerSecond
		}
		if rate > 0 || (budget > 0 && (c.TrafficPriority != "" && (scope != "" || c.TrafficPriority != "normal"))) {
			return true
		}
	}
	return false
}
func zoneDirectionRelevant(zs map[string]Cap, budget uint64, download bool) bool {
	for scope, c := range zs {
		if scope == "" {
			continue
		}
		rate := c.BitsPerSecond
		if download {
			rate = c.DownloadBitsPerSecond
		}
		if rate > 0 || budget > 0 && c.TrafficPriority != "" {
			return true
		}
	}
	return false
}
func aggregateCaps(caps []Cap, budget uint64, download bool) []Cap {
	out := []Cap{}
	for _, zs := range groupedCaps(caps) {
		if !directionRelevant(zs, budget, download) {
			continue
		}
		c := zs[""]
		if c.TrafficPriority == "" {
			c.TrafficPriority = "normal"
		}
		out = append(out, c)
	}
	return out
}

func zonePolicy(caps []Cap) map[string]any {
	out := map[string]any{}
	for app, zones := range groupedCaps(caps) {
		c := zones[""]
		entry := map[string]any{"rate": c.BitsPerSecond, "download_rate": c.DownloadBitsPerSecond, "priority": c.TrafficPriority}
		scoped := map[string]any{}
		for scope, v := range zones {
			if scope != "" {
				z := map[string]any{"rate": v.BitsPerSecond, "download_rate": v.DownloadBitsPerSecond}
				if v.TrafficPriority != "" {
					z["priority"] = v.TrafficPriority
				}
				scoped[scope] = z
			}
		}
		if len(scoped) > 0 {
			entry["zones"] = scoped
		}
		out[app] = entry
	}
	return out
}
func validateZones(c Config) error {
	groups := groupedCaps(c.Caps)
	cost := 0
	for _, zs := range groups {
		cost++
		if len(zs) > 1 || zs[""].Application == "" {
			cost += 3
		}
	}
	if cost > MaxCaps {
		return fmt.Errorf("class_capacity: at most 16 class nodes (four per zoned application)")
	}
	for _, download := range []bool{false, true} {
		b := c.UploadBudget
		if download {
			b = c.DownloadBudget
		}
		type parent struct {
			zs      map[string]Cap
			nominal uint64
		}
		var parents []parent
		total := b * 15 / 100
		for _, zs := range groups {
			if !directionRelevant(zs, b, download) {
				continue
			}
			all := zs[""]
			limit := all.BitsPerSecond
			if download {
				limit = all.DownloadBitsPerSecond
			}
			prio := all.TrafficPriority
			if prio == "" {
				prio = "normal"
			}
			ceil := limit
			if ceil == 0 {
				ceil = 100_000_000_000
			}
			n := ceil
			if b > 0 {
				if ceil > b {
					ceil = b
				}
				n = b * floorPercent[prio] / 100
				if n > ceil {
					n = ceil
				}
			}
			parents = append(parents, parent{zs, n})
			total += n
		}
		for _, p := range parents {
			if !zoneDirectionRelevant(p.zs, b, download) {
				continue
			}
			floor := p.nominal
			if b > 0 && total > b*3/5 {
				floor = floor * (b * 3 / 5) / total
			}
			weights := map[string]uint64{}
			var sum uint64
			for _, zone := range []string{"", "local", "internet"} {
				prio := p.zs[zone].TrafficPriority
				if zone == "" || prio == "" {
					prio = p.zs[""].TrafficPriority
				}
				if prio == "" {
					prio = "normal"
				}
				weights[zone] = floorPercent[prio]
				if b == 0 {
					weights[zone] = 15
				}
				sum += weights[zone]
			}
			for _, zone := range []string{"", "local", "internet"} {
				limit := uint64(0)
				if zone != "" {
					limit = p.zs[zone].BitsPerSecond
					if download {
						limit = p.zs[zone].DownloadBitsPerSecond
					}
				}
				n := floor * weights[zone] / sum
				if limit > 0 && n > limit {
					n = limit
				}
				if n < minFloor {
					return fmt.Errorf("allocation_below_minimum")
				}
			}
		}
	}
	return nil
}
