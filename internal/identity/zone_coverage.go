package identity

import (
	"fmt"
	"net/netip"
	"sort"
)

// ZoneCoverage partitions both address families at every classifier boundary.
// Every returned CIDR has uniform membership; additions/removals are exact for
// the reviewed generation, not a list of illustrative Internet destinations.
func ZoneCoverage(before, after NetworkZones, zone string) (old, new, added, removed []string, err error) {
	old, new, added, removed = []string{}, []string{}, []string{}, []string{}
	boundaries := append(before.Boundaries(), after.Boundaries()...)
	visits := 0
	var walk func(netip.Prefix) error
	walk = func(p netip.Prefix) error {
		visits++
		if visits > 250000 {
			return fmt.Errorf("zone coverage exceeds review budget")
		}
		split := false
		for _, b := range boundaries {
			if b.Bits() > p.Bits() && p.Contains(b.Addr()) {
				split = true
				break
			}
		}
		if split {
			bits := p.Bits() + 1
			a := p.Addr().As16()
			offset := 0
			if p.Addr().Is4() {
				offset = 96
			}
			at := offset + p.Bits()
			a[at/8] |= 1 << uint(7-at%8)
			right := netip.AddrFrom16(a)
			if p.Addr().Is4() {
				right = right.Unmap()
			}
			if e := walk(netip.PrefixFrom(p.Addr(), bits)); e != nil {
				return e
			}
			return walk(netip.PrefixFrom(right, bits))
		}
		b, a := before.Classify(p.Addr()), after.Classify(p.Addr())
		was, is := b.State == "known" && b.Zone == zone, a.State == "known" && a.Zone == zone
		if was {
			old = append(old, p.String())
		}
		if is {
			new = append(new, p.String())
		}
		if is && !was {
			added = append(added, p.String())
		}
		if was && !is {
			removed = append(removed, p.String())
		}
		if len(old)+len(new)+len(added)+len(removed) > 16384 {
			return fmt.Errorf("zone coverage exceeds response budget")
		}
		return nil
	}
	for _, root := range []string{"0.0.0.0/0", "::/0"} {
		if e := walk(netip.MustParsePrefix(root)); e != nil {
			return nil, nil, nil, nil, e
		}
	}
	for _, v := range []*[]string{&old, &new, &added, &removed} {
		sort.Strings(*v)
	}
	return
}
