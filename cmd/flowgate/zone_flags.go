package main

import "flowgate/internal/identity"

type zonePrefixes []string

func (v *zonePrefixes) String() string     { return "explicit configured CIDRs" }
func (v *zonePrefixes) Set(s string) error { *v = append(*v, s); return nil }
func configuredZones(l, i zonePrefixes) (identity.NetworkZones, error) {
	return identity.NewNetworkZones(l, i)
}
