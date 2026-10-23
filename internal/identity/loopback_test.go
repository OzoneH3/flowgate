package identity

import (
	"net"
	"net/netip"
	"testing"
)

func TestSameHostAddresses(t *testing.T) {
	addresses := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}, &net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)}}
	for _, tc := range []struct {
		local, remote string
		want          bool
	}{
		{"192.0.2.10", "192.0.2.10", true}, {"127.0.0.2", "192.0.2.10", true},
		{"2001:db8::10", "2001:db8::10", true}, {"192.0.2.10", "192.0.2.11", false},
		{"192.0.2.11", "192.0.2.10", false}, {"0.0.0.0", "127.0.0.1", false},
		{"224.0.0.1", "127.0.0.1", false}, {"fe80::1%eth0", "::1", false},
	} {
		if got := sameHostAddresses(netip.MustParseAddr(tc.local), netip.MustParseAddr(tc.remote), addresses); got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
}
