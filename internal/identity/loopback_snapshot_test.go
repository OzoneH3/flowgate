package identity

import (
	"net"
	"testing"
)

func TestLoopbackFreshInterfaceSnapshots(t *testing.T) {
	f, _ := ParseFlow("udp", "outgoing", "127.0.0.1:40000", "127.0.0.1:40001")
	f.NetNS, f.Interface = NetNS(), 7
	for _, tc := range []struct {
		links []net.Interface
		want  bool
	}{
		{[]net.Interface{{Index: 7, Flags: net.FlagLoopback}}, true},
		{[]net.Interface{{Index: 7, Flags: net.FlagUp}}, false},
		{[]net.Interface{{Index: 8, Flags: net.FlagLoopback}}, false},
		{nil, false},
	} {
		if got := IsLoopbackFlowOnInterfaces(f, tc.links); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	f.NetNS = "foreign"
	if IsLoopbackFlowOnInterfaces(f, []net.Interface{{Index: 7, Flags: net.FlagLoopback}}) {
		t.Fatal("foreign namespace")
	}
}
