package identity

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

// Real kernel equivalence of the port-filtered and full SOCK_DIAG dumps for the
// receiver sets Resolve uses, in the disposable lab namespace only: an IPv4
// socket and an IPv6 socket on the same UDP port, a reuseport pair on another
// port, and a connected socket. Resolve itself must then attribute the owner
// from the filtered census exactly as before.
func TestResolveDumpRealPortFilterEquivalence(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer v4.Close()
	port := v4.LocalAddr().(*net.UDPAddr).Port
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer v6.Close()
	connected, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	for _, local := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port), connected.LocalAddr().String()} {
		for _, direction := range []string{"incoming", "outgoing"} {
			l := netip.MustParseAddrPort(local)
			remote := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
			if l.Addr().Is6() {
				remote = netip.MustParseAddrPort(fmt.Sprintf("[::1]:%d", port))
			}
			f := Flow{Protocol: "udp", Direction: direction, Local: l, Remote: remote, NetNS: NetNS()}
			full, err := Sockets()
			if err != nil {
				t.Fatal(err)
			}
			filtered, err := UDPPortSockets(l.Port())
			if err != nil {
				t.Fatal(err)
			}
			want, got := receivers(full, f), receivers(filtered, f)
			if len(want) == 0 || fingerprint(nil, want) != fingerprint(nil, got) {
				t.Fatalf("%s %s: full %+v filtered %+v", direction, local, want, got)
			}
			for _, s := range filtered {
				if s.Protocol != "udp" || s.Local.Port() != l.Port() {
					t.Fatalf("kernel port filter returned foreign row %+v", s)
				}
			}
			dump, kind := resolveDump(f)
			if kind != "udp-port" {
				t.Fatal(kind)
			}
			viaResolve, err := dump()
			if err != nil || fingerprint(nil, receivers(viaResolve, f)) != fingerprint(nil, want) {
				t.Fatalf("resolve provider: %v %+v", err, viaResolve)
			}
			a := Resolve(f)
			if len(a.Sockets) != len(want) || fingerprint(nil, a.Sockets) != fingerprint(nil, want) {
				t.Fatalf("Resolve sockets differ: %+v", a)
			}
			if a.Status != "directly-associated" || a.Application == nil || len(a.Owners) != 1 || a.Owners[0].PID != os.Getpid() {
				t.Fatalf("owner attribution changed: %+v", a)
			}
		}
	}
}
