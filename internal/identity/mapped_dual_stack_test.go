package identity

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMappedIPv4ConnectionProvesDualStack(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	fd, e := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if e != nil {
		t.Skip(e)
	}
	defer unix.Close(fd)
	if e = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); e != nil {
		t.Fatal(e)
	}
	addr := unix.SockaddrInet6{Port: port}
	addr.Addr[10] = 255
	addr.Addr[11] = 255
	addr.Addr[12] = 127
	addr.Addr[15] = 1
	if e = unix.Connect(fd, &addr); e != nil {
		t.Fatal(e)
	}
	peer, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	local, e := unix.Getsockname(fd)
	if e != nil {
		t.Fatal(e)
	}
	flow := Flow{NetNS: NetNS(), Protocol: "tcp", Direction: "outgoing", Local: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(local.(*unix.SockaddrInet6).Port)), Remote: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))}
	for _, limit := range []int{0, 2048} {
		sockets, e := SocketsLimited(limit)
		if e != nil {
			t.Fatal(e)
		}
		rows := receivers(sockets, flow)
		if len(rows) != 1 || rows[0].Family != unix.AF_INET6 || rows[0].V6Only == nil || *rows[0].V6Only {
			t.Fatalf("mapped IPv4 socket lacks kernel dual-stack proof: %+v", rows)
		}
	}
	// Explicit IPv6-only listener diagnostics must still exclude IPv4.
	only, e := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(only)
	if e = unix.SetsockoptInt(only, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); e != nil {
		t.Fatal(e)
	}
	if e = unix.Bind(only, &unix.SockaddrInet6{}); e != nil {
		t.Fatal(e)
	}
	if e = unix.Listen(only, 1); e != nil {
		t.Fatal(e)
	}
	bound, e := unix.Getsockname(only)
	if e != nil {
		t.Fatal(e)
	}
	onlyPort := uint16(bound.(*unix.SockaddrInet6).Port)
	all, e := Sockets()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, s := range all {
		if s.Protocol == "tcp" && s.Family == unix.AF_INET6 && s.Local.Port() == onlyPort && s.State == 10 {
			found = true
			if s.V6Only == nil || !*s.V6Only {
				t.Fatal("explicit IPv6-only mode lost", s)
			}
			incoming := flow
			incoming.Direction = "incoming"
			incoming.Local = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), onlyPort)
			if matches(s, incoming) {
				t.Fatal("IPv6-only listener became an IPv4 candidate")
			}
		}
	}
	if !found {
		t.Fatal("IPv6-only listener missing")
	}
	// Real connected-socket delivery, not just a successful API acknowledgement.
	if _, e = unix.Write(fd, []byte("x")); e != nil {
		t.Fatal(e)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, e := peer.Read(b[:]); e != nil || n != 1 || b[0] != 'x' {
		t.Fatal("delivery", n, e)
	}
}
