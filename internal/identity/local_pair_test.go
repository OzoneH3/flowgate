package identity

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// Real loopback sockets of this test process; the descriptor scan is limited
// to this process (an unprivileged test cannot read other processes' fds).
func ownProcessOnly(t *testing.T) {
	old := holderSource
	holderSource = func() holderProc {
		p := procHolders()
		p.groups = func() ([]int, error) { return []int{os.Getpid()}, nil }
		return p
	}
	t.Cleanup(func() { holderSource = old })
}

func ap(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	p, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(p.Addr().Unmap(), p.Port())
}

func incomingFlow(proto string, server, client netip.AddrPort) Flow {
	return Flow{Protocol: proto, Direction: "incoming", Local: server, Remote: client, NetNS: NetNS()}
}

func tcpPair(t *testing.T, network, host string) (net.Listener, func() net.Conn) {
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skip("loopback unavailable: ", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return l, func() net.Conn {
		c, err := net.Dial(network, l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

func TestLocalPeerExactTupleIPv4AndIPv6(t *testing.T) {
	ownProcessOnly(t)
	for _, c := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		l, dial := tcpPair(t, c.network, c.host)
		client := dial()
		p := ResolveLocalPeer(incomingFlow("tcp", ap(t, l.Addr()), ap(t, client.LocalAddr())))
		if p == nil || p.State != "verified" || p.Role != "client" || p.Owner == nil || p.Owner.PID != os.Getpid() {
			t.Fatalf("%s: %+v", c.network, p)
		}
		if p.Socket.Kind != "client" || p.Socket.Local != ap(t, client.LocalAddr()) || p.Socket.Remote != ap(t, l.Addr()) || p.Socket.Cookie == "" || p.Socket.Inode == 0 {
			t.Fatalf("%s socket: %+v", c.network, p.Socket)
		}
		if !strings.Contains(p.Evidence, "cookie "+p.Socket.Cookie) || p.Owner.Start == "" {
			t.Fatalf("evidence %q", p.Evidence)
		}
		// Outgoing view of the same connection: the receiving listener.
		out := ResolveLocalPeer(Flow{Protocol: "tcp", Direction: "outgoing", Local: ap(t, client.LocalAddr()), Remote: ap(t, l.Addr()), NetNS: NetNS()})
		if out == nil || out.State != "verified" || out.Role != "server" || out.Socket.Kind != "listener" || out.Owner.PID != os.Getpid() {
			t.Fatalf("server side: %+v", out)
		}
	}
}

func TestLocalPeerMismatchedSourcePortNotCorrelated(t *testing.T) {
	ownProcessOnly(t)
	l, dial := tcpPair(t, "tcp4", "127.0.0.1")
	client := dial()
	c := ap(t, client.LocalAddr())
	wrong := netip.AddrPortFrom(c.Addr(), c.Port()+1)
	p := ResolveLocalPeer(incomingFlow("tcp", ap(t, l.Addr()), wrong))
	if p == nil || p.State != "unknown" || p.Owner != nil || p.Reason != LocalClientClosed {
		t.Fatalf("a different source port must never correlate: %+v", p)
	}
}

func TestLocalPeerConcurrentClientsSameServerPort(t *testing.T) {
	ownProcessOnly(t)
	l, dial := tcpPair(t, "tcp4", "127.0.0.1")
	a, b := dial(), dial()
	pa := ResolveLocalPeer(incomingFlow("tcp", ap(t, l.Addr()), ap(t, a.LocalAddr())))
	pb := ResolveLocalPeer(incomingFlow("tcp", ap(t, l.Addr()), ap(t, b.LocalAddr())))
	if pa.State != "verified" || pb.State != "verified" || pa.Socket.Cookie == pb.Socket.Cookie {
		t.Fatalf("each client must map to its own socket: %+v / %+v", pa.Socket, pb.Socket)
	}
	if pa.Socket.Local != ap(t, a.LocalAddr()) || pb.Socket.Local != ap(t, b.LocalAddr()) {
		t.Fatal("client sockets crossed")
	}
}

func TestLocalPeerShortLivedClientUnknown(t *testing.T) {
	ownProcessOnly(t)
	l, dial := tcpPair(t, "tcp4", "127.0.0.1")
	client := dial()
	addr := ap(t, client.LocalAddr())
	client.Close()
	time.Sleep(50 * time.Millisecond)
	p := ResolveLocalPeer(incomingFlow("tcp", ap(t, l.Addr()), addr))
	if p.State != "unknown" || p.Owner != nil || p.Reason != "Local client unknown: the client socket closed before it could be identified" {
		t.Fatalf("closed client must be unknown: %+v", p)
	}
}

func TestLocalPeerUDPConnectedOnly(t *testing.T) {
	ownProcessOnly(t)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer srv.Close()
	conn, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p := ResolveLocalPeer(incomingFlow("udp", ap(t, srv.LocalAddr()), ap(t, conn.LocalAddr())))
	if p.State != "verified" || p.Socket.Kind != "client" || p.Socket.Protocol != "udp" || p.Owner.PID != os.Getpid() {
		t.Fatalf("connected UDP peer: %+v", p)
	}
	out := ResolveLocalPeer(Flow{Protocol: "udp", Direction: "outgoing", Local: ap(t, conn.LocalAddr()), Remote: ap(t, srv.LocalAddr()), NetNS: NetNS()})
	if out.State != "verified" || out.Socket.Kind != "bound" {
		t.Fatalf("bound UDP receiver: %+v", out)
	}
	// An unconnected sender has no exact peer socket.
	loose, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer loose.Close()
	q := ResolveLocalPeer(incomingFlow("udp", ap(t, srv.LocalAddr()), ap(t, loose.LocalAddr())))
	if q.State != "unknown" || q.Owner != nil || q.Reason != LocalUDPClientUnknown {
		t.Fatalf("unconnected UDP sender must stay unknown: %+v", q)
	}
}

func TestLocalFlowClassification(t *testing.T) {
	oldAddrs, oldLo := localAddresses, loopbackInterface
	defer func() { localAddresses, loopbackInterface = oldAddrs, oldLo }()
	localAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.79.0.1"), netip.MustParseAddr("fd79::1")}, nil
	}
	loopbackInterface = func(i uint32) bool { return i == 1 }
	f := func(remote string, iface uint32) Flow {
		return Flow{Protocol: "tcp", Direction: "incoming", Local: netip.MustParseAddrPort("10.79.0.1:631"), Remote: netip.MustParseAddrPort(remote), Interface: iface}
	}
	for _, c := range []struct {
		remote string
		iface  uint32
		want   bool
	}{{"127.0.0.1:5000", 1, true}, {"[::1]:44104", 1, true}, {"10.79.0.1:5000", 1, true}, {"[fd79::1]:5000", 0, true}, {"10.79.0.2:5000", 2, false}, {"10.79.0.1:5000", 2, false}, {"192.0.2.1:5000", 1, false}} {
		if got := IsLocalFlow(f(c.remote, c.iface)); got != c.want {
			t.Errorf("%s via %d: got %v", c.remote, c.iface, got)
		}
	}
	if ResolveLocalPeer(f("10.79.0.2:5000", 2)) != nil {
		t.Fatal("remote host flows have no local peer")
	}
}
