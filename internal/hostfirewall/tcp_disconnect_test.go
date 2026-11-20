package hostfirewall

import (
	"net/netip"
	"testing"

	"flowgate/internal/identity"
	ct "github.com/ti-mo/conntrack"
)

func TestMatchEstablishedTCPRequiresUnambiguousAdmittedDirection(t *testing.T) {
	a, b := netip.MustParseAddrPort("10.0.0.1:33220"), netip.MustParseAddrPort("10.0.0.2:443")
	tuple := func(src, dst netip.AddrPort) (v ct.Tuple) {
		v.IP.SourceAddress, v.IP.DestinationAddress = src.Addr(), dst.Addr()
		v.Proto.Protocol, v.Proto.SourcePort, v.Proto.DestinationPort = 6, src.Port(), dst.Port()
		return v
	}
	flow := ct.Flow{
		Mark: approved, TupleOrig: tuple(a, b), TupleReply: tuple(b, a),
		Status:    ct.Status{Value: ct.StatusSeenReply | ct.StatusAssured | ct.StatusConfirmed},
		ProtoInfo: ct.ProtoInfo{TCP: &ct.ProtoInfoTCP{State: 3}},
	}
	s := identity.Socket{Protocol: "tcp", Local: a, Remote: b, State: 1, Cookie: "cookie", Inode: 5, NetNS: "ns"}
	check := func(want string, fs ...ct.Flow) {
		t.Helper()
		got := matchEstablishedTCP([]identity.Socket{s}, fs)
		if want == "" {
			if len(got) != 0 {
				t.Fatalf("unexpected socket directions: %+v", got)
			}
			return
		}
		if len(got) != 1 || got[0].Flow.Direction != want || got[0].Socket.Cookie != s.Cookie {
			t.Fatalf("wanted %s for exact socket, got %+v", want, got)
		}
	}
	check("outgoing", flow)
	s.Local, s.Remote = b, a
	check("incoming", flow)
	s.Local, s.Remote = a, b
	reversed := flow
	reversed.TupleOrig, reversed.TupleReply = flow.TupleReply, flow.TupleOrig
	check("", flow, reversed)
	nat := flow
	nat.TupleReply = tuple(b, netip.MustParseAddrPort("10.0.0.3:33220"))
	check("", nat)
	startup := flow
	startup.Mark |= preserved
	check("", startup)
	check("", flow, startup)
	handshake := flow
	handshake.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: 2}
	check("", handshake)
}
