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
	t.Run("translated reply competes across conntrack zones", func(t *testing.T) {
		nat.Zone = 2
		nat.TupleOrig = tuple(netip.MustParseAddrPort("10.0.0.3:33220"), b)
		nat.TupleReply = tuple(b, a) // The socket-visible tuple is in the reply.
		check := func(fs ...ct.Flow) {
			t.Helper()
			if got := matchEstablishedTCP([]identity.Socket{s}, fs); len(got) != 0 {
				t.Fatalf("translated competing row allowed an abort candidate: %+v", got)
			}
		}
		check(flow, nat)
		check(nat, flow)
	})
	for _, tc := range []struct {
		name string
		edit func(*ct.Flow)
	}{
		{"unassured", func(row *ct.Flow) { row.Status.Value &^= ct.StatusAssured }},
		{"not established", func(row *ct.Flow) { row.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: 2} }},
	} {
		t.Run("translated competitor "+tc.name, func(t *testing.T) {
			row := flow
			row.Zone = 2
			row.Status.Value |= ct.StatusSrcNAT
			third := netip.MustParseAddrPort("10.0.0.3:33220")
			fourth := netip.MustParseAddrPort("10.0.0.4:33220")
			row.TupleOrig = tuple(third, b)
			row.TupleReply = tuple(b, a) // Only the reply overlaps.
			tc.edit(&row)
			unrelated := row
			unrelated.TupleReply = tuple(b, fourth)
			for _, order := range []struct {
				name string
				rows func(ct.Flow) []ct.Flow
			}{
				{"eligible first", func(other ct.Flow) []ct.Flow { return []ct.Flow{flow, other} }},
				{"competitor first", func(other ct.Flow) []ct.Flow { return []ct.Flow{other, flow} }},
			} {
				t.Run(order.name, func(t *testing.T) {
					if got := matchEstablishedTCP([]identity.Socket{s}, order.rows(row)); len(got) != 0 {
						t.Errorf("competing reply must veto the abort candidate, got %+v", got)
					}
					if got := matchEstablishedTCP([]identity.Socket{s}, order.rows(unrelated)); len(got) != 1 ||
						got[0].Flow.Direction != "outgoing" || got[0].Socket.Cookie != s.Cookie {
						t.Errorf("unrelated row must leave the socket eligible, got %+v", got)
					}
				})
			}
		})
	}
	for _, flag := range []struct {
		name            string
		original, reply uint16
		want            bool
	}{
		{"original simultaneous open", 0x8000, 0x0000, false},
		{"reply simultaneous open", 0x0000, 0x8000, false},
		{"mask only", 0x0180, 0x0080, true},
	} {
		t.Run(flag.name, func(t *testing.T) {
			row := flow
			row.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: 3, OriginalFlags: flag.original, ReplyFlags: flag.reply}
			if got := matchEstablishedTCP([]identity.Socket{s}, []ct.Flow{row}); (len(got) == 1) != flag.want {
				t.Fatalf("abort candidates = %v, want eligible = %v", got, flag.want)
			}
		})
	}
	startup := flow
	startup.Mark |= preserved
	check("", startup)
	check("", flow, startup)
	handshake := flow
	handshake.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: 2}
	check("", handshake)
}
