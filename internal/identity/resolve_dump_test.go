package identity

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// Deterministic models of the two SOCK_DIAG providers. No kernel, no /proc:
// every flow used with Resolve here has no receiver, so attribution returns
// before any holder census; provider selection and failure handling are the
// subject. Equivalence of the competitor sets is checked on receivers directly.
type dumpModel struct {
	full, port []uint16 // recorded calls: 0 for the full dump, the port otherwise
	sockets    []Socket
	fullErr    error
	portErr    error
	filterPort bool // model the kernel filter exactly: UDP rows with that local port
}

func (m *dumpModel) install(t *testing.T) {
	t.Helper()
	saved := socketDumps
	socketDumps.full = func() ([]Socket, error) {
		m.full = append(m.full, 0)
		if m.fullErr != nil {
			return nil, m.fullErr
		}
		return append([]Socket(nil), m.sockets...), nil
	}
	socketDumps.udpPort = func(port uint16) ([]Socket, error) {
		m.port = append(m.port, port)
		if m.portErr != nil {
			return nil, m.portErr
		}
		var out []Socket
		for _, s := range m.sockets {
			if !m.filterPort || (s.Protocol == "udp" && s.Local.Port() == port) {
				out = append(out, s)
			}
		}
		return out, nil
	}
	t.Cleanup(func() { socketDumps = saved })
}

func resolveDumpFlow(local string) Flow {
	return Flow{Protocol: "udp", Direction: "outgoing", Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort("203.0.113.9:443"), NetNS: NetNS()}
}

func TestResolveDumpSelectsPortFilteredCensusForConcreteUDPOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		flow Flow
		want string
	}{
		{"udp concrete port", resolveDumpFlow("192.0.2.10:45136"), "udp-port"},
		{"udp ipv6 concrete port", Flow{Protocol: "udp", Direction: "incoming", Local: netip.MustParseAddrPort("[2001:db8::1]:5353"), Remote: netip.MustParseAddrPort("[2001:db8::2]:5353"), NetNS: NetNS()}, "udp-port"},
		{"udp zero port keeps full", resolveDumpFlow("192.0.2.10:0"), "full"},
		{"tcp keeps full", Flow{Protocol: "tcp", Direction: "incoming", Local: netip.MustParseAddrPort("192.0.2.10:443"), Remote: netip.MustParseAddrPort("203.0.113.9:40000"), NetNS: NetNS()}, "full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &dumpModel{filterPort: true}
			m.install(t)
			_, kind := resolveDump(tc.flow)
			if kind != tc.want {
				t.Fatalf("provider %q, want %q", kind, tc.want)
			}
			a := Resolve(tc.flow)
			if a.ReasonCode != ReasonNoSocketObserved || len(a.Sockets) != 0 {
				t.Fatalf("%+v", a)
			}
			switch tc.want {
			case "udp-port":
				if len(m.full) != 0 || len(m.port) != 1 || m.port[0] != tc.flow.Local.Port() {
					t.Fatalf("calls full=%v port=%v", m.full, m.port)
				}
			default:
				if len(m.full) != 1 || len(m.port) != 0 {
					t.Fatalf("calls full=%v port=%v", m.full, m.port)
				}
			}
		})
	}
}

func TestResolveDumpUsesOneProviderForBothPasses(t *testing.T) {
	m := &dumpModel{filterPort: true}
	m.install(t)
	dump, kind := resolveDump(resolveDumpFlow("192.0.2.10:45136"))
	if kind != "udp-port" {
		t.Fatal(kind)
	}
	dump()
	dump()
	if len(m.port) != 2 || m.port[0] != 45136 || m.port[1] != 45136 || len(m.full) != 0 {
		t.Fatalf("calls full=%v port=%v", m.full, m.port)
	}
}

func TestResolveDumpFailureSemanticsMatchFullCensus(t *testing.T) {
	boom := errors.New("netlink: operation not permitted")
	filtered := &dumpModel{filterPort: true, portErr: boom}
	filtered.install(t)
	a := Resolve(resolveDumpFlow("192.0.2.10:45136"))
	full := &dumpModel{fullErr: boom}
	full.install(t)
	b := Resolve(Flow{Protocol: "tcp", Direction: "incoming", Local: netip.MustParseAddrPort("192.0.2.10:443"), Remote: netip.MustParseAddrPort("203.0.113.9:40000"), NetNS: NetNS()})
	for _, a := range []Attribution{a, b} {
		if a.ReasonCode != ReasonSocketCensusUnavailable || a.Status != "unidentified" || a.Application != nil || len(a.Owners) != 0 || a.VisibilityComplete {
			t.Fatalf("%+v", a)
		}
	}
	if a.Reason != b.Reason {
		t.Fatalf("reason text differs: %q vs %q", a.Reason, b.Reason)
	}
}

func TestResolveDumpForeignNamespaceNeverDumps(t *testing.T) {
	m := &dumpModel{filterPort: true}
	m.install(t)
	f := resolveDumpFlow("192.0.2.10:45136")
	f.NetNS = "net:[1]"
	if a := Resolve(f); a.ReasonCode != ReasonNamespaceMismatch || len(m.full)+len(m.port) != 0 {
		t.Fatalf("%+v calls full=%v port=%v", a, m.full, m.port)
	}
}

// The competitor set from a kernel port filter must equal the full dump after
// matches for every receiver shape the matcher distinguishes.
func TestResolveDumpPortFilterPreservesCompetitorSet(t *testing.T) {
	yes, no := true, false
	sockets := []Socket{
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("0.0.0.0:5000"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: 1, Cookie: "1"},
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:5000"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: 2, Cookie: "2"},
		{Protocol: "udp", Family: unix.AF_INET6, Local: netip.MustParseAddrPort("[::]:5000"), Remote: netip.MustParseAddrPort("[::]:0"), Inode: 3, Cookie: "3", V6Only: &no},
		{Protocol: "udp", Family: unix.AF_INET6, Local: netip.MustParseAddrPort("[::]:5000"), Remote: netip.MustParseAddrPort("[::]:0"), Inode: 4, Cookie: "4", V6Only: &yes},
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("0.0.0.0:5000"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: 5, Cookie: "5"}, // reuseport twin of 1
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:5000"), Remote: netip.MustParseAddrPort("203.0.113.9:443"), Inode: 6, Cookie: "6"},
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:5001"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: 7, Cookie: "7"},
		{Protocol: "tcp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:5000"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), State: 10, Inode: 8, Cookie: "8"},
		{Protocol: "udp", Family: unix.AF_INET6, Local: netip.MustParseAddrPort("[2001:db8::1]:5000"), Remote: netip.MustParseAddrPort("[::]:0"), Inode: 9, Cookie: "9"},
	}
	kernelFilter := func(port uint16) []Socket {
		var out []Socket
		for _, s := range sockets {
			if s.Protocol == "udp" && s.Local.Port() == port {
				out = append(out, s)
			}
		}
		return out
	}
	for _, local := range []string{"192.0.2.10:5000", "198.51.100.7:5000", "[2001:db8::1]:5000", "[2001:db8::7]:5000", "192.0.2.10:5001", "192.0.2.10:5002"} {
		for _, remote := range []string{"203.0.113.9:443", "203.0.113.10:53", "[2001:db8::2]:443"} {
			l, r := netip.MustParseAddrPort(local), netip.MustParseAddrPort(remote)
			if l.Addr().Is4() != r.Addr().Is4() {
				continue
			}
			for _, direction := range []string{"incoming", "outgoing"} {
				f := Flow{Protocol: "udp", Direction: direction, Local: l, Remote: r, NetNS: NetNS()}
				want := fingerprint(nil, receivers(sockets, f))
				got := fingerprint(nil, receivers(kernelFilter(l.Port()), f))
				if want != got {
					t.Fatalf("%s %s->%s: competitor set differs", direction, local, remote)
				}
			}
		}
	}
	// Sensitivity: a filter that lost one wildcard competitor would be detected.
	f := resolveDumpFlow("192.0.2.10:5000")
	partial := kernelFilter(5000)[1:]
	if fingerprint(nil, receivers(sockets, f)) == fingerprint(nil, receivers(partial, f)) {
		t.Fatal("equivalence check is not sensitive to a missing competitor")
	}
}
