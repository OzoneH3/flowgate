package identity

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type reuseFixture struct {
	sockets []Socket
	owners  map[string]Application // socket cookie -> verified Windows application
	running map[int]bool
	calls   int
	fail    bool
	now     time.Time
	async   []func()
}

func syntheticWine(name, prefix string) Application {
	app := Application{Kind: "wine", Name: name, Executable: prefix + "/drive_c/" + name, Revision: "rev-" + name, Prefix: prefix}
	app.Key = digest("1000|wine|" + prefix + "|" + app.Executable)
	return app
}

func (x *reuseFixture) socket(port uint16, inode uint32, cookie string) Socket {
	return Socket{Protocol: "udp", Family: 2, Local: netip.MustParseAddrPort(fmt.Sprintf("0.0.0.0:%d", port)), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: inode, Cookie: cookie, NetNS: NetNS()}
}

// The full resolver stands in for the expensive runtime census: it answers from
// the current socket list and the verified owner of each cookie.
func (x *reuseFixture) resolve(f Flow) Attribution {
	x.calls++
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket"}
	for _, s := range x.sockets {
		if matches(s, f) {
			a.Sockets = append(a.Sockets, s)
		}
	}
	if x.fail || len(a.Sockets) != 1 {
		return a
	}
	app, ok := x.owners[a.Sockets[0].Cookie]
	if !ok {
		return a
	}
	pid := int(a.Sockets[0].Inode)
	a.Owners = []Process{{PID: pid, Start: "start", Application: app}}
	a.VisibilityComplete = true
	a.Status = "corroborated-runtime-table"
	a.Reason = "synthetic census"
	a.Fingerprint = a.Sockets[0].Cookie + app.Key
	a.Application = &app
	return a
}

func newReuseFixture() (*reuseFixture, *UDPAttributionReuse) {
	x := &reuseFixture{owners: map[string]Application{}, running: map[int]bool{}, now: time.Unix(1000, 0)}
	r := NewUDPAttributionReuse(x.resolve)
	r.Sockets = func() ([]Socket, error) { return append([]Socket(nil), x.sockets...), nil }
	r.Running = func(pid int, start string) bool { return x.running[pid] && start == "start" }
	r.Now = func() time.Time { return x.now }
	r.Async = func(fn func()) { x.async = append(x.async, fn) }
	return x, r
}

func udpFlow(direction, local, remote string) Flow {
	f, err := ParseFlow("udp", direction, local, remote)
	if err != nil {
		panic(err)
	}
	return f
}

func appOf(a Attribution) string {
	if a.Application == nil {
		return ""
	}
	return a.Application.Name
}

func TestUDPReuseServesBurstToManyRemotesFromOneVerifiedSocket(t *testing.T) {
	x, r := newReuseFixture()
	alpha := syntheticWine("alpha.exe", "/prefixes/alpha")
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha")}
	x.owners["c-alpha"] = alpha
	x.running[11] = true
	for i := 0; i < 15; i++ {
		a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", fmt.Sprintf("198.51.100.%d:7770", i+1)))
		if appOf(a) != "alpha.exe" || a.Status != "corroborated-runtime-table" {
			t.Fatalf("probe %d: %+v", i, a)
		}
	}
	if x.calls != 1 {
		t.Fatalf("burst from one verified socket ran %d full censuses, want 1", x.calls)
	}
}

func TestUDPReuseNeverTransfersBetweenApplicationsPrefixesOrSockets(t *testing.T) {
	x, r := newReuseFixture()
	alpha := syntheticWine("alpha.exe", "/prefixes/alpha")
	beta := syntheticWine("beta.exe", "/prefixes/beta")
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha"), x.socket(40001, 22, "c-beta")}
	x.owners["c-alpha"], x.owners["c-beta"] = alpha, beta
	x.running[11], x.running[22] = true, true
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")); appOf(a) != "alpha.exe" {
		t.Fatalf("alpha: %+v", a)
	}
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:40001", "198.51.100.1:7770")); appOf(a) != "beta.exe" || a.Application.Prefix != "/prefixes/beta" {
		t.Fatalf("beta must be attributed on its own socket: %+v", a)
	}
	// Alpha closes; Beta's prefix binds the same port. New cookie: no reuse.
	x.sockets = []Socket{x.socket(34429, 33, "c-beta-2"), x.socket(40001, 22, "c-beta")}
	x.owners["c-beta-2"] = beta
	x.running[33] = true
	calls := x.calls
	a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.2:7770"))
	if appOf(a) != "beta.exe" || a.Application.Prefix != "/prefixes/beta" || x.calls != calls+1 {
		t.Fatalf("replaced socket reused Alpha evidence: %+v calls=%d", a, x.calls-calls)
	}
	// Same port, unverified replacement: stays unidentified, never Alpha.
	x.sockets = []Socket{x.socket(34429, 44, "c-unknown")}
	if a := r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.3:7770")); a.Application != nil {
		t.Fatalf("unverified replacement inherited an application: %+v", a)
	}
}

func TestUDPReuseRequiresSameDirectionAndLocalEndpoint(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticWine("alpha.exe", "/prefixes/alpha")
	x.running[11] = true
	r.Resolve(udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770"))
	r.Resolve(udpFlow("incoming", "172.30.42.123:34429", "198.51.100.1:7770"))
	r.Resolve(udpFlow("outgoing", "100.87.58.72:34429", "198.51.100.1:7770"))
	if x.calls != 3 {
		t.Fatalf("direction/local endpoint must be verified separately, censuses=%d", x.calls)
	}
}

func TestUDPReuseWithdrawsOnOwnerExitAmbiguityFailureAndExpiry(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticWine("alpha.exe", "/prefixes/alpha")
	x.running[11] = true
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	r.Resolve(f)

	x.running[11] = false // recorded owner instance is gone
	x.fail = true
	if a := r.Resolve(f); a.Application != nil || x.calls != 2 {
		t.Fatalf("exited owner must force full census: %+v calls=%d", a, x.calls)
	}
	if r.Resolve(f); x.calls != 3 {
		t.Fatalf("failed attribution must not be reused, calls=%d", x.calls)
	}

	x.fail, x.running[11] = false, true
	r.Resolve(f)
	x.sockets = append(x.sockets, x.socket(34429, 12, "c-second"))
	if a := r.Resolve(f); a.Application != nil {
		t.Fatalf("two matching sockets must not reuse one: %+v", a)
	}

	x.sockets = x.sockets[:1]
	r.Resolve(f)
	calls := x.calls
	x.now = x.now.Add(r.Window)
	if r.Resolve(f); x.calls != calls+1 {
		t.Fatalf("evidence older than the window must be re-established")
	}
}

func TestUDPReuseRefreshesInBackgroundAndFailedRefreshWithdraws(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(34429, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticWine("alpha.exe", "/prefixes/alpha")
	x.running[11] = true
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	r.Resolve(f)
	x.now = x.now.Add(r.Refresh)
	if a := r.Resolve(f); appOf(a) != "alpha.exe" || x.calls != 1 || len(x.async) != 1 {
		t.Fatalf("refresh must not stall the datagram: calls=%d async=%d", x.calls, len(x.async))
	}
	r.Resolve(f)
	if len(x.async) != 1 {
		t.Fatalf("one refresh at a time, got %d", len(x.async))
	}
	x.fail = true
	x.async[0]()
	if a := r.Resolve(f); a.Application != nil || x.calls != 3 {
		t.Fatalf("failed refresh must withdraw reuse: %+v calls=%d", a, x.calls)
	}
}

func TestUDPReusePassesThroughTCPAndLinkLocal(t *testing.T) {
	x, r := newReuseFixture()
	x.sockets = []Socket{x.socket(5355, 11, "c-alpha")}
	x.owners["c-alpha"] = syntheticWine("alpha.exe", "/prefixes/alpha")
	x.running[11] = true
	for i := 0; i < 2; i++ {
		r.Resolve(udpFlow("outgoing", "172.30.42.123:5355", "[fe80::1]:5355"))
		r.Resolve(udpFlow("outgoing", "172.30.42.123:5355", "224.0.0.252:5355"))
	}
	tcp, _ := ParseFlow("tcp", "outgoing", "172.30.42.123:5355", "198.51.100.1:443")
	r.Resolve(tcp)
	r.Resolve(tcp)
	if x.calls != 6 {
		t.Fatalf("TCP and link-local UDP must keep full attribution, censuses=%d", x.calls)
	}
}
