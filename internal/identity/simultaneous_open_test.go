package identity

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Incoming TCP is received by a full socket bound to exactly the local/remote
// pair (simultaneous open, self-connect) before any listener on the port.
func TestReceiversPreferExactTCPPeerOverListener(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:40000", "127.0.0.1:40000")
	listener := Socket{Protocol: "tcp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("127.0.0.1:40000"), State: 10, Inode: 1, Cookie: "l"}
	self := Socket{diagObserved: true, diagFull: true, Protocol: "tcp", Family: unix.AF_INET, Local: f.Local, Remote: f.Remote, State: 2, Inode: 2, Cookie: "s"}
	if got := receivers([]Socket{listener, self}, f); len(got) != 1 || got[0].Cookie != "s" {
		t.Fatalf("exact peer must receive: %+v", got)
	}
	// A half-open request entry (no inode) never displaces the listener.
	request := self
	request.diagFull, request.Inode, request.State = false, 0, 3
	if got := receivers([]Socket{listener, request}, f); len(got) != 1 || got[0].Cookie != "l" {
		t.Fatalf("request socket displaced listener: %+v", got)
	}
	// Another remote endpoint is not this connection.
	other := self
	other.Remote = netip.MustParseAddrPort("127.0.0.1:40001")
	if got := receivers([]Socket{listener, other}, f); len(got) != 1 || got[0].Cookie != "l" {
		t.Fatalf("different remote treated as exact peer: %+v", got)
	}
	// Outgoing matching is unchanged.
	out, _ := ParseFlow("tcp", "outgoing", "127.0.0.1:40000", "127.0.0.1:40000")
	var before []Socket
	for _, s := range []Socket{listener, self} {
		if matches(s, out) {
			before = append(before, s)
		}
	}
	if got := receivers([]Socket{listener, self}, out); fingerprint(nil, got) != fingerprint(nil, before) {
		t.Fatalf("outgoing matching changed: %+v", got)
	}
	// No exact peer, no listener: nothing receives it.
	if got := receivers([]Socket{other}, f); len(got) != 0 {
		t.Fatalf("unrelated socket received: %+v", got)
	}
}

// A real socket connecting to its own port: the incoming side resolves to this
// process instead of "no visible matching socket".
func TestRealSelfConnectIncomingResolvesToOwner(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		host, other := "127.0.0.1", "127.0.0.1:1"
		if family == unix.AF_INET6 {
			host, other = "::1", "[::1]:1"
		}
		t.Run(host, func(t *testing.T) {
			fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Skip("socket family unavailable:", err)
			}
			defer unix.Close(fd)
			var local unix.Sockaddr = &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
			if family == unix.AF_INET6 {
				local = &unix.SockaddrInet6{Addr: netip.IPv6Loopback().As16()}
			}
			if err = unix.Bind(fd, local); err != nil {
				t.Skip("loopback unavailable:", err)
			}
			sa, err := unix.Getsockname(fd)
			if err != nil {
				t.Fatal(err)
			}
			if err = unix.Connect(fd, sa); err != nil {
				t.Skip("kernel refused TCP self-connect:", err)
			}
			port := 0
			switch v := sa.(type) {
			case *unix.SockaddrInet4:
				port = v.Port
			case *unix.SockaddrInet6:
				port = v.Port
			}
			endpoint := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
			f, _ := ParseFlow("tcp", "incoming", endpoint.String(), endpoint.String())
			a := Resolve(f)
			if len(a.Sockets) != 1 || len(a.Owners) != 1 || a.Owners[0].PID != os.Getpid() {
				t.Fatalf("self-connect incoming side has no receiving socket/owner: %s %s %+v", a.Status, a.Reason, a.Owners)
			}
			// Excluding every other owner needs complete process visibility (root).
			if os.Geteuid() == 0 && a.Application == nil {
				t.Fatalf("self-connect incoming side unattributed: %s %s", a.Status, a.Reason)
			}
			// The same port with another remote has no receiver (no listener exists).
			g, _ := ParseFlow("tcp", "incoming", endpoint.String(), other)
			if b := Resolve(g); len(b.Sockets) != 0 || b.Application != nil {
				t.Fatalf("unrelated remote matched the self-connected socket: %+v", b.Sockets)
			}
		})
	}
}

// Two synthetic Windows programs in separate prefixes (separate census tables).
// Each self-connect resolves to its own holder only; a listener of the other
// program on the same port never inherits the connection, and a schema-1 table
// without remote endpoints never guesses an exact peer.
func TestTableRowsPreferExactPeerPerPrefix(t *testing.T) {
	for _, tc := range []struct{ prefix, self, other string }{
		{"/synthetic/prefix-one", "Z:\\one\\alpha.exe", "Z:\\one\\beta.exe"},
		{"/synthetic/prefix-two", "Z:\\two\\beta.exe", "Z:\\two\\alpha.exe"},
	} {
		f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:41000", "127.0.0.1:41000")
		self := WindowsOwner{PID: 20, Created: 2, Image: tc.self, Address: "127.0.0.1", Port: 41000, State: 3, RemoteAddress: "127.0.0.1", RemotePort: 41000}
		listener := WindowsOwner{PID: 30, Created: 3, Image: tc.other, Address: "0.0.0.0", Port: 41000, State: 2, RemoteAddress: "0.0.0.0"}
		rows, err := selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{listener, self}}, f)
		if err != nil || len(rows) != 1 || rows[0].Image != tc.self {
			t.Fatalf("%s: exact peer not selected: %+v %v", tc.prefix, rows, err)
		}
		// Another remote: only the listener receives it.
		g, _ := ParseFlow("tcp", "incoming", "127.0.0.1:41000", "127.0.0.1:50000")
		if rows, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{listener, self}}, g); err != nil || len(rows) != 1 || rows[0].Image != tc.other {
			t.Fatalf("%s: listener lost for unrelated remote: %+v %v", tc.prefix, rows, err)
		}
		// Schema 1 has no remote endpoint: never an exact peer.
		if rows, err = selectTableRows(tableSnapshot{Schema: 1, Rows: []WindowsOwner{self}}, f); err != nil || len(rows) != 0 {
			t.Fatalf("%s: schema1 guessed an exact peer: %+v %v", tc.prefix, rows, err)
		}
		// A connecting row bound to the wildcard address is not an exact peer:
		// it never displaces another program's listener on the concrete address.
		wildcard := self
		wildcard.Address = "0.0.0.0"
		exactListener := listener
		exactListener.Address = "127.0.0.1"
		if rows, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{exactListener, wildcard}}, f); err != nil || len(rows) != 1 || rows[0].Image != tc.other {
			t.Fatalf("%s: wildcard connecting row displaced listener: %+v %v", tc.prefix, rows, err)
		}
		// A link-local exact remote keeps the interface-mapping refusal. The local
		// address is global so the remote-only guard is the one exercised.
		ll, _ := ParseFlow("tcp", "incoming", "[2001:db8::1]:41000", "[fe80::2]:41000")
		linkLocal := self
		linkLocal.Address, linkLocal.RemoteAddress, linkLocal.Family = "2001:db8::1", "fe80::2", 6
		if _, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{linkLocal}}, ll); err == nil || !strings.Contains(err.Error(), "remote interface mapping") {
			t.Fatalf("%s: link-local exact remote not refused by the remote guard: %v", tc.prefix, err)
		}
		// An exact row still needs a Windows process identity.
		broken := self
		broken.Created = 0
		if _, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{broken}}, f); err == nil {
			t.Fatalf("%s: accepted exact peer without generation", tc.prefix)
		}
	}
}
