package identity

// Local (same-host) connection pairing. A connection whose remote address is an
// address of this same network namespace has a second endpoint on this host:
// for an incoming request the client that initiated it, for an outgoing
// request the server socket that will receive it. This file identifies that
// counterpart from the EXACT reversed tuple only (protocol, local<->remote
// address:port swapped, same network namespace). It never correlates by
// destination port, timestamp or executable name alone. Display/pairing
// evidence only: a peer never widens or narrows any permission target.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// LocalPeerOwner is the one verified process holding the counterpart socket.
type LocalPeerOwner struct {
	PID         int         `json:"pid"`
	Start       string      `json:"start_ticks"`
	UID         uint32      `json:"uid"`
	BootID      string      `json:"boot_id,omitempty"`
	Executable  string      `json:"executable"`
	Application Application `json:"application"`
	Provenance  *Provenance `json:"provenance,omitempty"`
}

// LocalPeerSocket is the counterpart socket as observed (kernel socket cookie
// and inode identify this socket generation).
type LocalPeerSocket struct {
	// client: the initiating socket whose local==our remote and remote==our local.
	// listener: TCP listening socket that receives this SYN (not yet accepted).
	// bound: UDP socket bound to the destination address/port that receives it.
	Kind     string         `json:"kind"`
	Protocol string         `json:"protocol"`
	Local    netip.AddrPort `json:"local"`
	Remote   netip.AddrPort `json:"remote"`
	State    string         `json:"state"`
	Cookie   string         `json:"cookie"`
	Inode    uint32         `json:"inode"`
	UID      uint32         `json:"uid"`
	NetNS    string         `json:"netns"`
}

// LocalPeer is event.local_peer.
type LocalPeer struct {
	State    string           `json:"state"` // verified | unknown
	Role     string           `json:"role"`  // client (peer of an incoming request) | server (peer of an outgoing request)
	Reason   string           `json:"reason"`
	Evidence string           `json:"evidence,omitempty"`
	Owner    *LocalPeerOwner  `json:"owner,omitempty"`
	Socket   *LocalPeerSocket `json:"socket,omitempty"`
	// The other request of the same connection (outgoing <-> incoming), set by
	// the daemon only after the exact pair was confirmed.
	CorrelatedEventID string `json:"correlated_event_id,omitempty"`
}

const (
	LocalClientClosed = "Local client unknown: the client socket closed before it could be identified"
	// UDP: only a connected socket matches a tuple exactly.
	LocalUDPClientUnknown = "Local client unknown: no connected UDP socket has this exact tuple (an unconnected sender, or the client socket closed before it could be identified)"
	localClientNoOwner    = "Local client unknown: no visible process holds the client socket"
	localServerNotFound   = "Local server unknown: no socket is listening on this local address and port"
)

// localAddresses lists the addresses of this network namespace (tests replace it).
var localAddresses = func() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// loopbackInterface reports whether an interface index is a loopback device
// (tests replace it). Same-host packets traverse lo, never a physical device.
var loopbackInterface = linkIsLoopback

// localPairPIDs lists the processes whose descriptors are scanned (tests limit
// it to the test process; production scans every visible /proc entry).
var localPairPIDs = func() []int {
	entries, _ := os.ReadDir("/proc")
	out := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// IsLocalFlow: the remote address is an address of this same network namespace
// (loopback or an assigned local address) and the packet used a loopback
// device. A packet from another host or namespace carrying such a source
// address arrives on a non-loopback device and is not treated as local.
func IsLocalFlow(f Flow) bool {
	r := f.Remote.Addr().Unmap()
	if !r.IsValid() || r.IsUnspecified() {
		return false
	}
	if f.Interface != 0 && !loopbackInterface(f.Interface) {
		return false
	}
	if r.IsLoopback() {
		return true
	}
	addrs, err := localAddresses()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.WithZone("") == r.WithZone("") {
			return true
		}
	}
	return false
}

// ReversedFlow is the same connection seen from the other endpoint.
func ReversedFlow(f Flow) Flow {
	g := f
	g.Local, g.Remote = f.Remote, f.Local
	g.Direction = "incoming"
	if f.Direction == "incoming" {
		g.Direction = "outgoing"
	}
	return g
}

// exactClient: the initiating socket of an incoming request. Its local
// endpoint is exactly our remote endpoint and its remote endpoint exactly our
// local endpoint. TCP: SYN_SENT (or ESTABLISHED once admitted) with a live
// inode; TIME_WAIT/orphans have no owner. UDP: only a CONNECTED socket can be
// matched exactly; an unconnected sender never is.
func exactClient(s Socket, f Flow) bool {
	if s.Protocol != f.Protocol || s.Inode == 0 || s.Local != f.Remote || s.Remote != f.Local {
		return false
	}
	if s.Protocol == "tcp" {
		return s.State == 2 || s.State == 1
	}
	return s.Remote.Port() != 0 && !s.Remote.Addr().IsUnspecified()
}

// receiver: the socket the kernel delivers an outgoing request to, using the
// same exact-address/wildcard matching as Resolve for an incoming request.
func receiver(s Socket, f Flow) bool {
	return s.Inode != 0 && matches(s, ReversedFlow(f)) && (s.Protocol == "udp" || s.State == 10)
}

// ResolveLocalPeer returns nil when the flow is not a same-host connection.
func ResolveLocalPeer(f Flow) *LocalPeer {
	if !IsLocalFlow(f) {
		return nil
	}
	p := &LocalPeer{State: "unknown", Role: "client"}
	if f.Direction == "outgoing" {
		p.Role = "server"
	}
	if f.NetNS != NetNS() {
		p.Reason = "Local peer unknown: foreign network namespace is outside this observer"
		return p
	}
	sockets, err := Sockets()
	if err != nil {
		p.Reason = "Local peer unknown: socket diagnostics unavailable: " + err.Error()
		return p
	}
	return identifyLocalPeer(f, p, sockets, Sockets)
}

func identifyLocalPeer(f Flow, p *LocalPeer, sockets []Socket, again func() ([]Socket, error)) *LocalPeer {
	pick := func(s Socket) bool { return exactClient(s, f) }
	if p.Role == "server" {
		pick = func(s Socket) bool { return receiver(s, f) }
	}
	var found []Socket
	for _, s := range sockets {
		if pick(s) {
			found = append(found, s)
		}
	}
	switch {
	case len(found) == 0 && p.Role == "client":
		p.Reason = LocalClientClosed
		if f.Protocol == "udp" {
			p.Reason = LocalUDPClientUnknown
		}
		return p
	case len(found) == 0:
		p.Reason = localServerNotFound
		if f.Protocol == "udp" {
			p.Reason = "Local server unknown: no socket is bound to this local address and port"
		}
		return p
	case len(found) > 1:
		p.Reason = fmt.Sprintf("Local %s unknown: %d sockets match; the receiving socket cannot be singled out", p.Role, len(found))
		return p
	}
	s := found[0]
	kind := "client"
	if p.Role == "server" {
		kind = "listener"
		if s.Protocol == "udp" {
			kind = "bound"
		}
	}
	p.Socket = &LocalPeerSocket{Kind: kind, Protocol: s.Protocol, Local: s.Local, Remote: s.Remote, State: SocketState(s), Cookie: s.Cookie, Inode: s.Inode, UID: s.UID, NetNS: s.NetNS}
	owners, incomplete := socketHolders(s.Inode)
	// The socket must still be the same generation after the descriptor scan.
	if now, err := again(); err == nil {
		still := false
		for _, x := range now {
			if x.Inode == s.Inode && x.Cookie == s.Cookie && pick(x) {
				still = true
			}
		}
		if !still {
			p.Socket = nil
			p.Reason = LocalClientClosed
			if p.Role == "server" {
				p.Reason = "Local server unknown: the receiving socket closed before it could be identified"
			}
			return p
		}
	} else {
		p.Reason = "Local peer unknown: socket recheck unavailable"
		return p
	}
	owner := (*Process)(nil)
	if len(owners) == 1 {
		owner = &owners[0]
	} else if len(owners) == 2 {
		_, owner = brokerAssociation(owners)
	}
	switch {
	case len(owners) == 0:
		p.Reason = localClientNoOwner
		if p.Role == "server" {
			p.Reason = "Local server unknown: no visible process holds the receiving socket"
		}
		return p
	case owner == nil:
		p.Reason = fmt.Sprintf("Local %s unknown: %d processes share the socket; no single owner", p.Role, len(owners))
		return p
	case incomplete:
		p.Reason = fmt.Sprintf("Local %s unknown: process visibility incomplete; another holder cannot be excluded", p.Role)
		return p
	}
	p.State = "verified"
	p.Owner = &LocalPeerOwner{PID: owner.PID, Start: owner.Start, UID: owner.UID, BootID: owner.BootID, Executable: owner.Executable, Application: owner.Application, Provenance: owner.Provenance}
	if p.Role == "client" {
		p.Reason = "Verified local client: the socket with the exact reversed tuple in this network namespace"
		p.Evidence = fmt.Sprintf("%s socket %s -> %s (%s), cookie %s, inode %d; one descriptor holder PID %d (start %s)", strings.ToUpper(s.Protocol), s.Local, s.Remote, SocketState(s), s.Cookie, s.Inode, owner.PID, owner.Start)
	} else {
		p.Reason = "Verified local server: the one socket that receives this destination in this network namespace"
		p.Evidence = fmt.Sprintf("%s %s socket %s (%s), cookie %s, inode %d; one descriptor holder PID %d (start %s)", strings.ToUpper(s.Protocol), kind, s.Local, SocketState(s), s.Cookie, s.Inode, owner.PID, owner.Start)
	}
	return p
}

// socketHolders scans visible processes for descriptors of one socket inode.
func socketHolders(inode uint32) ([]Process, bool) {
	want := fmt.Sprintf("socket:[%d]", inode)
	var owners []Process
	incomplete := false
	for _, pid := range localPairPIDs() {
		base := "/proc/" + strconv.Itoa(pid)
		fds, err := os.ReadDir(base + "/fd")
		if err != nil {
			if _, e := os.Stat(base); e == nil && !strings.Contains(string(readBound(base+"/status", 4096)), "State:\tZ") {
				incomplete = true
			}
			continue
		}
		for _, fd := range fds {
			if link(base+"/fd/"+fd.Name()) != want {
				continue
			}
			p, err := Inspect(pid)
			if err != nil {
				incomplete = true
			} else {
				p.Provenance = CaptureProvenance(p)
				owners = append(owners, p)
			}
			break
		}
	}
	return owners, incomplete
}
