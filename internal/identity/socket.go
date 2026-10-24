package identity

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Socket struct {
	// Internal diagnostic framing distinguishes a request_sock from a full socket.
	diagObserved bool
	diagFull     bool
	Counters     *TCPBytes      `json:"counters,omitempty"`
	Interface    uint32         `json:"interface_index,omitempty"`
	Family       uint8          `json:"family"`
	V6Only       *bool          `json:"v6_only,omitempty"`
	Protocol     string         `json:"protocol"`
	Local        netip.AddrPort `json:"local"`
	Remote       netip.AddrPort `json:"remote"`
	State        uint8          `json:"state"`
	Inode        uint32         `json:"inode"`
	Cookie       string         `json:"cookie"`
	UID          uint32         `json:"uid"`
	NetNS        string         `json:"netns"`
}
type Flow struct {
	NetworkScope NetworkScope   `json:"network_scope"`
	Protocol     string         `json:"protocol"`
	Direction    string         `json:"direction"`
	Local        netip.AddrPort `json:"local"`
	Remote       netip.AddrPort `json:"remote"`
	NetNS        string         `json:"netns"`
	Interface    uint32         `json:"interface_index"`
}

func (f Flow) Key() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", f.NetNS, f.Protocol, f.Direction, f.Local, f.Remote)
}

type Attribution struct {
	Table              *TableEvidence `json:"runtime_table,omitempty"`
	VisibilityComplete bool           `json:"visibility_complete"`
	Association        *Association   `json:"association,omitempty"`
	Status             string         `json:"status"`
	Reason             string         `json:"reason"`
	ReasonCode         string         `json:"reason_code,omitempty"`
	Owners             []Process      `json:"owners"`
	Sockets            []Socket       `json:"sockets"`
	Fingerprint        string         `json:"fingerprint"`
	Application        *Application   `json:"application,omitempty"`
}

func NetNS() string              { return link("/proc/self/ns/net") }
func Sockets() ([]Socket, error) { return SocketsLimited(0) }

// UDPSockets is the complete UDP census of both families, without TCP rows.
func UDPSockets() ([]Socket, error) { return socketsFor([]byte{unix.IPPROTO_UDP}, 0) }

// SocketsLimited bounds retained rows; zero preserves the enforcement census.
func SocketsLimited(limit int) ([]Socket, error) {
	return socketsFor([]byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}, limit)
}
func socketsFor(protos []byte, limit int) ([]Socket, error) {
	c, e := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var result []Socket
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range protos {
			req := make([]byte, 56)
			req[0] = family
			req[1] = proto
			if limit > 0 && proto == unix.IPPROTO_TCP {
				req[2] = 1 << (2 /* INET_DIAG_INFO */ - 1)
			}
			binary.NativeEndian.PutUint32(req[4:8], 0xffffffff)
			for i := 48; i < 56; i++ {
				req[i] = 255
			}
			var msgs []netlink.Message
			if limit > 0 {
				msgs, e = boundedDiag(req, limit-len(result))
			} else {
				msgs, e = c.Execute(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request | netlink.Dump}, Data: req})
			}
			dumpErr := e
			if e != nil && len(msgs) == 0 {
				return result, e
			}
			for _, m := range msgs {
				if limit > 0 && len(result) >= limit {
					return result, fmt.Errorf("socket row limit reached")
				}
				b := m.Data
				if len(b) < 72 {
					return nil, fmt.Errorf("short inet_diag response")
				}
				var la, ra netip.Addr
				if family == unix.AF_INET {
					la = netip.AddrFrom4([4]byte(b[8:12]))
					ra = netip.AddrFrom4([4]byte(b[24:28]))
				} else {
					la = netip.AddrFrom16([16]byte(b[8:24]))
					ra = netip.AddrFrom16([16]byte(b[24:40]))
				}
				iface := binary.NativeEndian.Uint32(b[40:44])
				// Scope identifiers are presentation for host snapshots only; the
				// established enforcement matching path retains its exact behavior.
				if limit > 0 && iface != 0 {
					if la.IsLinkLocalUnicast() {
						la = la.WithZone(strconv.FormatUint(uint64(iface), 10))
					}
					if ra.IsLinkLocalUnicast() {
						ra = ra.WithZone(strconv.FormatUint(uint64(iface), 10))
					}
				}
				name := "tcp"
				if proto == unix.IPPROTO_UDP {
					name = "udp"
				}
				var v6only *bool
				var counters *TCPBytes
				var full bool
				attrs, err := netlink.UnmarshalAttributes(b[72:])
				if err != nil {
					return nil, err
				}
				for _, attr := range attrs {
					if attr.Type == 2 || attr.Type == 8 || attr.Type == 22 {
						full = true
					}
					if limit > 0 && proto == unix.IPPROTO_TCP && attr.Type == 2 /* INET_DIAG_INFO */ {
						counters = parseTCPBytes(attr.Data)
					}
					if attr.Type == 11 && len(attr.Data) == 1 {
						value := attr.Data[0] != 0
						v6only = &value
					}
				}
				// Linux omits SKV6ONLY on some connected TCP diagnostics.
				// Concrete IPv4-mapped endpoints on a full IPv6 socket are
				// themselves kernel evidence that IPv4 delivery is enabled.
				if v6only == nil && full && binary.NativeEndian.Uint32(b[68:72]) != 0 && family == unix.AF_INET6 && la.Is4In6() && ra.Is4In6() {
					value := false
					v6only = &value
				}
				result = append(result, Socket{diagObserved: true, diagFull: full, Counters: counters, Interface: iface, Family: family, V6Only: v6only, Protocol: name, Local: netip.AddrPortFrom(la.Unmap(), binary.BigEndian.Uint16(b[4:6])), Remote: netip.AddrPortFrom(ra.Unmap(), binary.BigEndian.Uint16(b[6:8])), State: b[1], Inode: binary.NativeEndian.Uint32(b[68:72]), UID: binary.NativeEndian.Uint32(b[64:68]), Cookie: fmt.Sprintf("%x", b[44:52]), NetNS: NetNS()})
			}
			if dumpErr != nil {
				return result, dumpErr
			}
		}
	}
	return result, nil
}
func matches(s Socket, f Flow) bool {
	if s.Protocol != f.Protocol || s.Local.Port() != f.Local.Port() {
		return false
	}
	// Unknown v6-only state remains a candidate; known v6-only cannot receive IPv4.
	if f.Local.Addr().Is4() && s.Family == unix.AF_INET6 && s.V6Only != nil && *s.V6Only {
		return false
	}
	if f.Local.Addr().Is6() && !f.Local.Addr().Is4In6() && s.Family == unix.AF_INET {
		return false
	}
	if s.Local.Addr() != f.Local.Addr() && !s.Local.Addr().IsUnspecified() {
		return false
	}
	if f.Protocol == "tcp" && f.Direction == "incoming" {
		return s.State == 10
	}
	if s.Remote.Port() != 0 && s.Remote != f.Remote {
		return false
	}
	return true
}

// receivers lists the sockets that can receive f. For incoming TCP the kernel
// delivers to a full socket bound to exactly this local/remote pair before any
// listener: a simultaneous open, including a socket connecting to its own port.
// Only when no such socket exists does a listener receive the connection.
// Request sockets (half-open entries without an inode) never displace a listener.
func receivers(sockets []Socket, f Flow) []Socket {
	var exact, listeners []Socket
	for _, s := range sockets {
		if f.Protocol == "tcp" && f.Direction == "incoming" && exactTCPPeer(s, f) {
			exact = append(exact, s)
		} else if matches(s, f) {
			listeners = append(listeners, s)
		}
	}
	if len(exact) != 0 {
		return exact
	}
	return listeners
}

func exactTCPPeer(s Socket, f Flow) bool {
	local := netip.AddrPortFrom(f.Local.Addr().Unmap(), f.Local.Port())
	remote := netip.AddrPortFrom(f.Remote.Addr().Unmap(), f.Remote.Port())
	return s.Protocol == "tcp" && s.State != 10 && s.Inode != 0 && (!s.diagObserved || s.diagFull) && s.Local == local && s.Remote == remote
}

func Resolve(f Flow) Attribution {
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket", ReasonCode: ReasonNoSocketObserved}
	if f.NetNS != NetNS() {
		a.setReason(ReasonNamespaceMismatch, "foreign network namespace is outside this observer")
		return a
	}
	sockets, e := Sockets()
	if e != nil {
		a.setReason(ReasonSocketCensusUnavailable, "socket diagnostics unavailable: "+e.Error())
		return a
	}
	wanted := map[string]bool{}
	for _, s := range receivers(sockets, f) {
		a.Sockets = append(a.Sockets, s)
		wanted[fmt.Sprintf("socket:[%d]", s.Inode)] = true
	}
	if len(wanted) == 0 {
		return a
	}
	_, resolved := resolveHolderIdentities(wanted, func(pid int) (Process, error) {
		p, err := Inspect(pid)
		if err == nil {
			p.Provenance = CaptureProvenance(p)
		}
		return p, err
	}, nil)
	covered := map[string]bool{}
	incomplete := !resolved.Complete
	seen := map[string]bool{}
	for socket, owners := range resolved.Owners {
		for _, p := range owners {
			covered[socket] = true
			key := fmt.Sprintf("%d:%s:%s", p.PID, p.Start, p.HolderWitness)
			if !seen[key] {
				a.Owners = append(a.Owners, p)
				seen[key] = true
			}
		}
	}
	// A process may retain a socket from a different network namespace. Scan every
	// visible process, then verify the socket snapshot did not change mid-scan.
	again, err := Sockets()
	if err != nil {
		a.setReason(ReasonSocketCensusUnavailable, "socket recheck unavailable")
		return a
	}
	current := receivers(again, f)
	if fingerprint(nil, current) != fingerprint(nil, a.Sockets) {
		a.setReason(ReasonSocketChanged, "listener changed during attribution")
		return a
	}
	a.VisibilityComplete = !incomplete && len(covered) == len(wanted)
	a.Fingerprint = fingerprint(a.Owners, a.Sockets)
	if !incomplete && len(covered) == len(wanted) && len(a.Sockets) == 1 {
		if association, client := brokerAssociation(a.Owners); association != nil {
			a.Association = association
			app := client.Application
			a.Application = &app
			a.Status = "corroborated-broker-client"
			a.setReason(ReasonBrokerClientAssociation, "one visible Windows client and verified Wine broker; non-sharing handle assumption applies")
			a.Fingerprint = digest(a.Fingerprint + fmt.Sprintf("|%d:%d", association.ClientChannel, association.BrokerChannel))
			return a
		}
	}
	if unresolvedOwnership(&a, incomplete) {
		return a
	}
	if incomplete || len(covered) != len(wanted) {
		a.setReason(ReasonProcessVisibilityIncomplete, "incomplete process visibility; cannot exclude another owner")
		return a
	}
	p := a.Owners[0]
	if p.Application.Key == "" {
		a.setReason(ReasonRuntimeIdentityUnverified, "runtime observed but Windows image/prefix not corroborated")
		return a
	}
	a.Status = "directly-associated"
	if p.Application.Kind == "wine" {
		a.Status = "corroborated"
	}
	a.setReason(ReasonNativeOwnerObserved, "one visible socket and one current FD owner; observation is subject to races")
	if p.Application.Kind == "wine" {
		a.ReasonCode = ReasonRuntimeOwnerObserved
	}
	app := p.Application
	a.Application = &app
	return a
}
func ParseFlow(protocol, direction, local, remote string) (Flow, error) {
	l, e := netip.ParseAddrPort(local)
	if e != nil {
		return Flow{}, e
	}
	r, e := netip.ParseAddrPort(remote)
	if e != nil {
		return Flow{}, e
	}
	if !strings.Contains("|tcp|udp|", "|"+protocol+"|") || (direction != "incoming" && direction != "outgoing") {
		return Flow{}, fmt.Errorf("invalid protocol/direction")
	}
	return Flow{Protocol: protocol, Direction: direction, Local: l, Remote: r, NetNS: NetNS()}, nil
}

// A missing userspace holder is an observation, never proof of kernel origin.
// Preserve socket/fingerprint/visibility evidence and permission refusal.
func unresolvedOwnership(a *Attribution, incomplete bool) bool {
	if len(a.Sockets) == 1 && len(a.Owners) == 0 {
		a.Status = "unidentified"
		if incomplete {
			a.setReason(ReasonProcessVisibilityIncomplete, "process visibility incomplete; no supported userspace owner established")
		} else {
			a.setReason(ReasonNoUserspaceOwnerObserved, "socket observed without a visible userspace FD owner; kernel origin not established")
		}
		return true
	}
	if len(a.Sockets) != 1 || len(a.Owners) != 1 {
		a.Status = "multiple-candidates"
		a.setReason(ReasonMultipleCandidates, "multiple socket or process candidates; application permission unavailable")
		return true
	}
	return false
}
