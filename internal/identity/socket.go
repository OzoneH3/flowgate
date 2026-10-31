package identity

import (
	"encoding/binary"
	diagnostics "flowgate/internal/serveprofile"
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
	queueOutputInterface uint32         // private NFQUEUE evidence, never decoded from API/collector JSON
	NetworkScope         NetworkScope   `json:"network_scope"`
	Protocol             string         `json:"protocol"`
	Direction            string         `json:"direction"`
	Local                netip.AddrPort `json:"local"`
	Remote               netip.AddrPort `json:"remote"`
	NetNS                string         `json:"netns"`
	Interface            uint32         `json:"interface_index"`
}

func (f Flow) Key() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", f.NetNS, f.Protocol, f.Direction, f.Local, f.Remote)
}

type Attribution struct {
	freshConnectionProof                                            bool          // set only by complete observation, never JSON or reuse
	renewalPhase                                                    *renewalPhase // observation-only; never identity or policy evidence
	diagnosticHolderAttempts                                        int
	diagnosticFirstIssues                                           []string
	diagnosticBegin, diagnosticEnd                                  time.Time
	diagnosticDumpEnd, diagnosticRecheckBegin, diagnosticRecheckEnd time.Time
	diagnosticRecheck                                               []Socket
	diagnosticIssues                                                []string
	diagnosticSocketIssues                                          map[string]string
	diagnosticSource                                                string
	diagnosticHintAge                                               time.Duration
	presentationTarget                                              *permissionPresentation // immutable-list display only; never authority
	Table                                                           *TableEvidence          `json:"runtime_table,omitempty"`
	VisibilityComplete                                              bool                    `json:"visibility_complete"`
	Association                                                     *Association            `json:"association,omitempty"`
	Status                                                          string                  `json:"status"`
	Reason                                                          string                  `json:"reason"`
	ReasonCode                                                      string                  `json:"reason_code,omitempty"`
	Owners                                                          []Process               `json:"owners"`
	Sockets                                                         []Socket                `json:"sockets"`
	Fingerprint                                                     string                  `json:"fingerprint"`
	Application                                                     *Application            `json:"application,omitempty"`
}

// FreshConnectionProof identifies a complete observation from THIS resolver
// call, not native reuse or presentation data. It is not itself permission.
func (a Attribution) FreshConnectionProof() bool { return a.freshConnectionProof }

func NetNS() string              { return link("/proc/self/ns/net") }
func Sockets() ([]Socket, error) { return SocketsLimited(0) }

// UDPSockets is the complete UDP census of both families, without TCP rows.
func UDPSockets() ([]Socket, error) { return socketsFor([]byte{unix.IPPROTO_UDP}, 0) }

// SocketsLimited bounds retained rows; zero preserves the enforcement census.
func SocketsLimited(limit int) ([]Socket, error) {
	return socketsFor([]byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}, limit)
}

// UDPPortSockets retains every UDP competitor on this local port in both
// address families. This is a filtered multipart dump, never a single-socket
// lookup: wildcard, dual-stack and reuseport ambiguity must remain visible.
func UDPPortSockets(port uint16) ([]Socket, error) {
	if port == 0 {
		return nil, fmt.Errorf("UDP local port is zero")
	}
	return socketsForPort([]byte{unix.IPPROTO_UDP}, 0, port)
}

func socketsFor(protos []byte, limit int) ([]Socket, error) {
	return socketsForPort(protos, limit, 0)
}

func diagRequest(family, proto byte, limit int, port uint16) []byte {
	req := make([]byte, 56)
	req[0], req[1] = family, proto
	if limit > 0 && proto == unix.IPPROTO_TCP {
		req[2] = 1 << (2 - 1)
	}
	binary.NativeEndian.PutUint32(req[4:8], 0xffffffff)
	// inet_diag_sockid.idiag_sport is network byte order. No destination or
	// address filter: connected and unconnected candidates are both needed.
	binary.BigEndian.PutUint16(req[8:10], port)
	for i := 48; i < 56; i++ {
		req[i] = 255
	}
	return req
}

func socketsForPort(protos []byte, limit int, port uint16) ([]Socket, error) {
	defer diagnostics.Begin(diagnostics.SocketCensus).End()
	c, e := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var result []Socket
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range protos {
			req := diagRequest(family, proto, limit, port)
			var msgs []netlink.Message
			if limit > 0 {
				// At the aggregate limit, still distinguish an empty remaining
				// family/protocol from overflow. One sentinel row suffices; it is
				// rejected below and never added to the retained result.
				remaining := limit - len(result)
				if remaining == 0 {
					remaining = 1
				}
				msgs, e = boundedDiag(req, remaining)
			} else {
				msgs, e = c.Execute(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request | netlink.Dump}, Data: req})
			}
			dumpErr := e
			if e != nil && len(msgs) == 0 {
				return result, e
			}
			for _, m := range msgs {
				if limit > 0 && len(result) >= limit {
					return result, ErrSocketCensusCapacity
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

// socketDumps are the SOCK_DIAG providers Resolve chooses from; tests substitute
// deterministic models. Both passes of one Resolve use the same provider.
var socketDumps = struct {
	full    func() ([]Socket, error)
	udpPort func(uint16) ([]Socket, error)
}{Sockets, UDPPortSockets}

// resolveDump selects the socket census for a flow. A UDP flow with a concrete
// local port can only be received by UDP sockets bound to that port in either
// address family (matches requires equal protocol and local port), so the
// kernel's port-filtered multipart dump yields exactly the competitor set the
// full dump yields after matches: wildcard, dual-stack and reuseport
// candidates included. Every other flow, and a zero port, keeps the full dump.
// This changes cost only: failure handling and the recheck are unchanged.
func resolveDump(f Flow) (func() ([]Socket, error), string) {
	if f.Protocol == "udp" && f.Local.Port() != 0 {
		port := f.Local.Port()
		return func() ([]Socket, error) { return socketDumps.udpPort(port) }, "udp-port"
	}
	return socketDumps.full, "full"
}

// inspectWithProvenance is the holder inspection both Resolve and ResolveBatch use.
func inspectWithProvenance(pid int) (Process, error) {
	p, err := Inspect(pid)
	if err == nil {
		p.Provenance = CaptureProvenance(p)
	}
	return p, err
}

func Resolve(f Flow) (result Attribution) {
	begin := diagnostics.ObservationTime()
	defer func() { result.diagnosticBegin = begin; result.diagnosticEnd = diagnostics.ObservationTime() }()
	defer diagnostics.Begin(diagnostics.FullResolve).End()
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket", ReasonCode: ReasonNoSocketObserved}
	if f.NetNS != NetNS() {
		a.setReason(ReasonNamespaceMismatch, "foreign network namespace is outside this observer")
		return a
	}
	dump, _ := resolveDump(f)
	sockets, e := dump()
	a.diagnosticDumpEnd = diagnostics.ObservationTime()
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
		diagnosticNoSocket("resolve", f, sockets, begin)
		return a
	}
	_, resolved := resolveHolderIdentities(wanted, inspectWithProvenance, nil)
	if !begin.IsZero() {
		a.diagnosticHolderAttempts = resolved.diagnosticAttempts
		a.diagnosticFirstIssues = resolved.diagnosticFirstIssues
		a.diagnosticIssues = resolved.Issues
		a.diagnosticSocketIssues = resolved.SocketIssues
	}
	// Observed owners are evidence recorded before the recheck, so a failed
	// recheck keeps them (without granting visibility or authority).
	covered := collectOwners(&a, wanted, resolved.Owners)
	// A process may retain a socket from a different network namespace. Scan every
	// visible process, then verify the socket snapshot did not change mid-scan,
	// using the same census provider as the first pass.
	a.diagnosticRecheckBegin = diagnostics.ObservationTime()
	again, err := dump()
	a.diagnosticRecheckEnd = diagnostics.ObservationTime()
	if err != nil {
		a.setReason(ReasonSocketCensusUnavailable, "socket recheck unavailable")
		return a
	}
	current := receivers(again, f)
	if !begin.IsZero() {
		a.diagnosticRecheck = current
	}
	finalizeAttribution(&a, wanted, covered, !resolved.Complete, current)
	return a
}

// collectOwners appends the de-duplicated holders of this flow's wanted sockets
// to a.Owners and returns how many wanted sockets have at least one holder.
// owners entries for sockets outside wanted are ignored.
func collectOwners(a *Attribution, wanted map[string]bool, owners map[string][]Process) int {
	covered := map[string]bool{}
	seen := map[string]bool{}
	for socket, ps := range owners {
		if !wanted[socket] {
			continue
		}
		for _, p := range ps {
			covered[socket] = true
			key := fmt.Sprintf("%d:%s:%s", p.PID, p.Start, p.HolderWitness)
			if !seen[key] {
				a.Owners = append(a.Owners, p)
				seen[key] = true
			}
		}
	}
	return len(covered)
}

// finalizeAttribution applies the post-recheck decision shared by Resolve and
// ResolveBatch to ONE flow whose owners were already collected for its own
// wanted sockets (covered = wanted sockets with a holder). current is the
// flow's receiver set from the recheck dump.
func finalizeAttribution(a *Attribution, wanted map[string]bool, covered int, incomplete bool, current []Socket) {
	if fingerprint(nil, current) != fingerprint(nil, a.Sockets) {
		a.setReason(ReasonSocketChanged, "listener changed during attribution")
		return
	}
	a.VisibilityComplete = !incomplete && covered == len(wanted)
	a.Fingerprint = fingerprint(a.Owners, a.Sockets)
	if !incomplete && covered == len(wanted) && len(a.Sockets) == 1 {
		if association, client := brokerAssociation(a.Owners); association != nil {
			a.Association = association
			app := client.Application
			a.Application = &app
			a.Status = "corroborated-broker-client"
			a.setReason(ReasonBrokerClientAssociation, "one visible Windows client and verified Wine broker; non-sharing handle assumption applies")
			a.Fingerprint = digest(a.Fingerprint + fmt.Sprintf("|%d:%d", association.ClientChannel, association.BrokerChannel))
			return
		}
	}
	if unresolvedOwnership(a, incomplete) {
		return
	}
	if incomplete || covered != len(wanted) {
		a.setReason(ReasonProcessVisibilityIncomplete, "incomplete process visibility; cannot exclude another owner")
		return
	}
	p := a.Owners[0]
	if p.Application.Key == "" {
		a.setReason(ReasonRuntimeIdentityUnverified, "runtime observed but Windows image/prefix not corroborated")
		return
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
	a.freshConnectionProof = true
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
