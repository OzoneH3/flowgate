package identity

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Socket struct {
	Protocol string         `json:"protocol"`
	Local    netip.AddrPort `json:"local"`
	Remote   netip.AddrPort `json:"remote"`
	State    uint8          `json:"state"`
	Inode    uint32         `json:"inode"`
	Cookie   string         `json:"cookie"`
	UID      uint32         `json:"uid"`
	NetNS    string         `json:"netns"`
}
type Flow struct {
	Protocol  string         `json:"protocol"`
	Direction string         `json:"direction"`
	Local     netip.AddrPort `json:"local"`
	Remote    netip.AddrPort `json:"remote"`
	NetNS     string         `json:"netns"`
	Interface uint32         `json:"interface_index"`
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
	Owners             []Process      `json:"owners"`
	Sockets            []Socket       `json:"sockets"`
	Fingerprint        string         `json:"fingerprint"`
	Application        *Application   `json:"application,omitempty"`
}

func NetNS() string { return link("/proc/self/ns/net") }
func Sockets() ([]Socket, error) {
	c, e := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var result []Socket
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			req := make([]byte, 56)
			req[0] = family
			req[1] = proto
			binary.NativeEndian.PutUint32(req[4:8], 0xffffffff)
			for i := 48; i < 56; i++ {
				req[i] = 255
			}
			msgs, e := c.Execute(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request | netlink.Dump}, Data: req})
			if e != nil {
				return nil, e
			}
			for _, m := range msgs {
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
				name := "tcp"
				if proto == unix.IPPROTO_UDP {
					name = "udp"
				}
				result = append(result, Socket{Protocol: name, Local: netip.AddrPortFrom(la.Unmap(), binary.BigEndian.Uint16(b[4:6])), Remote: netip.AddrPortFrom(ra.Unmap(), binary.BigEndian.Uint16(b[6:8])), State: b[1], Inode: binary.NativeEndian.Uint32(b[68:72]), UID: binary.NativeEndian.Uint32(b[64:68]), Cookie: fmt.Sprintf("%x", b[44:52]), NetNS: NetNS()})
			}
		}
	}
	return result, nil
}
func matches(s Socket, f Flow) bool {
	if s.Protocol != f.Protocol || s.Local.Port() != f.Local.Port() {
		return false
	}
	// Include IPv6 wildcard as a candidate for IPv4; v6-only is not known in this baseline.
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
func Resolve(f Flow) Attribution {
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket"}
	if f.NetNS != NetNS() {
		a.Reason = "foreign network namespace is outside this observer"
		return a
	}
	sockets, e := Sockets()
	if e != nil {
		a.Reason = "socket diagnostics unavailable: " + e.Error()
		return a
	}
	wanted := map[string]bool{}
	for _, s := range sockets {
		if matches(s, f) {
			a.Sockets = append(a.Sockets, s)
			wanted[fmt.Sprintf("socket:[%d]", s.Inode)] = true
		}
	}
	if len(wanted) == 0 {
		return a
	}
	entries, _ := os.ReadDir("/proc")
	covered := map[string]bool{}
	incomplete := false
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		base := "/proc/" + entry.Name()
		ns := link(base + "/ns/net")
		if ns == "" {
			status := string(readBound(base+"/status", 4096))
			if status == "" {
				if _, err := os.Stat(base); os.IsNotExist(err) {
					continue
				}
			}
			if strings.Contains(status, "State:\tZ") {
				continue
			}
			incomplete = true
			continue
		}
		fds, e := os.ReadDir(base + "/fd")
		if e != nil {
			incomplete = true
			continue
		}
		owns := false
		for _, fd := range fds {
			s := link(base + "/fd/" + fd.Name())
			if wanted[s] {
				owns = true
				covered[s] = true
			}
		}
		if owns {
			p, e := Inspect(pid)
			if e != nil {
				incomplete = true
			} else {
				a.Owners = append(a.Owners, p)
			}
		}
	}
	// A process may retain a socket from a different network namespace. Scan every
	// visible process, then verify the socket snapshot did not change mid-scan.
	again, err := Sockets()
	if err != nil {
		a.Reason = "socket recheck unavailable"
		return a
	}
	var current []Socket
	for _, s := range again {
		if matches(s, f) {
			current = append(current, s)
		}
	}
	if fingerprint(nil, current) != fingerprint(nil, a.Sockets) {
		a.Reason = "listener changed during attribution"
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
			a.Reason = "one visible Windows client and verified Wine broker; non-sharing handle assumption applies"
			a.Fingerprint = digest(a.Fingerprint + fmt.Sprintf("|%d:%d", association.ClientChannel, association.BrokerChannel))
			return a
		}
	}
	if len(a.Sockets) != 1 || len(a.Owners) != 1 {
		a.Status = "multiple-candidates"
		a.Reason = "shared descriptor, shared listener, or hidden owner; application permission unavailable"
		return a
	}
	if incomplete || len(covered) != len(wanted) {
		a.Reason = "incomplete process visibility; cannot exclude another owner"
		return a
	}
	p := a.Owners[0]
	if p.Application.Key == "" {
		a.Reason = "runtime observed but Windows image/prefix not corroborated"
		return a
	}
	a.Status = "directly-associated"
	if p.Application.Kind == "wine" {
		a.Status = "corroborated"
	}
	a.Reason = "one visible socket and one current FD owner; observation is subject to races"
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
