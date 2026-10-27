package identity

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// SocketExists checks the original socket generation, not its current owners.
// It is intended for shaping lease maintenance, never permission authority.
// Discovery rejects foreign-namespace flows before binding; a namespace mismatch
// here is an error, never evidence that a foreign socket disappeared.
// The network namespace is selected by the query socket, not returned by DIAG.
func SocketExists(s Socket) (bool, error) {
	if s.NetNS == "" || s.NetNS != NetNS() {
		return false, fmt.Errorf("exact socket namespace mismatch")
	}
	req, err := exactSocketRequest(s)
	if err != nil {
		return false, err
	}
	c, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false, err
	}
	ms, err := c.Execute(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request}, Data: req})
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESTALE) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(ms) != 1 || ms[0].Header.Type != 20 || ms[0].Header.Flags&netlink.Multi != 0 {
		return false, fmt.Errorf("unexpected exact socket response")
	}
	return exactSocketReply(s, ms[0].Data)
}

func exactSocketRequest(s Socket) ([]byte, error) {
	if s.Inode == 0 || !s.Local.IsValid() || !s.Remote.IsValid() || s.Local.Port() == 0 ||
		(s.Family != unix.AF_INET && s.Family != unix.AF_INET6) {
		return nil, fmt.Errorf("unsupported exact socket descriptor")
	}
	cookie, err := hex.DecodeString(s.Cookie)
	if err != nil || len(cookie) != 8 || s.Cookie == "ffffffffffffffff" {
		return nil, fmt.Errorf("invalid exact socket cookie")
	}
	var proto byte
	switch s.Protocol {
	case "tcp":
		proto = unix.IPPROTO_TCP
	case "udp":
		proto = unix.IPPROTO_UDP
	default:
		return nil, fmt.Errorf("unsupported exact socket protocol")
	}
	local, remote := s.Local, s.Remote
	// udp_diag_dump_one uses the historical reversed lookup convention.
	if proto == unix.IPPROTO_UDP {
		local, remote = remote, local
	}
	r := make([]byte, 56)
	r[0], r[1] = s.Family, proto
	binary.NativeEndian.PutUint32(r[4:8], ^uint32(0))
	binary.BigEndian.PutUint16(r[8:10], local.Port())
	binary.BigEndian.PutUint16(r[10:12], remote.Port())
	for i, addr := range []netip.Addr{local.Addr(), remote.Addr()} {
		if s.Family == unix.AF_INET {
			if !addr.Unmap().Is4() {
				return nil, fmt.Errorf("exact socket family mismatch")
			}
			a := addr.As4()
			copy(r[12+i*16:], a[:])
		} else {
			a := addr.As16()
			copy(r[12+i*16:], a[:])
		}
	}
	binary.NativeEndian.PutUint32(r[44:48], s.Interface)
	copy(r[48:56], cookie)
	return r, nil
}

func exactSocketReply(s Socket, b []byte) (bool, error) {
	if len(b) < 72 || b[0] != s.Family {
		return false, fmt.Errorf("malformed exact socket response")
	}
	var local, remote netip.Addr
	if s.Family == unix.AF_INET {
		local = netip.AddrFrom4([4]byte(b[8:12]))
		remote = netip.AddrFrom4([4]byte(b[24:28]))
	} else {
		local = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		remote = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	}
	return netip.AddrPortFrom(local, binary.BigEndian.Uint16(b[4:6])) == s.Local &&
		netip.AddrPortFrom(remote, binary.BigEndian.Uint16(b[6:8])) == s.Remote &&
		binary.NativeEndian.Uint32(b[40:44]) == s.Interface &&
		hex.EncodeToString(b[44:52]) == s.Cookie &&
		binary.NativeEndian.Uint32(b[64:68]) == s.UID &&
		binary.NativeEndian.Uint32(b[68:72]) == s.Inode, nil
}
