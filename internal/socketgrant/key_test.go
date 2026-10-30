package socketgrant

import (
	"encoding/binary"
	"encoding/hex"
	"flowgate/internal/identity"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// Real kernel ABI check, not an application-identity or enforcement test.
func TestNetlinkCookieEqualsSocketCookie(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var socketErr error
	if err = raw.Control(func(fd uintptr) { cookie, socketErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE) }); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	rows, err := identity.UDPPortSockets(local.Port())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rows {
		if s.Local != local {
			continue
		}
		b, err := hex.DecodeString(s.Cookie)
		if err != nil || len(b) != 8 {
			t.Fatal(s.Cookie, err)
		}
		if binary.NativeEndian.Uint64(b) != cookie {
			t.Fatalf("netlink %x != SO_COOKIE %x", b, cookie)
		}
		return
	}
	t.Fatal("bound socket missing from netlink")
}
