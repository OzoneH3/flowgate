package queue

import (
	"context"
	"encoding/binary"
	"errors"
	"flowgate/internal/identity"
	"fmt"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real payload delivery, not just SYN attribution. Use scripts/lab.sh: never
// install test firewall rules in the host namespace.
func TestSelfConnectPayloadKernel(t *testing.T) {
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	current, _ := os.Readlink("/proc/self/ns/net")
	if parent == "" || parent == current {
		t.Skip("requires scripts/lab.sh private netns")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: 104, MaxQueueLen: 128, MaxPacketLen: 65535, Copymode: nfqueue.NfQnlCopyPacket, Flags: nfqueue.NfQaCfgFlagConntrack, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	var mode atomic.Int32 // 0: reproduce, 1: fix, 2: deny incoming, 3: deny outgoing
	var updates atomic.Int32
	errs := make(chan error, 32)
	check := func(e error) {
		if e != nil {
			select {
			case errs <- e:
			default:
			}
		}
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		direction := "outgoing"
		if a.Hook != nil && *a.Hook == 1 {
			direction = "incoming"
		}
		allow := !(mode.Load() == 2 && direction == "incoming") && !(mode.Load() == 3 && direction == "outgoing")
		if allow && (mode.Load() == 1 || mode.Load() == 4) && a.Payload != nil {
			f, _, e := Parse(*a.Payload, direction)
			if a.InDev != nil {
				f.Interface = *a.InDev
			}
			check(e)
			if e == nil && selfConnect(f) {
				var raw []byte
				if a.Ct != nil {
					raw = *a.Ct
				}
				msg, e := selfConnectUpdate(f, raw)
				if e == nil {
					if mode.Load() == 4 {
						header, attrs, err := netfilter.UnmarshalNetlink(msg)
						if err != nil {
							check(err)
						}
						for i := range attrs {
							if attrs[i].Type == 12 {
								binary.BigEndian.PutUint32(attrs[i].Data, binary.BigEndian.Uint32(attrs[i].Data)^1)
							}
						}
						msg, err = netfilter.MarshalNetlink(header, attrs)
						check(err)
						e = applySelfConnectUpdate(msg)
						if !errors.Is(e, unix.ENOENT) {
							check(fmt.Errorf("mismatched ID: %v", e))
						}
						allow = false
						check(nf.SetVerdict(*a.PacketID, nfqueue.NfDrop))
						return 0
					}
					e = applySelfConnectUpdate(msg)
				}
				check(e)
				allow = e == nil
				if allow {
					updates.Add(1)
				}
			}
		}
		verdict := nfqueue.NfDrop
		if allow {
			verdict = nfqueue.NfAccept
		}
		check(nf.SetVerdict(*a.PacketID, verdict))
		return 0
	}, func(e error) int { check(e); return 0 })
	if err != nil {
		t.Fatal(err)
	}
	rules := "add table inet self_payload\n"
	for _, h := range []string{"input", "output"} {
		rules += fmt.Sprintf(`add chain inet self_payload %s { type filter hook %s priority 10; policy accept; }
add chain inet self_payload admit_%s { type filter hook %s priority 11; policy accept; }
add rule inet self_payload admit_%s meta l4proto tcp ct mark set ct mark | 0x10000000
add rule inet self_payload %s meta l4proto != tcp accept
add rule inet self_payload %s ct state invalid counter drop
add rule inet self_payload %s ct direction reply ct mark & 0x30000000 != 0 accept
add rule inet self_payload %s tcp flags & (syn | ack) == syn queue num 104
add rule inet self_payload %s ct mark & 0x20000000 != 0 accept
add rule inet self_payload %s ct mark & 0x10000000 != 0 ct state established accept
add rule inet self_payload %s counter drop
`, h, h, h, h, h, h, h, h, h, h, h, h)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("nft: %v %s", e, out)
	}
	defer exec.Command("nft", "delete", "table", "inet", "self_payload").Run()
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, m := range []int32{0, 1, 2, 3, 4} {
			t.Run(fmt.Sprintf("%s/mode%d", host, m), func(t *testing.T) {
				mode.Store(m)
				before := updates.Load()
				c, e := dialSelf(host)
				if m >= 2 {
					if e == nil {
						c.Close()
						t.Fatal("denied SYN connected")
					}
					if updates.Load() != before {
						t.Fatal("denial changed tracking")
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				for i, p := range []string{"first", "second", "third", "fourth"} {
					if _, e = c.Write([]byte(p)); e != nil {
						t.Fatal(e)
					}
					b := make([]byte, len(p))
					_, e = io.ReadFull(c, b)
					if m == 0 && i == 1 {
						if e == nil {
							t.Fatal("expected baseline invalid-state payload failure")
						}
						return
					}
					if e != nil || string(b) != p {
						t.Fatalf("payload %d: %q %v", i, b, e)
					}
				}
				if m == 1 && updates.Load() == before {
					t.Fatal("no incoming update")
				}
			})
		}
	}
	select {
	case e := <-errs:
		t.Fatal(e)
	default:
	}
}

func dialSelf(host string) (net.Conn, error) {
	family := unix.AF_INET
	var sa unix.Sockaddr = &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if host == "::1" {
		family = unix.AF_INET6
		sa = &unix.SockaddrInet6{Addr: netip.IPv6Loopback().As16()}
	}
	fd, e := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	if e = unix.Bind(fd, sa); e != nil {
		return nil, e
	}
	sa, e = unix.Getsockname(fd)
	if e != nil {
		return nil, e
	}
	e = unix.Connect(fd, sa)
	if e != nil && e != unix.EINPROGRESS {
		return nil, e
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	n, e := unix.Poll(poll, 500)
	if e != nil {
		return nil, e
	}
	if n == 0 {
		return nil, fmt.Errorf("connect timeout")
	}
	if code, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); e != nil || code != 0 {
		return nil, fmt.Errorf("connect: %d %v", code, e)
	}
	dup, e := unix.Dup(fd)
	if e != nil {
		return nil, e
	}
	file := os.NewFile(uintptr(dup), "self-connect")
	defer file.Close()
	return net.FileConn(file)
}

func TestSelfConnectScope(t *testing.T) {
	for _, tc := range []struct {
		proto, dir, local, remote string
		want                      bool
	}{
		{"tcp", "incoming", "127.0.0.1:1234", "127.0.0.1:1234", true},
		{"tcp", "incoming", "[::1]:1234", "[::1]:1234", true},
		{"tcp", "outgoing", "127.0.0.1:1234", "127.0.0.1:1234", false},
		{"udp", "incoming", "127.0.0.1:1234", "127.0.0.1:1234", false},
		{"tcp", "incoming", "127.0.0.1:1234", "127.0.0.1:1235", false},
		{"tcp", "incoming", "192.0.2.1:1234", "192.0.2.1:1234", false},
	} {
		f := identity.Flow{Protocol: tc.proto, Direction: tc.dir, Local: netip.MustParseAddrPort(tc.local), Remote: netip.MustParseAddrPort(tc.remote)}
		if selfConnect(f) != tc.want {
			t.Fatal(tc)
		}
		if _, e := selfConnectUpdate(f, nil); e == nil {
			t.Fatal("missing evidence accepted")
		}
	}
}

func TestSelfConnectEvidenceAndUpdateFields(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			index = uint32(i.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("no loopback")
	}
	f := identity.Flow{Protocol: "tcp", Direction: "incoming", Local: netip.MustParseAddrPort("127.0.0.1:1234"), Remote: netip.MustParseAddrPort("127.0.0.1:1234"), Interface: index}
	nest := func(kind uint16, children ...netfilter.Attribute) netfilter.Attribute {
		return netfilter.Attribute{Type: kind, Nested: true, Children: children}
	}
	fixture := func() []netfilter.Attribute {
		tuple := func(kind uint16) netfilter.Attribute {
			return nest(kind,
				nest(1, netfilter.Attribute{Type: 1, Data: []byte{127, 0, 0, 1}}, netfilter.Attribute{Type: 2, Data: []byte{127, 0, 0, 1}}),
				nest(2, netfilter.Attribute{Type: 1, Data: []byte{6}}, netfilter.Attribute{Type: 2, Data: netfilter.Uint16Bytes(1234)}, netfilter.Attribute{Type: 3, Data: netfilter.Uint16Bytes(1234)}))
		}
		return []netfilter.Attribute{tuple(1), tuple(2), {Type: 3, Data: netfilter.Uint32Bytes(8)}, {Type: 12, Data: netfilter.Uint32Bytes(42)}, {Type: 18, Data: netfilter.Uint16Bytes(7)}}
	}
	for _, name := range []string{"valid", "no-id", "unconfirmed", "different-original", "different-reply", "udp", "bad-zone", "no-interface"} {
		t.Run(name, func(t *testing.T) {
			a := fixture()
			flow := f
			switch name {
			case "no-id":
				a[3].Data = nil
			case "unconfirmed":
				a[2].Data = netfilter.Uint32Bytes(0)
			case "different-original":
				a[0].Children[0].Children[0].Data = []byte{127, 0, 0, 2}
			case "different-reply":
				a[1].Children[1].Children[1].Data = netfilter.Uint16Bytes(1235)
			case "udp":
				a[0].Children[1].Children[0].Data = []byte{17}
			case "bad-zone":
				a[4].Data = []byte{1}
			case "no-interface":
				flow.Interface = 0
			}
			raw, e := netfilter.MarshalAttributes(a)
			if e != nil {
				t.Fatal(e)
			}
			msg, e := selfConnectUpdate(flow, raw)
			if name != "valid" {
				if e == nil {
					t.Fatal("invalid evidence accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			_, got, e := netfilter.UnmarshalNetlink(msg)
			if e != nil {
				t.Fatal(e)
			}
			if len(got) != 4 || got[0].Type != 1 || got[1].Type != 12 || got[2].Type != 4 || got[3].Type != 18 {
				t.Fatalf("unexpected update fields: %+v", got)
			}
			if binary.BigEndian.Uint32(got[1].Data) != 42 || binary.BigEndian.Uint16(got[3].Data) != 7 {
				t.Fatal("ID/zone lost")
			}
			tcp := got[2].Children
			if len(tcp) != 1 || tcp[0].Type != 1 || len(tcp[0].Children) != 2 {
				t.Fatal("invalid protoinfo")
			}
			for i, a := range tcp[0].Children {
				if a.Type != uint16(4+i) || len(a.Data) != 2 || a.Data[0] != 8 || a.Data[1] != 8 {
					t.Fatalf("flags not masked: %+v", a)
				}
			}
		})
	}
}
