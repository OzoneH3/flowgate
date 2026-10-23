package socketcontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"flowgate/internal/identity"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func socket() identity.Socket {
	return identity.Socket{Family: unix.AF_INET, Protocol: "tcp", State: 1, Inode: 123, Cookie: "0102030405060708", UID: 1000, NetNS: "net:[1]", Local: netip.MustParseAddrPort("127.0.0.1:1234"), Remote: netip.MustParseAddrPort("127.0.0.1:5678")}
}

func reply(s identity.Socket, request []byte) []netlink.Message {
	b := make([]byte, 72)
	b[0], b[1] = s.Family, s.State
	copy(b[4:52], request[8:56])
	binary.NativeEndian.PutUint32(b[64:68], s.UID)
	binary.NativeEndian.PutUint32(b[68:72], s.Inode)
	return []netlink.Message{{Header: netlink.Header{Type: 20}, Data: b}}
}

func acknowledgement() []netlink.Message {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint16(b[8:10], 21)
	return []netlink.Message{{Header: netlink.Header{Type: netlink.Error}, Data: b}}
}

func TestInvalidTargets(t *testing.T) {
	for name, change := range map[string]func(*identity.Socket){
		"udp":             func(s *identity.Socket) { s.Protocol = "udp" },
		"listener":        func(s *identity.Socket) { s.State = 10 },
		"inode":           func(s *identity.Socket) { s.Inode = 0 },
		"namespace":       func(s *identity.Socket) { s.NetNS = "" },
		"cookie_absent":   func(s *identity.Socket) { s.Cookie = "" },
		"cookie_wildcard": func(s *identity.Socket) { s.Cookie = "ffffffffffffffff" },
		"cookie_zero":     func(s *identity.Socket) { s.Cookie = "0000000000000000" },
		"cookie_short":    func(s *identity.Socket) { s.Cookie = "01020304" },
		"cookie_invalid":  func(s *identity.Socket) { s.Cookie = "nothex0102030405" },
		"family":          func(s *identity.Socket) { s.Family = unix.AF_UNIX },
		"mixed_family":    func(s *identity.Socket) { s.Remote = netip.MustParseAddrPort("[::1]:5678") },
		"unspecified":     func(s *identity.Socket) { s.Remote = netip.MustParseAddrPort("0.0.0.0:5678") },
		"port_zero":       func(s *identity.Socket) { s.Local = netip.MustParseAddrPort("127.0.0.1:0") },
		"invalid_address": func(s *identity.Socket) { s.Local = netip.AddrPort{} },
	} {
		t.Run(name, func(t *testing.T) {
			s := socket()
			change(&s)
			if _, err := encode(s); err == nil {
				t.Fatal("invalid target accepted")
			}
		})
	}
}

func TestFreshMismatchNeverDestroys(t *testing.T) {
	for _, offset := range []int{0, 1, 4, 6, 8, 24, 40, 44, 64, 68} {
		s := socket()
		req, _ := encode(s)
		calls := 0
		r, err := abort(context.Background(), s, req, func(m netlink.Message) ([]netlink.Message, error) {
			calls++
			out := reply(s, req)
			out[0].Data[offset] ^= 1
			return out, nil
		})
		if err == nil || r.Status != Rejected || r.Attempted || calls != 1 {
			t.Fatalf("offset %d: %+v %v calls=%d", offset, r, err, calls)
		}
	}
}

func TestNoDestroyForIncompleteOrUnframedResponse(t *testing.T) {
	s := socket()
	req, _ := encode(s)
	for _, response := range [][]netlink.Message{nil, {{Data: make([]byte, 72)}}, {{Header: netlink.Header{Type: 20}, Data: make([]byte, 71)}}, append(reply(s, req), reply(s, req)...)} {
		calls := 0
		r, err := abort(context.Background(), s, req, func(netlink.Message) ([]netlink.Message, error) { calls++; return response, nil })
		if err == nil || r.Attempted || r.Status != Rejected || calls != 1 {
			t.Fatalf("%+v %v calls=%d", r, err, calls)
		}
	}
}

func TestExactAbortAndErrorOutcomes(t *testing.T) {
	for _, test := range []struct {
		err  error
		want Status
	}{
		{nil, Acknowledged}, {unix.ENOENT, NotFound}, {unix.ESRCH, NotFound},
		{unix.EPERM, Forbidden}, {unix.EOPNOTSUPP, Unsupported},
		{context.DeadlineExceeded, Unknown}, {errors.New("lost acknowledgement"), Unknown},
	} {
		s := socket()
		req, _ := encode(s)
		calls := 0
		r, err := abort(context.Background(), s, req, func(m netlink.Message) ([]netlink.Message, error) {
			calls++
			if string(m.Data) != string(req) {
				t.Fatal("exact cookie/tuple changed")
			}
			if calls == 1 {
				if m.Header.Type != 20 || m.Header.Flags != netlink.Request {
					t.Fatal("query must be exact, without dump")
				}
				return reply(s, req), nil
			}
			if m.Header.Type != 21 || m.Header.Flags != netlink.Request|netlink.Acknowledge {
				t.Fatal("invalid destroy message")
			}
			return acknowledgement(), test.err
		})
		if r.Status != test.want || !r.Attempted || !errors.Is(err, test.err) || calls != 2 {
			t.Fatalf("%+v %v calls=%d", r, err, calls)
		}
	}
}

func TestMissingAcknowledgementIsUnknownWithoutRetry(t *testing.T) {
	s := socket()
	req, _ := encode(s)
	badType := acknowledgement()
	badType[0].Header.Type = netlink.Done
	badRequest := acknowledgement()
	badRequest[0].Data[8] = 20
	badError := acknowledgement()
	badError[0].Data[0] = 1
	for _, response := range [][]netlink.Message{nil, {{Header: netlink.Header{Type: netlink.Error}, Data: make([]byte, 4)}}, badType, badRequest, badError, append(acknowledgement(), acknowledgement()...)} {
		calls := 0
		r, err := abort(context.Background(), s, req, func(netlink.Message) ([]netlink.Message, error) {
			calls++
			if calls == 1 {
				return reply(s, req), nil
			}
			return response, nil
		})
		if err == nil || r.Status != Unknown || !r.Attempted || calls != 2 {
			t.Fatal(r, err, calls)
		}
	}
}

func TestReadErrorAndCancellationNeverDestroy(t *testing.T) {
	s := socket()
	req, _ := encode(s)
	for _, failure := range []error{unix.ENOENT, unix.EPERM, unix.EOPNOTSUPP, context.DeadlineExceeded} {
		calls := 0
		r, err := abort(context.Background(), s, req, func(netlink.Message) ([]netlink.Message, error) { calls++; return nil, failure })
		if !errors.Is(err, failure) || r.Attempted || r.Status == Unknown || calls != 1 {
			t.Fatalf("%+v %v calls=%d", r, err, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	r, err := abort(ctx, s, req, func(netlink.Message) ([]netlink.Message, error) { calls++; cancel(); return reply(s, req), nil })
	if !errors.Is(err, context.Canceled) || r.Attempted || calls != 1 {
		t.Fatal(r, err, calls)
	}
	r, err = abort(ctx, s, req, func(netlink.Message) ([]netlink.Message, error) { t.Fatal("query after cancel"); return nil, nil })
	if !errors.Is(err, context.Canceled) || r.Attempted {
		t.Fatal(r, err)
	}
}

func TestNamespaceAndIPv6(t *testing.T) {
	r, err := Abort(context.Background(), socket())
	if err == nil || r.Status != Rejected || r.Attempted {
		t.Fatal(r, err)
	}
	for _, endpoints := range [][2]string{{"[::1]:1234", "[::1]:5678"}, {"127.0.0.1:1234", "127.0.0.1:5678"}, {"[fe80::1%7]:1234", "[fe80::2%7]:5678"}} {
		s := socket()
		s.Family = unix.AF_INET6
		s.Interface = 7
		s.Local, s.Remote = netip.MustParseAddrPort(endpoints[0]), netip.MustParseAddrPort(endpoints[1])
		req, err := encode(s)
		if err != nil {
			t.Fatal(err)
		}
		local := s.Local.Addr().As16()
		if string(req[12:28]) != string(local[:]) {
			t.Fatal("wrong IPv6/mapped encoding")
		}
		s.Local = netip.MustParseAddrPort("[fe80::1%8]:1234")
		if _, err := encode(s); err == nil {
			t.Fatal("mismatched scope accepted")
		}
	}
}
