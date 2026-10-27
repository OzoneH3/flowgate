package identity

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExactSocketEncoding(t *testing.T) {
	s := Socket{Family: unix.AF_INET, Protocol: "udp", Local: netip.MustParseAddrPort("127.0.0.1:1234"), Remote: netip.MustParseAddrPort("127.0.0.2:5678"), Cookie: "0123456789abcdef", Inode: 12, UID: 42}
	r, e := exactSocketRequest(s)
	if e != nil {
		t.Fatal(e)
	}
	if binary.BigEndian.Uint16(r[8:10]) != 5678 || binary.BigEndian.Uint16(r[10:12]) != 1234 || r[15] != 2 || r[31] != 1 {
		t.Fatalf("UDP request not reversed: %x", r)
	}
	b := make([]byte, 72)
	b[0] = s.Family
	copy(b[4:8], []byte{4, 210, 22, 46})
	copy(b[8:12], []byte{127, 0, 0, 1})
	copy(b[24:28], []byte{127, 0, 0, 2})
	copy(b[44:52], r[48:56])
	binary.NativeEndian.PutUint32(b[64:68], 42)
	binary.NativeEndian.PutUint32(b[68:72], 12)
	if ok, e := exactSocketReply(s, b); !ok || e != nil {
		t.Fatalf("match %v %v", ok, e)
	}
	for _, offset := range []int{4, 8, 24, 40, 44, 64, 68} {
		b[offset] ^= 1
		if ok, _ := exactSocketReply(s, b); ok {
			t.Fatalf("accepted mismatch offset %d", offset)
		}
		b[offset] ^= 1
	}
	if _, e := exactSocketReply(s, b[:71]); e == nil {
		t.Fatal("short response accepted")
	}
	s.Cookie = "ffffffffffffffff"
	if _, e := exactSocketRequest(s); e == nil {
		t.Fatal("wildcard cookie accepted")
	}
}

// This gate runs ONLY in the disposable guest, never on the host.
func TestExactSocketGuest(t *testing.T) {
	if os.Getenv("FLOWGATE_EXACT_GUEST") != "1" {
		t.Skip("isolated guest only")
	}
	find := func(proto string, local, remote net.Addr) Socket {
		t.Helper()
		rows, e := SocketsLimited(4096)
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range rows {
			if s.Protocol == proto && s.Local.String() == local.String() && (remote == nil || s.Remote.String() == remote.String()) {
				return s
			}
		}
		t.Fatalf("missing %s %s %v", proto, local, remote)
		return Socket{}
	}
	check := func(s Socket, want bool) {
		t.Helper()
		ok, e := SocketExists(s)
		if e != nil || ok != want {
			t.Fatalf("exists %+v = %v %v want %v", s, ok, e, want)
		}
	}
	for _, family := range []string{"4", "6"} {
		host := "127.0.0.1"
		if family == "6" {
			host = "::1"
		}
		t.Run("tcp"+family, func(t *testing.T) {
			l, e := net.Listen("tcp"+family, net.JoinHostPort(host, "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			ls := find("tcp", l.Addr(), nil)
			check(ls, true)
			c, e := net.Dial("tcp"+family, l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			a, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			s := find("tcp", c.LocalAddr(), c.RemoteAddr())
			check(s, true)
			wrong := s
			wrong.Cookie = "0000000000000000"
			check(wrong, false)
			wrong = s
			wrong.UID++
			check(wrong, false)
			c.Close()
			a.Close()
			check(s, false)
			rows, e := SocketsLimited(4096)
			if e != nil {
				t.Fatal(e)
			}
			tw := false
			for _, r := range rows {
				if r.Protocol == "tcp" && r.Local == s.Local && r.Remote == s.Remote && r.State == 6 {
					tw = true
					check(s, false)
				}
			}
			t.Logf("closed TCP same-tuple TIME_WAIT observed=%v", tw)
			l.Close()
			check(ls, false)
		})
		t.Run("udp"+family, func(t *testing.T) {
			u, e := net.ListenPacket("udp"+family, net.JoinHostPort(host, "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			check(find("udp", u.LocalAddr(), nil), true)
			c, e := net.Dial("udp"+family, u.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			s := find("udp", c.LocalAddr(), c.RemoteAddr())
			check(s, true)
			c.Close()
			check(s, false)
		})
	}
	// 128 generation queries with unrelated socket population >1024.
	var sockets []net.PacketConn
	defer func() {
		for _, s := range sockets {
			s.Close()
		}
	}()
	for i := 0; i < 1300; i++ {
		s, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		sockets = append(sockets, s)
	}
	rows, e := SocketsLimited(4096)
	if e != nil {
		t.Fatal(e)
	}
	var sample []Socket
	for _, s := range rows {
		if s.Protocol == "udp" && strings.HasPrefix(s.Local.String(), "127.0.0.1:") {
			sample = append(sample, s)
			if len(sample) == 128 {
				break
			}
		}
	}
	if len(sample) != 128 {
		t.Fatal("insufficient query sample")
	}
	exactRows, err := SocketsLimited(len(rows))
	if err != nil || len(exactRows) != len(rows) {
		t.Fatalf("exact capacity: %d/%d %v", len(exactRows), len(rows), err)
	}
	if _, err := SocketsLimited(len(rows) - 1); err == nil {
		t.Fatal("capacity+1 accepted")
	}

	start := time.Now()
	for _, s := range sample {
		check(s, true)
	}
	t.Logf("128 lookups, population=%d, elapsed=%s", len(rows), time.Since(start))
	if _, e := os.Stat("/work/m1/probe"); e == nil {
		worker := exec.Command("/work/m1/probe", "serve-sockets")
		in, e := worker.StdinPipe()
		if e != nil {
			t.Fatal(e)
		}
		out, e := worker.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = worker.Start(); e != nil {
			t.Fatal(e)
		}
		defer worker.Process.Kill()
		reader := bufio.NewReader(out)
		start = time.Now()
		for _, s := range sample {
			s.Counters = nil
			s.V6Only = nil
			raw, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if len(raw)*2+8 >= 1024 {
				t.Fatalf("descriptor too large: %d", len(raw))
			}
			fmt.Fprintf(in, "exists %s\n", hex.EncodeToString(raw))
			answer, e := reader.ReadString('\n')
			if e != nil || answer != "true\n" {
				t.Fatalf("worker: %q %v", answer, e)
			}
			ack, e := reader.ReadString('\n')
			if e != nil || ack != "\x1eOK\n" {
				t.Fatalf("ack: %q %v", ack, e)
			}
		}
		t.Logf("128 serial worker roundtrips, population=%d, elapsed=%s", len(rows), time.Since(start))
		in.Close()
		if e := worker.Wait(); e != nil {
			t.Fatal(e)
		}
	}

}
