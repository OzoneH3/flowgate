package socketcontrol

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"flowgate/internal/identity"
	"golang.org/x/sys/unix"
)

// This fixture only runs inside scripts/lab.sh. It exercises the actual package,
// not a mock transport. Two connections use the same test process; independent
// native-executable and descriptor-transfer proofs are recorded separately.
func TestAbortKernel(t *testing.T) {
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	current, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil || parent == "" || parent == current {
		t.Skip("requires scripts/lab.sh private network namespace")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, side := range []string{"connect", "accept"} {
			t.Run(network+"/"+side, func(t *testing.T) {
				client, server, ended := pair(t, network)
				other, _, _ := pair(t, network)
				roundtrip(t, client)
				roundtrip(t, other)
				target := client
				if side == "accept" {
					target = server
				}
				sockets, err := identity.Sockets()
				if err != nil {
					t.Fatal(err)
				}
				var expected identity.Socket
				for _, s := range sockets {
					if s.Local == endpoint(t, target.LocalAddr()) && s.Remote == endpoint(t, target.RemoteAddr()) && s.State == 1 {
						if expected.Inode != 0 {
							t.Fatal("ambiguous target")
						}
						expected = s
					}
				}
				if expected.Inode == 0 {
					t.Fatal("missing target")
				}
				wrong := expected
				cookie, _ := hex.DecodeString(wrong.Cookie)
				cookie[0] ^= 1
				wrong.Cookie = hex.EncodeToString(cookie)
				r, err := Abort(context.Background(), wrong)
				if r.Status != NotFound || r.Attempted || !errors.Is(err, unix.ENOENT) {
					t.Fatal(r, err)
				}
				roundtrip(t, client)
				r, err = Abort(context.Background(), expected)
				if err != nil || r.Status != Acknowledged || !r.Attempted {
					t.Fatal(r, err)
				}
				client.SetDeadline(time.Now().Add(time.Second))
				_, writeErr := client.Write([]byte("next"))
				if writeErr == nil {
					_, writeErr = client.Read(make([]byte, 4))
				}
				if writeErr == nil {
					t.Fatal("aborted connection exchanged new data")
				}
				if e, ok := writeErr.(net.Error); ok && e.Timeout() {
					t.Fatalf("timeout does not prove abort: %v", e)
				}
				if side == "connect" && !errors.Is(writeErr, unix.ECONNABORTED) && !errors.Is(writeErr, unix.EPIPE) {
					t.Fatal(writeErr)
				}
				select {
				case e := <-ended:
					if side == "accept" && !errors.Is(e, unix.ECONNABORTED) {
						t.Fatalf("local accepted socket: %v", e)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("peer exchange did not end")
				}
				for i := 0; i < 10; i++ {
					roundtrip(t, other)
				}
				r, err = Abort(context.Background(), expected)
				if r.Status != NotFound || r.Attempted || !errors.Is(err, unix.ENOENT) {
					t.Fatal("replay", r, err)
				}
			})
		}
	}
}

func endpoint(t *testing.T, a net.Addr) netip.AddrPort {
	t.Helper()
	p, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pair(t *testing.T, network string) (net.Conn, net.Conn, <-chan error) {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	client, err := net.DialTimeout(network, l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	ended := make(chan error, 1)
	go func() {
		b := make([]byte, 4)
		for {
			if _, err := io.ReadFull(server, b); err != nil {
				ended <- err
				return
			}
			if _, err := server.Write(b); err != nil {
				ended <- err
				return
			}
		}
	}()
	return client, server, ended
}

func roundtrip(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "data" {
		t.Fatalf("receiver: %q %v", b, err)
	}
}
