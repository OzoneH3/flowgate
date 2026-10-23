package accounting

import (
	"bufio"
	"flowgate/internal/identity"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Child copies are distinct executables, not two script arguments donated the
// interpreter's identity. This fixture sends only inside its private namespace.
func TestAccountingTrafficChild(t *testing.T) {
	if os.Getenv("FLOWGATE_ACCOUNTING_CHILD") != "1" {
		return
	}
	c, err := net.Dial(os.Getenv("FLOWGATE_ACCOUNTING_NETWORK"), os.Getenv("FLOWGATE_ACCOUNTING_ADDRESS"))
	if err != nil {
		panic(err)
	}
	defer c.Close()
	fmt.Println("ready")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "quit" {
			return
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(make([]byte, 1024)); err != nil {
			panic(err)
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			panic(err)
		}
		fmt.Println("sent")
	}
}
func TestObservedCollectorPrivateNamespace(t *testing.T) {
	if os.Getenv("FLOWGATE_ACCOUNTING_PRIVATE_NETNS") != "1" {
		t.Skip("explicit private-netns fixture only")
	}
	if parent := os.Getenv("FLOWGATE_PARENT_NETNS"); parent == "" || parent == identity.NetNS() {
		t.Fatal("not in lab namespace")
	}
	scratch, err := os.MkdirTemp("../../.workspace/tmp", "usage-real-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratch)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	var programs []string
	for _, label := range []string{"alpha", "beta"} {
		p, _ := filepath.Abs(filepath.Join(scratch, label))
		if err := os.WriteFile(p, contents, 0700); err != nil {
			t.Fatal(err)
		}
		programs = append(programs, p)
	}
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				addr = "[::1]:0"
			}
			var address string
			if strings.HasPrefix(network, "tcp") {
				ln, err := net.Listen(network, addr)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				address = ln.Addr().String()
				go func() {
					for {
						c, err := ln.Accept()
						if err != nil {
							return
						}
						go func() {
							defer c.Close()
							for {
								if _, err := io.ReadFull(c, make([]byte, 1024)); err != nil {
									return
								}
								if _, err := c.Write([]byte{1}); err != nil {
									return
								}
							}
						}()
					}
				}()
			} else {
				pc, err := net.ListenPacket(network, addr)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				address = pc.LocalAddr().String()
				go func() {
					for {
						b := make([]byte, 2048)
						_, peer, err := pc.ReadFrom(b)
						if err != nil {
							return
						}
						pc.WriteTo([]byte{1}, peer)
					}
				}()
			}
			type child struct {
				cmd   *exec.Cmd
				in    io.WriteCloser
				lines *bufio.Scanner
			}
			var children []child
			for _, program := range programs {
				cmd := exec.Command(program, "-test.run=^TestAccountingTrafficChild$")
				cmd.Env = append(os.Environ(), "FLOWGATE_ACCOUNTING_CHILD=1", "FLOWGATE_ACCOUNTING_NETWORK="+network, "FLOWGATE_ACCOUNTING_ADDRESS="+address)
				in, _ := cmd.StdinPipe()
				out, _ := cmd.StdoutPipe()
				cmd.Stderr = os.Stderr
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
				lines := bufio.NewScanner(out)
				if !lines.Scan() || lines.Text() != "ready" {
					t.Fatal("child not ready", lines.Text())
				}
				children = append(children, child{cmd, in, lines})
			}
			ledger := New()
			collector := identity.ActivityCollector{}
			cookies := map[string]identity.UDPCount{}
			since := time.Now()
			sample := int64(0)
			if strings.HasPrefix(network, "udp") {
				// Actual bound sockets/owners and receiver traffic, but injected source
				// counters: this tests integration, NOT BPF collection correctness.
				collector.UDP = func() identity.UDPSnapshot {
					sample++
					return identity.UDPSnapshot{State: "active", NetNS: identity.NetNS(), Machine: true, Generation: "fixture", SampleNS: sample * 1e9, Collected: time.Now(), Rows: cookies}
				}
			}
			collect := func() identity.ActivitySnapshot {
				s := collector.Collect()
				if !s.Complete {
					t.Fatalf("incomplete private census: %s %v", s.Error, s.Issues)
				}
				ledger.Observe(s)
				return s
			}
			s := collect()
			ids := map[string]bool{}
			keys := map[string]bool{}
			for _, r := range s.Rows {
				for _, owner := range r.Owners {
					p := s.Processes[owner]
					for _, c := range children {
						if p.PID == c.cmd.Process.Pid {
							ids[r.ID] = true
							keys[p.Application.Key] = true
							cookies[r.Socket.Cookie] = identity.UDPCount{Since: since}
						}
					}
				}
			}
			if len(ids) != 2 || len(keys) != 2 {
				t.Fatalf("expected two distinct apps/sockets; rows %v keys %v", ids, keys)
			}
			before := collect()
			for _, c := range children {
				fmt.Fprintln(c.in, "send")
				if !c.lines.Scan() || c.lines.Text() != "sent" {
					t.Fatal("send failed")
				}
			}
			for cookie := range cookies {
				cookies[cookie] = identity.UDPCount{Since: since, Uploaded: 1024, Downloaded: 1}
			}
			after := collect()
			expected := map[string]uint64{}
			prior := map[string]uint64{}
			for _, r := range before.Rows {
				prior[r.ID] = r.Traffic.Uploaded
			}
			for _, r := range after.Rows {
				if ids[r.ID] {
					if !r.Traffic.Available {
						t.Fatal("counter unavailable")
					}
					p := after.Processes[r.Owners[0]]
					expected[p.Application.Key] = r.Traffic.Uploaded - prior[r.ID]
				}
			}
			got := ledger.Snapshot(0, true)
			found := 0
			for _, e := range got.Entries {
				if want, ok := expected[e.Application.Key]; ok {
					found++
					if want == 0 || e.Uploaded != strconv.FormatUint(want, 10) {
						t.Fatal("observed-delta conservation", e, want)
					}
				}
			}
			if found != 2 {
				t.Fatal("missing two application totals", got)
			}
			for _, c := range children {
				fmt.Fprintln(c.in, "quit")
				c.in.Close()
				if err := c.cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			collect()
			closed := ledger.Snapshot(0, true)
			for _, e := range closed.Entries {
				if want, ok := expected[e.Application.Key]; ok && e.Uploaded != strconv.FormatUint(want, 10) {
					t.Fatal("closed history changed", e)
				}
			}
			t.Logf("%s: two distinct applications; observed counter deltas retained after exit; UDP uses injected API counters", network)
		})
	}
}
