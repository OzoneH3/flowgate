package daemon_test

// This focused kernel check runs only inside the explicitly marked disposable
// namespace. It checks the new DNS policy path, not the settled host lifecycle.
import (
	"context"
	"encoding/binary"
	"flowgate/internal/daemon"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/queue"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var dnsQuery = []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1}

func dnsExchange(proto, address string, data []byte) ([]byte, error) {
	c, err := net.DialTimeout(proto, address, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if proto == "tcp" {
		h := make([]byte, 2)
		binary.BigEndian.PutUint16(h, uint16(len(data)))
		if _, err = c.Write(append(h, data...)); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(c, h); err != nil {
			return nil, err
		}
		b := make([]byte, binary.BigEndian.Uint16(h))
		_, err = io.ReadFull(c, b)
		return b, err
	}
	if _, err = c.Write(data); err != nil {
		return nil, err
	}
	b := make([]byte, 512)
	n, err := c.Read(b)
	return b[:n], err
}
func dnsListen(t *testing.T, addr string, answer func(string, []byte) []byte) {
	t.Helper()
	u, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		for {
			b := make([]byte, 512)
			n, a, e := u.ReadFrom(b)
			if e != nil {
				return
			}
			out := answer("udp", b[:n])
			if out != nil {
				u.WriteTo(out, a)
			}
		}
	}()
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				h := make([]byte, 2)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(h))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				out := answer("tcp", b)
				if out != nil {
					binary.BigEndian.PutUint16(h, uint16(len(out)))
					c.Write(append(h, out...))
				}
			}()
		}
	}()
}
func TestEssentialDNSNativeHelper(t *testing.T) {
	mode := os.Getenv("ESSENTIAL_DNS_HELPER")
	if mode == "" {
		t.Skip("helper only")
	}
	if mode == "server" {
		dnsListen(t, "127.0.0.54:53", func(_ string, b []byte) []byte {
			b[2] = 0x81
			b[3] = 0x80
			b[7] = 1
			return append(b, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 203, 0, 113, 7)
		})
		os.WriteFile(os.Getenv("ESSENTIAL_DNS_READY"), []byte("ready"), 0600)
		time.Sleep(30 * time.Second)
		return
	}
	b, e := dnsExchange(os.Getenv("ESSENTIAL_DNS_PROTO"), os.Getenv("ESSENTIAL_DNS_ADDR"), dnsQuery)
	if mode == "deny" {
		if e == nil {
			t.Fatal("unexpected DNS delivery", b)
		}
		return
	}
	if e != nil || len(b) < 4 || b[2] != 0x81 {
		t.Fatal("DNS response", b, e)
	}
}
func TestEssentialDNSKernelReceivers(t *testing.T) {
	if os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == "" || os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == identity.NetNS() {
		t.Skip("explicit disposable network namespace required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	client, server := filepath.Join(dir, "dns-client"), filepath.Join(dir, "dns-upstream")
	for _, path := range []string{client, server} {
		if err = os.WriteFile(path, contents, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ready := filepath.Join(dir, "ready")
	child := exec.Command(server, "-test.run=^TestEssentialDNSNativeHelper$")
	child.Env = append(os.Environ(), "ESSENTIAL_DNS_HELPER=server", "ESSENTIAL_DNS_READY="+ready)
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, e := os.Stat(ready); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var delivered atomic.Int32
	dnsListen(t, "127.0.0.53:53", func(proto string, b []byte) []byte {
		out, e := dnsExchange(proto, "127.0.0.54:53", b)
		if e != nil {
			return nil
		}
		delivered.Add(1)
		return out
	})
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	env := essential.Default()
	env.Inspect = func(pid int) (identity.Process, error) {
		q, e := identity.Inspect(pid)
		q.Cgroup = "0::/system.slice/systemd-resolved.service"
		return q, e
	}
	env.Sockets = func() ([]identity.Socket, error) {
		all, e := identity.Sockets()
		out := []identity.Socket{}
		for _, s := range all {
			if s.Local.Addr().String() == "127.0.0.53" {
				out = append(out, s)
			}
		}
		return out, e
	}
	env.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			if args[1] == "systemd-resolved.service" {
				return []byte("ActiveState=active\nMainPID=" + strconv.Itoa(p.PID)), nil
			}
			return []byte("ActiveState=inactive\nMainPID=0"), nil
		case "resolvectl":
			return []byte(`[{"ifname":"lo","ifindex":1,"servers":[{"addressString":"127.0.0.54","port":53}]}]`), nil
		}
		return nil, nil
	}
	e := daemon.New(time.Second)
	defer e.CloseProcessTargets()
	e.ConfigureEssential(ctx, env)
	e.SaveRules = func([]policy.Rule) error { return nil }
	preview, err := e.PreviewEssential(e.Generation, "apply", essential.Options{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Rules) != 6 {
		t.Fatalf("expected 6 exact DNS rules, got %d %+v", len(preview.Rules), preview.Components)
	}
	if _, _, err = e.ApplyEssential(e.Generation, preview.Token, "apply", essential.Options{}, 0); err != nil {
		t.Fatal(err)
	}
	// This fixture tests exact DNS presets, so explicitly opt localhost into
	// filtering rather than relying on the general application default.
	rules := e.Rules(0, true)
	rules = append(rules, policy.Rule{Schema: 4, ID: "fixture-localhost-block", Action: "block", Filter: policy.Filter{AllPrograms: true, AllUIDs: true, NetworkZone: "local", Direction: "outgoing", Protocol: "*", RemoteAddress: "127.0.0.54"}})
	if err = e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	queueReady := make(chan error, 1)
	go func() {
		err := queue.RunConfigured(ctx, e, "outgoing", 101, false, func() error { queueReady <- nil; return nil })
		if err != nil {
			select {
			case queueReady <- err:
			default:
			}
		}
	}()
	select {
	case err = <-queueReady:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queue timeout")
	}
	nft := func(script string) error {
		c := exec.Command("nft", "-f", "-")
		c.Stdin = strings.NewReader(script)
		b, e := c.CombinedOutput()
		if e != nil {
			return fmt.Errorf("%s: %w", b, e)
		}
		return nil
	}
	if err = nft("add table inet essential_dns_test\nadd chain inet essential_dns_test output { type filter hook output priority 10; policy accept; }\nadd rule inet essential_dns_test output udp dport 53 queue num 101\nadd rule inet essential_dns_test output tcp dport 53 tcp flags & (syn | ack) == syn queue num 101\n"); err != nil {
		t.Fatal(err)
	}
	defer nft("delete table inet essential_dns_test\n")
	for _, proto := range []string{"udp", "tcp"} {
		for _, direct := range []bool{false, true} {
			mode, address := "allow", "127.0.0.53:53"
			if direct {
				mode, address = "deny", "127.0.0.54:53"
			}
			c := exec.Command(client, "-test.run=^TestEssentialDNSNativeHelper$")
			c.Env = append(os.Environ(), "ESSENTIAL_DNS_HELPER="+mode, "ESSENTIAL_DNS_PROTO="+proto, "ESSENTIAL_DNS_ADDR="+address)
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s: %v %s events=%+v", proto, mode, err, out, e.List(0, true))
			}
		}
	}
	if delivered.Load() != 2 {
		t.Fatal("receiver count", delivered.Load())
	}
	t.Log("PASS real native UDP+TCP client→verified stub→configured upstream DNS responses; unrelated direct DNS attempts blocked; exact executable scopes")
}
