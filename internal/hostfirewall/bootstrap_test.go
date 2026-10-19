package hostfirewall

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEssentialBootstrapScopeShape(t *testing.T) {
	for _, r := range []string{guardRules("test"), profileRules("test", "both")} {
		if strings.Contains(r, "udp sport 68 udp dport 67 accept") || strings.Contains(r, "udp sport 547 udp dport 546 accept") {
			t.Fatal("unapproved DHCP bypass", r)
		}
	}
	for _, r := range []string{guardRules("test", policy.BootstrapInterface{Name: "approved0", IPv4: true, IPv6: true}), profileRules("test", "both", policy.BootstrapInterface{Name: "approved0", IPv4: true, IPv6: true})} {
		if !strings.Contains(r, `iifname "approved0"`) || !strings.Contains(r, `oifname "approved0"`) {
			t.Fatal("missing interface boundary")
		}
		if strings.Contains(r, "iifname \"lo\"") {
			t.Fatal("universal loopback")
		}
	}
	if strings.Contains(guardRules("test", policy.BootstrapInterface{Name: "x\"; bad", IPv4: true}), "bad") {
		t.Fatal("interface injection")
	}
}
func TestEssentialDHCPNativeServer(t *testing.T) {
	if os.Getenv("ESSENTIAL_DHCP_SERVER") == "" {
		t.Skip("helper only")
	}
	for _, item := range []struct{ network, address string }{{"udp4", "0.0.0.0:67"}} {
		c, err := net.ListenPacket(item.network, item.address)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		go func(c net.PacketConn) {
			for {
				b := make([]byte, 256)
				n, a, e := c.ReadFrom(b)
				if e != nil {
					return
				}
				c.WriteTo(b[:n], a)
			}
		}(c)
	}
	// Listen on multicast group as a separate socket to exercise DHCPv6 discovery.
	group := &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547}
	iface, _ := net.InterfaceByName("fgpeer")
	mc, err := net.ListenMulticastUDP("udp6", iface, group)
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()
	go func() {
		for {
			b := make([]byte, 256)
			n, a, e := mc.ReadFromUDP(b)
			if e != nil {
				return
			}
			mc.WriteToUDP(b[:n], a)
		}
	}()
	os.WriteFile(os.Getenv("ESSENTIAL_DHCP_READY"), []byte("ready"), 0600)
	time.Sleep(30 * time.Second)
}
func TestEssentialDHCPBootstrapKernel(t *testing.T) {
	if os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == "" || os.Getenv("FLOWGATE_ESSENTIAL_PRIVATE_NETNS") == identity.NetNS() {
		t.Skip("explicit disposable namespace required")
	}
	run := func(name string, args ...string) {
		t.Helper()
		b, e := exec.Command(name, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %s %v", name, args, b, e)
		}
	}
	peer := exec.Command("unshare", "-n", "sleep", "30")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	pid := fmt.Sprint(peer.Process.Pid)
	time.Sleep(100 * time.Millisecond)
	run("ip", "link", "add", "fgclient", "type", "veth", "peer", "name", "fgpeer")
	defer exec.Command("ip", "link", "del", "fgclient").Run()
	run("ip", "link", "set", "fgpeer", "netns", pid)
	run("ip", "link", "set", "fgclient", "up")
	run("ip", "addr", "add", "192.0.2.1/24", "dev", "fgclient")
	run("ip", "-6", "addr", "add", "fe80::1/64", "dev", "fgclient", "nodad")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "lo", "up")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "fgpeer", "up")
	run("nsenter", "-t", pid, "-n", "ip", "addr", "add", "192.0.2.2/24", "dev", "fgpeer")
	run("nsenter", "-t", pid, "-n", "ip", "-6", "addr", "add", "fe80::2/64", "dev", "fgpeer", "nodad")
	path, _ := os.Executable()
	ready := filepath.Join(t.TempDir(), "ready")
	server := exec.Command("nsenter", "-t", pid, "-n", path, "-test.run=^TestEssentialDHCPNativeServer$")
	server.Env = append(os.Environ(), "ESSENTIAL_DHCP_SERVER=1", "ESSENTIAL_DHCP_READY="+ready)
	logfile, err := os.Create(filepath.Join(t.TempDir(), "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logfile.Close()
	server.Stdout = logfile
	server.Stderr = logfile
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	until := time.Now().Add(3 * time.Second)
	for {
		if _, e := os.Stat(ready); e == nil {
			break
		}
		if time.Now().After(until) {
			b, _ := os.ReadFile(logfile.Name())
			t.Fatalf("server startup %s", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	nftScript := func(s string) {
		t.Helper()
		c := exec.Command("nft", "-f", "-")
		c.Stdin = strings.NewReader(s)
		b, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("nft %v %s", e, b)
		}
	}
	lo, err := net.ListenPacket("udp4", "127.0.0.1:67")
	if err != nil {
		t.Fatal(err)
	}
	defer lo.Close()
	var unrelated atomic.Int32
	go func() {
		for {
			b := make([]byte, 64)
			n, a, e := lo.ReadFrom(b)
			if e != nil {
				return
			}
			unrelated.Add(1)
			lo.WriteTo(b[:n], a)
		}
	}()
	for _, mode := range []string{"guard", "active"} {
		r := guardRules("test", policy.BootstrapInterface{Name: "fgclient", IPv4: true, IPv6: true})
		table := GuardTable
		if mode == "active" {
			table = Table
			r = profileRules("test", "both", policy.BootstrapInterface{Name: "fgclient", IPv4: true, IPv6: true})
		}
		nftScript(r)
		for _, q := range []struct{ proto, local, remote string }{{"udp4", "192.0.2.1:68", "192.0.2.2:67"}, {"udp4", "192.0.2.1:68", "192.0.2.255:67"}, {"udp6", "[fe80::1%fgclient]:546", "[fe80::2%fgclient]:547"}, {"udp6", "[fe80::1%fgclient]:546", "[ff02::1:2%fgclient]:547"}} {
			l, _ := net.ResolveUDPAddr(q.proto, q.local)
			d, _ := net.ResolveUDPAddr(q.proto, q.remote)
			c, e := net.ListenUDP(q.proto, l)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := c.SyscallConn()
			raw.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1) })
			c.SetDeadline(time.Now().Add(1200 * time.Millisecond))
			if _, e = c.WriteToUDP([]byte("dedicated DHCP client probe"), d); e == nil {
				b := make([]byte, 128)
				_, _, e = c.ReadFromUDP(b)
			}
			c.Close()
			if e != nil {
				t.Fatalf("%s %s %s: %v", mode, q.proto, q.remote, e)
			}
		}
		// An unapproved interface must not inherit the protocol bypass.
		c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 68})
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(150 * time.Millisecond))
		c.WriteToUDP([]byte("negative"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 67})
		b := make([]byte, 16)
		_, _, e = c.ReadFromUDP(b)
		c.Close()
		if e == nil || unrelated.Load() != 0 {
			t.Fatal("unapproved interface allowed")
		}
		nftScript("delete table inet " + table + "\n")
	}
	t.Log("PASS interface-scoped DHCPv4 unicast+broadcast and DHCPv6 link-local+multicast request/reply under boot guard and active hooks; no host lease changes")
}
