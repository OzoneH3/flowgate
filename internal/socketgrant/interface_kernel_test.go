//go:build socketprototype

package socketgrant

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Two real veth paths with peer UDP echoes: retiring A must never interrupt B.
// Explicit fixture grants isolate kernel routing/lifecycle from attribution.
func TestInterfaceRetirementKernelReceiver(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("FLOWGATE_PARENT_NETNS") == "" {
		t.Skip("private root fixture required")
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	if ns == os.Getenv("FLOWGATE_PARENT_NETNS") {
		t.Fatal("not isolated")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v %s", name, args, err, out)
		}
	}
	run("ip", "netns", "add", "fgpeer")
	defer exec.Command("ip", "netns", "del", "fgpeer").Run()
	for i := 1; i <= 2; i++ {
		local, peer := fmt.Sprintf("fgl%d", i), fmt.Sprintf("fgp%d", i)
		run("ip", "link", "add", local, "type", "veth", "peer", "name", peer)
		defer exec.Command("ip", "link", "del", local).Run()
		run("ip", "link", "set", peer, "netns", "fgpeer")
		run("ip", "addr", "add", fmt.Sprintf("198.18.%d.1/24", i), "dev", local)
		run("ip", "link", "set", local, "up")
		run("ip", "netns", "exec", "fgpeer", "ip", "addr", "add", fmt.Sprintf("198.18.%d.2/24", i), "dev", peer)
		run("ip", "netns", "exec", "fgpeer", "ip", "link", "set", peer, "up")
	}
	echo := exec.Command("ip", "netns", "exec", "fgpeer", "python3", "-u", "-c", `import socket,select
s=[]
for i in (1,2):
 x=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);x.bind(('198.18.%d.2'%i,45678));s.append(x)
print('ready',flush=True)
while True:
 for x in select.select(s,[],[])[0]:
  b,a=x.recvfrom(4096);x.sendto(b,a)
`)
	pipe, err := echo.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	echo.Stderr = os.Stderr
	if err = echo.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { echo.Process.Kill(); echo.Wait() }()
	ready := make([]byte, 6)
	if _, err = pipe.Read(ready); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString("add table inet fg_retire\nadd chain inet fg_retire socket_output\nadd chain inet fg_retire output { type filter hook output priority 10; policy accept; }\nadd rule inet fg_retire output ip daddr 198.18.0.0/16 meta l4proto udp jump socket_output\nadd rule inet fg_retire output ip daddr 198.18.0.0/16 meta l4proto udp drop\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	defer exec.Command("nft", "delete", "table", "inet", "fg_retire").Run()
	k, err := OpenRoutedKernel("fg_retire", "socket_output")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	var keys [2]Key
	var sockets [2]*net.UDPConn
	for i := range keys {
		link, err := net.InterfaceByName(fmt.Sprintf("fgl%d", i+1))
		if err != nil {
			t.Fatal(err)
		}
		if err = k.AddInterface(uint32(link.Index)); err != nil {
			t.Fatal(err)
		}
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(198, 18, byte(i+1), 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		sockets[i] = s
		raw, _ := s.SyscallConn()
		var cookie uint64
		raw.Control(func(fd uintptr) { cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE) })
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = Key{Cookie: cookie, Interface: uint32(link.Index), Source: [4]byte{198, 18, byte(i + 1), 1}, Destination: [4]byte{198, 18, byte(i + 1), 2}}
		binary.BigEndian.PutUint16(keys[i].SourcePort[:], uint16(s.LocalAddr().(*net.UDPAddr).Port))
		binary.BigEndian.PutUint16(keys[i].DestinationPort[:], 45678)
	}
	store, err := NewConnection(RetainForSession(k))
	if err != nil {
		t.Fatal(err)
	}
	publish := func(i int) {
		t.Helper()
		if ok, err := store.Publish(store.Begin(), keys[i], 0); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	send := func(i int, want bool, label string) {
		t.Helper()
		s := sockets[i]
		s.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := s.WriteToUDP([]byte(label), &net.UDPAddr{IP: net.IPv4(198, 18, byte(i+1), 2), Port: 45678})
		if err != nil && !errors.Is(err, unix.EPERM) {
			t.Fatal(err)
		}
		b := make([]byte, 128)
		n, _, readerr := s.ReadFromUDP(b)
		if want && (readerr != nil || string(b[:n]) != label) {
			t.Fatal(label, readerr)
		}
		if !want && readerr == nil {
			t.Fatal("unauthorized delivery", label)
		}
	}
	send(0, false, "initial-deny")
	publish(0)
	publish(1)
	send(0, true, "a-live")
	send(1, true, "b-live")
	old := keys[0].Interface
	if err = k.RetireInterface(old); err != nil {
		t.Fatal(err)
	}
	if err = k.Epoch(store.Begin().generation); err != nil {
		t.Fatal(err)
	}
	send(0, false, "kernel-barrier-with-stale-grant-after-epoch-write")
	send(1, true, "b-during-retirement")
	if err = store.RetireInterface(old); err != nil {
		t.Fatal(err)
	}
	// Even a stale map entry matching the current global epoch cannot use A's
	// retired instance; future epoch changes must leave it zero too.
	stale := Value{Generation: store.Begin().generation}
	if err = k.Epoch(stale.Generation); err != nil {
		t.Fatal(err)
	}
	send(0, false, "retired-with-link-present")
	run("ip", "link", "del", "fgl1")
	for n := 0; n < 100; n++ {
		send(1, true, fmt.Sprintf("survivor-%d", n))
	}
	hits, err := k.Stats(keys[1])
	if err != nil || hits.Packets != 102 {
		t.Fatal("survivor hits", hits, err)
	}
	// Force the old numeric index onto a new device, a different instance.
	run("ip", "link", "add", "name", "fgl1", "index", fmt.Sprint(old), "type", "veth", "peer", "name", "replacement")
	run("ip", "link", "set", "replacement", "netns", "fgpeer")
	run("ip", "addr", "add", "198.18.1.1/24", "dev", "fgl1")
	run("ip", "link", "set", "fgl1", "up")
	run("ip", "netns", "exec", "fgpeer", "ip", "addr", "add", "198.18.1.2/24", "dev", "replacement")
	run("ip", "netns", "exec", "fgpeer", "ip", "link", "set", "replacement", "up")
	if err = k.AddInterface(old); err == nil {
		t.Fatal("reused index revived in old session")
	}
	if ok, err := store.Publish(store.Begin(), keys[0], 0); ok || err != nil {
		t.Fatal("old index publication", ok, err)
	}
	if err = store.Revoke(); err != nil {
		t.Fatal(err)
	}
	publish(1)
	send(0, false, "reuse-after-policy-epoch")
	send(1, true, "b-after-policy-epoch")
	// Off/on owns entirely new programs/maps and may verify the new instance.
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = k.Close(); err != nil {
		t.Fatal(err)
	}
	k, err = OpenRoutedKernel("fg_retire", "socket_output")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	for _, key := range keys {
		if err = k.AddInterface(key.Interface); err != nil {
			t.Fatal(err)
		}
	}
	store, err = NewConnection(RetainForSession(k))
	if err != nil {
		t.Fatal(err)
	}
	send(0, false, "fresh-session-no-inherited-grant")
	publish(0)
	publish(1)
	send(0, true, "fresh-session-reverified-a")
	send(1, true, "fresh-session-reverified-b")
	t.Log("PASS two-path UDP delivery, survivor 102 exact fast hits, retired index reuse denied, epoch revoke, fresh session re-verification")
}
