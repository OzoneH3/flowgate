//go:build socketprototype

package socketgrant

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"testing"
	"time"
)

type erroringRoute struct {
	*RoutedKernel
	fail bool
}

func (k *erroringRoute) Epoch(n uint64) error {
	if k.fail {
		return errors.New("injected epoch failure")
	}
	return k.RoutedKernel.Epoch(n)
}
func (k *erroringRoute) Delete(key Key) error {
	if k.fail {
		return errors.New("injected delete failure")
	}
	return k.RoutedKernel.Delete(key)
}
func TestConnectionKernelReceiver(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("FLOWGATE_PARENT_NETNS") == "" {
		t.Skip("private root fixture required")
	}
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns == os.Getenv("FLOWGATE_PARENT_NETNS") {
		t.Fatal("not isolated")
	}
	nft := func(script string) {
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = bytes.NewBufferString(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft: %v %s", err, out)
		}
	}
	nft("add table inet flowgate_connection_receiver\nadd chain inet flowgate_connection_receiver socket_output\nadd chain inet flowgate_connection_receiver output { type filter hook output priority 10; policy accept; }\nadd rule inet flowgate_connection_receiver output ip daddr 127.0.0.1 meta l4proto udp jump socket_output\nadd rule inet flowgate_connection_receiver output ip daddr 127.0.0.1 meta l4proto udp drop\n")
	defer exec.Command("nft", "delete", "table", "inet", "flowgate_connection_receiver").Run()
	kernel, err := OpenRoutedKernel("flowgate_connection_receiver", "socket_output")
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = kernel.AddInterface(uint32(lo.Index)); err != nil {
		t.Fatal(err)
	}
	wrapped := &erroringRoute{RoutedKernel: kernel}
	store, err := NewConnection(RetainForSession(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var setErr error
		err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
		if err != nil {
			return err
		}
		return setErr
	}}
	packet, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	sender, _ := packet.(*net.UDPConn)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	raw, _ := sender.SyscallConn()
	var cookie uint64
	raw.Control(func(fd uintptr) { cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE) })
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Cookie: cookie, Interface: uint32(lo.Index), Source: [4]byte{127, 0, 0, 1}, Destination: [4]byte{127, 0, 0, 1}}
	binary.BigEndian.PutUint16(key.SourcePort[:], uint16(sender.LocalAddr().(*net.UDPAddr).Port))
	binary.BigEndian.PutUint16(key.DestinationPort[:], uint16(receiver.LocalAddr().(*net.UDPAddr).Port))
	checkSendError := func(err error) {
		if err != nil && !errors.Is(err, unix.EPERM) {
			t.Fatal("unexpected send failure", err)
		}
	}
	send := func(want bool, label string) {
		_ = receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, sendErr := sender.WriteToUDP([]byte(label), receiver.LocalAddr().(*net.UDPAddr))
		checkSendError(sendErr)
		buf := make([]byte, 128)
		n, _, readErr := receiver.ReadFromUDP(buf)
		if want && (sendErr != nil || readErr != nil || string(buf[:n]) != label) {
			t.Fatalf("%s delivery failed: %v %v", label, sendErr, readErr)
		}
		if !want && readErr == nil {
			t.Fatalf("%s delivered without authorization", label)
		}
	}
	send(false, "unverified")
	if ok, err := store.Publish(store.Begin(), key, 0); err != nil || !ok {
		t.Fatal(err)
	}
	send(true, "initial")
	secondPacket, err := lc.ListenPacket(context.Background(), "udp4", sender.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	second := secondPacket.(*net.UDPConn)
	defer second.Close()
	secondRaw, err := second.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var secondCookie uint64
	if err = secondRaw.Control(func(fd uintptr) { secondCookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE) }); err != nil {
		t.Fatal(err)
	}
	if secondCookie == 0 || secondCookie == cookie {
		t.Fatal("cookie fixture is not distinct")
	}
	receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = second.WriteToUDP([]byte("other-cookie"), receiver.LocalAddr().(*net.UDPAddr))
	checkSendError(err)
	otherCookieBuf := make([]byte, 64)
	if _, _, err = receiver.ReadFromUDP(otherCookieBuf); err == nil {
		t.Fatal("same tuple different cookie inherited permission")
	}
	send(true, "original-cookie-still-live")

	time.Sleep(350 * time.Millisecond)
	send(true, "no-ownership-expiry")
	if err = store.Revoke(); err != nil {
		t.Fatal(err)
	}
	send(false, "policy-revoked")
	horizon := BootNow() + uint64(150*time.Millisecond)
	if ok, err := store.Publish(store.Begin(), key, horizon); err != nil || !ok {
		t.Fatal(err)
	}
	send(true, "temporary-live")
	time.Sleep(170 * time.Millisecond)
	send(false, "temporary-expired")
	if ok, err := store.Publish(store.Begin(), key, 0); err != nil || !ok {
		t.Fatal(err)
	}
	// Exact destination/port separation while the original tuple remains live.
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = sender.WriteToUDP([]byte("other"), other.LocalAddr().(*net.UDPAddr))
	checkSendError(err)
	buf := make([]byte, 32)
	if _, _, err = other.ReadFromUDP(buf); err == nil {
		t.Fatal("destination permission transferred")
	}
	send(true, "original-still-live")
	// Both map writes fail; only confirmed exact-rule detachment can revoke.
	snapshot := func() []map[string]any {
		raw, err := exec.Command("nft", "-j", "list", "table", "inet", "flowgate_connection_receiver").Output()
		if err != nil {
			t.Fatal(err)
		}
		var data struct{ Nftables []map[string]any }
		if err = json.Unmarshal(raw, &data); err != nil {
			t.Fatal(err)
		}
		var kept []map[string]any
		for _, item := range data.Nftables {
			if _, meta := item["metainfo"]; meta {
				continue
			}
			if rule, ok := item["rule"].(map[string]any); ok && rule["chain"] == "socket_output" {
				continue
			}
			kept = append(kept, item)
		}
		return kept
	}
	beforeDetach := snapshot()
	wrapped.fail = true
	if err = store.Close(); err != nil {
		t.Fatal("emergency revocation failed", err)
	}
	send(false, "emergency-detached")
	if !reflect.DeepEqual(beforeDetach, snapshot()) {
		t.Fatal("emergency detach changed non-accelerator rules")
	}
	rawGate, err := exec.Command("nft", "-j", "list", "chain", "inet", "flowgate_connection_receiver", "socket_output").Output()
	if err != nil {
		t.Fatal(err)
	}
	var listing struct{ Nftables []map[string]any }
	json.Unmarshal(rawGate, &listing)
	for _, item := range listing.Nftables {
		if _, ok := item["rule"]; ok {
			t.Fatal("accelerator rule survived")
		}
	}
	if err = store.Close(); err != nil {
		t.Fatal("repeat close failed", err)
	}

	fmt.Println("CONNECTION_RECEIVER_PASS initial/live-after-250ms/policy/temp-expiry/destination/emergency-detach")
}
