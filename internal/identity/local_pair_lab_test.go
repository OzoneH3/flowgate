package identity

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func startLocalPeerFixture(t *testing.T, fixture string, result any) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), fixture)
	build := exec.Command("cc", "-Wall", "-Wextra", "-O2", "-pthread", "../../fixtures/ownership/"+fixture+".c", "-o", bin)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building fixture: %v: %s", err, out)
	}
	cmd := exec.Command(bin)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		if fixture == "leader-exit" {
			cmd.Process.Kill()
		}
		cmd.Wait()
	})
	if err := json.NewDecoder(out).Decode(result); err != nil {
		t.Fatal(err)
	}
}

func TestLocalPeerActivityHolderAgreement(t *testing.T) {
	if parent := os.Getenv("FLOWGATE_PARENT_NETNS"); parent == "" || parent == NetNS() {
		t.Skip("private lab namespace required")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("C compiler unavailable")
	}
	var worker struct {
		PID, TID int
		Ports    [4]uint16
	}
	startLocalPeerFixture(t, "leader-exit", &worker)
	deadline := time.Now().Add(5 * time.Second)
	for !activityLeaderExited(fmt.Sprintf("/proc/%d", worker.PID)) {
		if time.Now().After(deadline) {
			t.Fatal("fixture leader did not exit")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, name := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(name, func(t *testing.T) {
			host := "127.0.0.1"
			if name[3] == '6' {
				host = "::1"
			}
			peer := compareLocalPeerWithActivity(t, name[:3], host, worker.Ports[i], []int{worker.TID})
			if peer.State != "verified" || peer.Owner == nil || peer.Owner.PID != worker.TID || peer.Owner.Start == "" {
				t.Errorf("expected surviving worker TID %d, got state=%s owner=%+v (%s)", worker.TID, peer.State, peer.Owner, peer.Reason)
			}
		})
	}
	t.Run("shared", func(t *testing.T) {
		var fixture struct {
			PID, Child int
			Port       uint16
		}
		startLocalPeerFixture(t, "shared", &fixture)
		peer := compareLocalPeerWithActivity(t, "udp", "127.0.0.1", fixture.Port, []int{fixture.PID, fixture.Child})
		if peer.State != "unknown" || peer.Owner != nil || !strings.Contains(peer.Reason, "2 processes share the socket") {
			t.Fatalf("shared holder set must stay ambiguous: %+v", peer)
		}
	})
}

func compareLocalPeerWithActivity(t *testing.T, protocol, host string, port uint16, want []int) *LocalPeer {
	t.Helper()
	addr := netip.MustParseAddr(host)
	flow := Flow{Protocol: protocol, Direction: "outgoing", Local: netip.AddrPortFrom(addr, 33333),
		Remote: netip.AddrPortFrom(addr, port), NetNS: NetNS()}
	peer := ResolveLocalPeer(flow)
	if peer == nil || peer.Socket == nil || peer.Socket.Inode == 0 || peer.Socket.Cookie == "" {
		t.Fatalf("Local Peer did not identify a socket generation: %+v", peer)
	}
	snapshot := CollectConnectionSample(port, nil).Activity
	var holders []int
	for _, row := range snapshot.Rows {
		if s := row.Socket; s.Inode == peer.Socket.Inode && s.Cookie == peer.Socket.Cookie && s.NetNS == peer.Socket.NetNS {
			for _, id := range row.Owners {
				holders = append(holders, snapshot.Processes[id].PID)
			}
		}
	}
	slices.Sort(holders)
	slices.Sort(want)
	t.Logf("inode=%d cookie=%s Activity=%v Local Peer=%s (%s)", peer.Socket.Inode, peer.Socket.Cookie, holders, peer.State, peer.Reason)
	if !slices.Equal(holders, want) {
		t.Fatalf("Activity holders %v, want %v", holders, want)
	}
	return peer
}
