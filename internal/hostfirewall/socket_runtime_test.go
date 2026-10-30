//go:build socketprototype

package hostfirewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// This fixture uses the real queue, activation, digest audit, link watcher and
// cleanup. Its refusing resolver deliberately grants no application authority.
func TestRoutedProtectionSessionPrivateNamespace(t *testing.T) {
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	if parent == "" || parent == identity.NetNS() || os.Geteuid() != 0 {
		t.Skip("private root network namespace required")
	}
	dir := os.Getenv("FLOWGATE_SOCKET_SESSION_RUN")
	if dir == "" {
		t.Fatal("explicit workspace run directory required")
	}
	if os.Getenv("FLOWGATE_SESSION_CRASH_CHILD") == "1" {
		child := newCrashSession(t, dir)
		if _, err := child.ProtectionStart("", strings.Repeat("e", 32), "both"); err != nil {
			t.Fatal(err)
		}
		waitEvaluation(t, child, "active")
		if child.SocketSessionFailure() != nil {
			t.Fatal(child.SocketSessionFailure())
		}
		// Synthetic grant only: isolate crash/expiry lifecycle from identity.
		sa, err := unix.Getsockname(3)
		if err != nil {
			t.Fatal(err)
		}
		local := sa.(*unix.SockaddrInet4)
		cookie, err := unix.GetsockoptUint64(3, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			t.Fatal(err)
		}
		link, err := net.InterfaceByName("fgsession0")
		if err != nil {
			t.Fatal(err)
		}
		key := socketgrant.Key{Cookie: cookie, Source: local.Addr, Destination: [4]byte{198, 18, 1, 2}, Interface: uint32(link.Index)}
		binary.BigEndian.PutUint16(key.SourcePort[:], uint16(local.Port))
		binary.BigEndian.PutUint16(key.DestinationPort[:], 45678)
		owner := child.socketSession.(*routedSocketSession)
		if err = owner.backend.Epoch(77); err != nil {
			t.Fatal(err)
		}
		deadline := socketgrant.BootNow() + uint64(socketgrant.Window)
		if err = owner.backend.Put(key, socketgrant.Value{Deadline: deadline, Generation: 77}); err != nil {
			t.Fatal(err)
		}
		if err = unix.Sendto(3, []byte("grant"), 0, &unix.SockaddrInet4{Addr: key.Destination, Port: 45678}); err != nil {
			t.Fatal(err)
		}
		hits, err := owner.backend.Stats(key)
		if err != nil || hits.Packets == 0 {
			t.Fatal("grant was not exercised", hits, err)
		}
		proof, _ := json.Marshal(map[string]any{"synthetic": true, "deadline": deadline, "fast_hits": hits.Packets})
		if err := os.WriteFile(filepath.Join(dir, "ready"), proof, 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if err := exec.Command("ip", "link", "add", "fgsession0", "type", "dummy").Run(); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("ip", "link", "del", "fgsession0").Run()
	if err := exec.Command("ip", "address", "add", "198.18.1.1/24", "dev", "fgsession0").Run(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "set", "fgsession0", "up").Run(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := daemon.New(time.Second)
	e.Mode = "daemon-monitor"
	uid := uint32(0)
	e.APIUID = &uid
	e.AdministratorUID = &uid
	zones := identity.NewZoneManagerWithPublisher(e.Zones.Legacy(), e.NetworkZonePublisher())
	e.ZoneSource = zones.Snapshot
	resolver := daemon.SocketSessionResolvers{
		Fresh:    func(identity.Flow) identity.Attribution { return identity.Attribution{} },
		Observed: func(identity.Flow) (identity.Attribution, uint64) { return identity.Attribution{}, 0 },
	}
	m := NewEvaluation(ctx, e, filepath.Join(dir, "state"), filepath.Join(dir, "api", "s"), filepath.Join(dir, "data", "rules.db"))
	if err := m.ConfigureProtection(filepath.Join(dir, "desired.json")); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureSocketSession(RoutedSocketSessionFactory(e, resolver)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if m.Status().ID != "" {
			_, _ = m.ProtectionStop(m.Status().ID)
		}
		m.Close()
	}()
	if _, err := m.ProtectionStart("", strings.Repeat("c", 32), "both"); err != nil {
		t.Fatal(err)
	}
	active := waitEvaluation(t, m, "active")
	record, err := Read(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := tableDigestForFormat(Table, record.DigestFormat)
	if err != nil || digest != record.TableDigest {
		t.Fatal("installed gate outside digest", err)
	}
	listing, err := nft("-j", "list", "table", "inet", Table)
	if err != nil || !strings.Contains(string(listing), "socket_output") || !strings.Contains(string(listing), "flowgate-socket:") {
		t.Fatal("route rules missing", err, string(listing))
	}
	_ = os.WriteFile(filepath.Join(dir, "rules-before.json"), listing, 0600)
	numericBefore, _ := tableListing(Table, record.DigestFormat)
	_ = os.WriteFile(filepath.Join(dir, "numeric-before.json"), numericBefore, 0600)
	if e.SocketAuthorizationFailure() != nil {
		t.Fatal(e.SocketAuthorizationFailure())
	}
	if err = exec.Command("ip", "link", "set", "fgsession0", "name", "fgsession1").Run(); err != nil {
		t.Fatal(err)
	}
	renamed, err := tableDigestForFormat(Table, record.DigestFormat)
	if err != nil || renamed != digest {
		t.Fatal("rename changed numeric digest", err)
	}
	if err = exec.Command("ip", "link", "del", "fgsession1").Run(); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * time.Second)
	for e.SocketAuthorizationFailure() == nil && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.SocketAuthorizationFailure() == nil {
		t.Fatal("installed link deletion did not disable")
	}
	afterListing, _ := nft("-j", "list", "table", "inet", Table)
	_ = os.WriteFile(filepath.Join(dir, "rules-after.json"), afterListing, 0600)
	numericAfter, _ := tableListing(Table, record.DigestFormat)
	_ = os.WriteFile(filepath.Join(dir, "numeric-after.json"), numericAfter, 0600)
	after, err := tableDigestForFormat(Table, record.DigestFormat)
	if err != nil || after != digest {
		t.Fatal("disable mutated audited rules", err)
	}
	if err = exec.Command("ip", "link", "add", "fgsession0", "type", "dummy").Run(); err != nil {
		t.Fatal(err)
	}
	replaced, err := tableDigestForFormat(Table, record.DigestFormat)
	if err != nil || replaced != digest {
		t.Fatal("same-name replacement changed old index rule", err)
	}
	time.Sleep(2200 * time.Millisecond)
	if m.Status().State != "active" {
		t.Fatal("real audit degraded after link changes", m.Status())
	}
	if _, err = m.ProtectionStop(active.ID); err != nil {
		t.Fatal(err)
	}
	stopped := waitEvaluation(t, m, "stopped")
	if stopped.Cleanup != "confirmed" || m.socketSession != nil {
		t.Fatal("owner cleanup incomplete", stopped)
	}
	tables, err := nft("list", "tables")
	if err != nil || strings.Contains(string(tables), Table) || strings.Contains(string(tables), GuardTable) {
		t.Fatal("owned interception remains", err, string(tables))
	}
	if err = exec.Command("ip", "address", "add", "198.18.1.1/24", "dev", "fgsession0").Run(); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command("ip", "link", "set", "fgsession0", "up").Run(); err != nil {
		t.Fatal(err)
	}
	factory := RoutedSocketSessionFactory(e, resolver)
	if err = m.ConfigureSocketSession(func(ctx context.Context, table, chain string) (SocketSessionResources, error) {
		owner, err := factory(ctx, table, chain)
		if err != nil {
			return owner, err
		}
		return owner, errors.New("injected optional accelerator failure")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = m.ProtectionStart(stopped.ID, strings.Repeat("d", 32), "both"); err != nil {
		t.Fatal(err)
	}
	fallback := waitEvaluation(t, m, "active")
	if m.SocketSessionFailure() == nil || e.SocketAuthorizationStatus() != nil || m.socketSession == nil {
		t.Fatal("partial accelerator failure did not retain disabled owner with active queue")
	}
	if _, err = m.ProtectionStop(fallback.ID); err != nil {
		t.Fatal(err)
	}
	stopped = waitEvaluation(t, m, "stopped")
	if stopped.Cleanup != "confirmed" || m.socketSession != nil {
		t.Fatal("fallback cleanup incomplete", stopped)
	}
	crashDir := filepath.Join(dir, "crash")
	if err = os.Mkdir(crashDir, 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	baselinePrograms := sessionProgramIDs(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socketFile := os.NewFile(uintptr(fd), "crash-test-socket")
	defer socketFile.Close()
	if err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 1, 1}}); err != nil {
		t.Fatal(err)
	}
	// Observe packets after the protection output hooks: sendto success alone
	// does not establish that NFQUEUE delivered an outgoing UDP datagram.
	observer := exec.Command("nft", "-f", "-")
	observer.Stdin = strings.NewReader(`add table inet fg_crash_observer
add counter inet fg_crash_observer delivered
add chain inet fg_crash_observer post { type filter hook postrouting priority 300; policy accept; }
add rule inet fg_crash_observer post ip saddr 198.18.1.1 ip daddr 198.18.1.2 udp dport 45678 counter name delivered
`)
	if raw, er := observer.CombinedOutput(); er != nil {
		t.Fatal(er, string(raw))
	}
	defer exec.Command("nft", "delete", "table", "inet", "fg_crash_observer").Run()
	countEgress := func() uint64 {
		raw, er := exec.Command("nft", "-j", "list", "counter", "inet", "fg_crash_observer", "delivered").Output()
		if er != nil {
			t.Fatal(er)
		}
		var result struct {
			Nftables []struct{ Counter *struct{ Packets uint64 } }
		}
		if er = json.Unmarshal(raw, &result); er != nil {
			t.Fatal(er)
		}
		for _, entry := range result.Nftables {
			if entry.Counter != nil {
				return entry.Counter.Packets
			}
		}
		t.Fatal("egress counter absent")
		return 0
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestRoutedProtectionSessionPrivateNamespace$", "-test.timeout=30s")
	cmd.ExtraFiles = []*os.File{socketFile}
	cmd.Env = append(os.Environ(), "FLOWGATE_SESSION_CRASH_CHILD=1", "FLOWGATE_SOCKET_SESSION_RUN="+crashDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()
	killed := false
	defer func() {
		if !killed {
			_ = cmd.Process.Kill()
			<-childDone
		}
	}()
	readyUntil := time.Now().Add(12 * time.Second)
	for {
		if _, er := os.Stat(filepath.Join(crashDir, "ready")); er == nil {
			break
		}
		if time.Now().After(readyUntil) {
			t.Fatal("crash child did not activate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := countEgress(); got != 1 {
		t.Fatalf("live grant egress count = %d, want 1", got)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-childDone
	killed = true
	time.Sleep(socketgrant.Window + 50*time.Millisecond)
	for name, args := range map[string][]string{
		"after-kill-rules.json": {"nft", "-j", "list", "ruleset"},
		"after-kill-queues.txt": {"cat", "/proc/net/netfilter/nfnetlink_queue"},
		"after-kill-maps.json":  {"bpftool", "-j", "map", "show"},
	} {
		raw, diagErr := exec.Command(args[0], args[1:]...).CombinedOutput()
		if diagErr != nil {
			raw = append(raw, []byte(diagErr.Error())...)
		}
		_ = os.WriteFile(filepath.Join(crashDir, name), raw, 0600)
	}
	sendErr := unix.Sendto(fd, []byte("expired"), 0, &unix.SockaddrInet4{Addr: [4]byte{198, 18, 1, 2}, Port: 45678})
	if got := countEgress(); got != 1 {
		t.Fatalf("expired packet reached postrouting: count %d", got)
	}
	_ = os.WriteFile(filepath.Join(crashDir, "expiry-egress.txt"), []byte(fmt.Sprintf("live=1 after_expiry=1 send_error=%v\n", sendErr)), 0600)
	if reflect.DeepEqual(sessionProgramIDs(t), baselinePrograms) {
		t.Fatal("crash fixture had no surviving nft program reference")
	}
	if err = RecoverContinuous(filepath.Join(crashDir, "state")); err != nil {
		t.Fatal(err)
	}
	releaseUntil := time.Now().Add(2 * time.Second)
	for !reflect.DeepEqual(sessionProgramIDs(t), baselinePrograms) {
		if time.Now().After(releaseUntil) {
			t.Fatal("recovery leaked killed-child programs")
		}
		time.Sleep(20 * time.Millisecond)
	}
	recovered, err := Read(filepath.Join(crashDir, "state"))
	if err != nil || recovered.State != "stopped" {
		t.Fatal("crash recovery failed", recovered, err)
	}
	replacement := newCrashSession(t, crashDir)
	defer replacement.Close()
	if _, err = replacement.ProtectionStart("", strings.Repeat("f", 32), "both"); err != nil {
		t.Fatal(err)
	}
	fresh := waitEvaluation(t, replacement, "active")
	if replacement.SocketSessionFailure() != nil {
		t.Fatal(replacement.SocketSessionFailure())
	}
	if _, err = replacement.ProtectionStop(fresh.ID); err != nil {
		t.Fatal(err)
	}
	waitEvaluation(t, replacement, "stopped")
	t.Log("PASS activation + real audit ticks + rename/delete/readd + optional failure + SIGKILL/RecoverContinuous/new session + cleanup; no grant/performance claim")
}

func newCrashSession(t *testing.T, dir string) *Evaluation {
	t.Helper()
	e := daemon.New(time.Second)
	e.Mode = "daemon-monitor"
	uid := uint32(0)
	e.APIUID = &uid
	e.AdministratorUID = &uid
	zones := identity.NewZoneManagerWithPublisher(e.Zones.Legacy(), e.NetworkZonePublisher())
	e.ZoneSource = zones.Snapshot
	resolver := daemon.SocketSessionResolvers{Fresh: func(identity.Flow) identity.Attribution { return identity.Attribution{} }, Observed: func(identity.Flow) (identity.Attribution, uint64) { return identity.Attribution{}, 0 }}
	m := NewEvaluation(context.Background(), e, filepath.Join(dir, "state"), filepath.Join(dir, "api", "s"), filepath.Join(dir, "data", "rules.db"))
	if err := m.ConfigureProtection(filepath.Join(dir, "desired.json")); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureSocketSession(RoutedSocketSessionFactory(e, resolver)); err != nil {
		t.Fatal(err)
	}
	return m
}

func sessionProgramIDs(t *testing.T) []int {
	t.Helper()
	raw, err := exec.Command("bpftool", "-j", "prog", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ ID int }
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	ids := make([]int, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	sort.Ints(ids)
	return ids
}
