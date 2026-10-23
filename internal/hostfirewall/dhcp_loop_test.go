package hostfirewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"flowgate/internal/daemon"
	"flowgate/internal/essential"
	"flowgate/internal/identity"

	"github.com/florianl/go-nfqueue/v2"
)

// bindQueue binds and releases the protection queue number in this namespace.
func bindQueue() error {
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: Queue, MaxQueueLen: 1, MaxPacketLen: 64, Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: time.Second})
	if err != nil {
		return err
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return nf.RegisterWithErrorFunc(ctx, func(nfqueue.Attribute) int { return 0 }, func(error) int { return 0 })
}

type loopLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *loopLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *loopLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The actual continuous protection loop (production 1 s audit, 10 s environment
// audit, 30 s discovery) against real links, the real owned table and the real
// queue in a disposable namespace. NetworkManager answers are the only fixture;
// every discovery call waits at a barrier until the test supplies its answer.
func TestEssentialDHCPProtectionLoopRefresh(t *testing.T) {
	parent := os.Getenv("FLOWGATE_PARENT_NETNS")
	if parent == "" || parent == identity.NetNS() || os.Geteuid() != 0 {
		t.Skip("requires disposable lab namespace")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if b, e := exec.Command(name, args...).CombinedOutput(); e != nil {
			t.Fatalf("%s %v: %s %v", name, args, b, e)
		}
	}
	linkNames := func() []string {
		t.Helper()
		ifs, err := net.Interfaces()
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, i := range ifs {
			names = append(names, i.Name)
		}
		slices.Sort(names)
		return names
	}
	baseline := linkNames()
	// lp2 is linked and up but never an active connection: a guard built from all
	// links instead of the refreshed scopes would include it.
	for _, name := range []string{"lp0", "lp1", "lp2"} {
		run("ip", "link", "add", name, "type", "dummy")
		run("ip", "link", "set", name, "up")
		defer exec.Command("ip", "link", "del", name).Run()
	}

	var logs loopLog
	previous := log.Writer()
	log.SetOutput(io.MultiWriter(previous, &logs))
	defer log.SetOutput(previous)

	type answer struct {
		active []string
		err    error
	}
	calls, answers := make(chan time.Time), make(chan answer)
	env := essential.Environment{Run: func(ctx context.Context, command string, args ...string) ([]byte, error) {
		if command != "nmcli" {
			return nil, fmt.Errorf("unexpected command %s", command)
		}
		if args[0] != "-t" {
			return []byte("auto\nauto"), nil
		}
		select {
		case calls <- time.Now():
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var a answer
		select {
		case a = <-answers:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if a.err != nil {
			return nil, a.err
		}
		lines := []string{}
		for i, name := range a.active {
			lines = append(lines, fmt.Sprintf("uuid-%d:%s", i, name))
		}
		return []byte(strings.Join(lines, "\n")), nil
	}}
	reply := func(label string, a answer) {
		t.Helper()
		select {
		case answers <- a:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: discovery call abandoned before its answer", label)
		}
	}

	dir, err := os.MkdirTemp("../../.workspace/tmp", "dhcp-loop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.Abs(dir)
	api, data, state, desired := filepath.Join(dir, "api"), filepath.Join(dir, "data"), filepath.Join(dir, "state"), filepath.Join(dir, "desired")
	os.Mkdir(api, 0711)
	os.Mkdir(data, 0700)
	os.Mkdir(desired, 0700)
	e := daemon.New(time.Second)
	e.Essential = essential.NewManager(env)
	m := NewEvaluation(context.Background(), e, state, filepath.Join(api, "s"), filepath.Join(data, "rules.db"))
	defer m.Close()
	if err = m.ConfigureProtection(filepath.Join(desired, "protection.json")); err != nil {
		t.Fatal(err)
	}

	scopes := func(label, table string, want map[string]bool) error {
		for _, chain := range []string{"dhcp_input", "dhcp_output"} {
			dump, err := nft("list", "chain", "inet", table, chain)
			if err != nil {
				return fmt.Errorf("%s: %s %s: %v", label, table, chain, err)
			}
			for name, present := range want {
				if strings.Contains(string(dump), fmt.Sprintf("%q", name)) != present {
					return fmt.Errorf("%s: %s %s %s present=%v\n%s", label, table, chain, name, !present, dump)
				}
			}
		}
		return nil
	}
	// The refresh runs on a later 1 s tick after discovery returns. Observe under
	// the cleanup lock the refresh holds, so chains, record and digest are one
	// consistent snapshot rather than a view between the nft batch and the save.
	refreshed := func(label string, want map[string]bool) {
		t.Helper()
		names := []string{}
		for name, present := range want {
			if present {
				names = append(names, name)
			}
		}
		slices.Sort(names)
		deadline := time.Now().Add(3 * time.Second)
		for {
			err := evaluationLock(state, func() error {
				if err := scopes(label, Table, want); err != nil {
					return err
				}
				r, err := Read(state)
				if err != nil {
					return err
				}
				saved := []string{}
				for _, b := range r.Bootstrap {
					saved = append(saved, b.Name)
				}
				digest, err := tableDigest()
				if err != nil {
					return err
				}
				if !slices.Equal(saved, names) || r.TableDigest != digest {
					return fmt.Errorf("%s: persisted record %v digest match=%v, want %v", label, saved, r.TableDigest == digest, names)
				}
				return nil
			})
			if err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// Waits at the barrier for the loop's next discovery while requiring the
	// state to stay active on every 50 ms sample: each wait spans ~30 digest
	// audits and at least two environment audits.
	next := func(label string, since time.Time, a answer) time.Time {
		t.Helper()
		deadline := time.Now().Add(35 * time.Second)
		for {
			select {
			case at := <-calls:
				if gap := at.Sub(since); gap < 29*time.Second || gap > 33*time.Second {
					t.Fatalf("%s: discovery after %v, want the 30 s cadence", label, gap)
				}
				reply(label, a)
				return at
			case <-time.After(50 * time.Millisecond):
			}
			if s := m.Status(); s.State != "active" {
				t.Fatalf("%s: left active before discovery: %+v", label, s)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no discovery call within 35 s", label)
			}
		}
	}

	if _, err = m.ProtectionStart("", strings.Repeat("a", 32), "both"); err != nil {
		t.Fatal(err)
	}
	// Activation discovers once (ApprovedBootstrap) before installing the table.
	select {
	case <-calls:
		reply("activation", answer{active: []string{"lp0"}})
	case <-time.After(30 * time.Second):
		t.Fatalf("no activation discovery: %+v", m.Status())
	}
	waitEvaluation(t, m, "active")
	activated := time.Now()
	refreshed("activation", map[string]bool{"lp0": true, "lp1": false, "lp2": false})

	at := next("second connection", activated, answer{active: []string{"lp0", "lp1"}})
	refreshed("second connection", map[string]bool{"lp0": true, "lp1": true, "lp2": false})

	failed := errors.New("NetworkManager restarting")
	at = next("discovery failure", at, answer{err: failed})
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "DHCP refresh discovery failed; retaining active scopes: nmcli active connections failed: "+failed.Error()) {
		if time.Now().After(deadline) {
			t.Fatalf("discovery failure not consumed by the loop\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	refreshed("discovery failure retained", map[string]bool{"lp0": true, "lp1": true, "lp2": false})

	// A further call on the 30 s cadence proves the failed result cleared the
	// pending discovery. lp0 stays linked; only its connection is deactivated.
	at = next("connection deactivated", at, answer{active: []string{"lp1"}})
	refreshed("connection deactivated", map[string]bool{"lp0": false, "lp1": true, "lp2": false})
	for hold := time.Now().Add(12 * time.Second); time.Now().Before(hold); time.Sleep(50 * time.Millisecond) {
		if st := m.Status(); st.State != "active" {
			t.Fatalf("left active after refresh: %+v", st)
		}
	}
	// Control for the post-Stop probe: the live consumer must hold the queue.
	if err = bindQueue(); err == nil {
		t.Fatalf("queue %d bindable while protection is active", Queue)
	}

	// Foreign mutation of the owned table: fail closed with the refreshed scopes.
	run("nft", "add", "rule", "inet", Table, "input", "counter")
	s := waitEvaluation(t, m, "degraded")
	if s.Cleanup != "unconfirmed" || !strings.Contains(s.Reason, "changed") {
		t.Fatalf("mutation outcome %+v", s)
	}
	// Degraded is published before the guard is installed; InstallGuard holds the
	// cleanup lock, so observe the owned guard under it.
	deadline = time.Now().Add(5 * time.Second)
	for {
		err = evaluationLock(state, func() error {
			if yes, err := guardOwned(state); err != nil || !yes {
				return fmt.Errorf("guard not owned: %v %v", yes, err)
			}
			return scopes("guard", GuardTable, map[string]bool{"lp0": false, "lp1": true, "lp2": false})
		})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err = m.ProtectionStop(s.ID); err != nil {
		t.Fatal(err)
	}
	s = waitEvaluation(t, m, "stopped")
	if s.Cleanup != "confirmed" || m.ProtectionStatus().DesiredMode != "monitoring" {
		t.Fatalf("stop outcome %+v desired %s", s, m.ProtectionStatus().DesiredMode)
	}
	tables, err := nft("list", "tables")
	if err != nil || strings.Contains(string(tables), Table) || strings.Contains(string(tables), GuardTable) {
		t.Fatalf("owned tables remain: %v\n%s", err, tables)
	}
	// /proc/net/netfilter/nfnetlink_queue is not readable from the user
	// namespace; an exclusive bind is the direct evidence instead.
	if err = bindQueue(); err != nil {
		t.Fatalf("queue %d still bound after Stop: %v", Queue, err)
	}
	if r, err := Read(state); err != nil || r.State != "stopped" {
		t.Fatalf("record %+v %v", r, err)
	}
	for _, name := range []string{"lp0", "lp1", "lp2"} {
		run("ip", "link", "del", name)
	}
	if after := linkNames(); !slices.Equal(after, baseline) {
		t.Fatalf("links %v, baseline %v", after, baseline)
	}
	t.Log("PASS real loop: 30 s discovery cadence, refresh add/remove with persisted digest, active across post-refresh audits, discovery failure consumed and scopes retained, guard after mutation holds only refreshed scopes, Stop removes table, guard and queue binding")
}
