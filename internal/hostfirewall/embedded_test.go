package hostfirewall

import (
	"context"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"flowgate/internal/udpaccount"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitEvaluation(t *testing.T, m *Evaluation, state string) daemon.EvaluationStatus {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		s := m.Status()
		if s.State == state {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %s: %+v", state, m.Status())
	return daemon.EvaluationStatus{}
}
func TestEvaluationCASAndLostResponse(t *testing.T) {
	e := daemon.New(time.Second)
	m := NewEvaluation(context.Background(), e, "unused", "unused", "unused")
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	m.probe = func() []readiness.Check {
		calls++
		close(entered)
		<-release
		return []readiness.Check{{ID: "fixture", Status: readiness.Blocked, Code: "fixture_refusal", Detail: "injected refusal"}}
	}
	first, err := m.Start("", strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := m.Start("", strings.Repeat("a", 32)); err != nil || s.ID != first.ID || s.StopsAt != first.StopsAt {
				t.Error("retry renewed", s, err)
			}
			if _, err := m.Start("", strings.Repeat("b", 32)); err == nil {
				t.Error("concurrent stale Start accepted")
			}
		}()
	}
	wg.Wait()
	if _, err = m.Stop("old"); err == nil {
		t.Fatal("stale Stop accepted")
	}
	close(release)
	waitEvaluation(t, m, "failed")
	final := m.Status()
	if final.Cleanup != "confirmed" || final.ReasonCode != "fixture_refusal" {
		t.Fatal(final)
	}
	if s, err := m.Start("", strings.Repeat("a", 32)); err != nil || s.ID != first.ID || s.State != "failed" {
		t.Fatal("lost-response retry after refusal restarted", s, err)
	}
	if calls != 1 {
		t.Fatal("duplicate probes", calls)
	}
	if _, err := m.Start(final.ID, "not-a-nonce"); err == nil {
		t.Fatal("bad nonce accepted")
	}
	if _, err := m.Stop(final.ID); err != nil {
		t.Fatal(err)
	}
}
func TestEvaluationReadinessIsBoundedSingleFlight(t *testing.T) {
	m := NewEvaluation(context.Background(), daemon.New(time.Second), "unused", "unused", "unused")
	entered, release := make(chan struct{}), make(chan struct{})
	m.probe = func() []readiness.Check { close(entered); <-release; return []readiness.Check{} }
	m.Readiness()
	<-entered
	for i := 0; i < 10; i++ {
		if s := m.Readiness(); s.Readiness.State != "checking" {
			t.Fatal(s)
		}
	}
	if _, err := m.Start("", strings.Repeat("a", 32)); err == nil {
		t.Fatal("start raced readiness")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for m.Status().Readiness.State != "ready" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.Status().State != "stopped" || m.Status().ID != "" {
		t.Fatal("preflight activated", m.Status())
	}
}

// Real kernel cleanup fault injection, only in explicitly disposable namespaces.
// The test binary uses the separately built actual daemon for its watchdog.
type untouchedTraffic struct{}

func (untouchedTraffic) Status() udpaccount.Status {
	return udpaccount.Status{State: "active", Generation: "independent-collector"}
}
func (untouchedTraffic) Start(...string) (udpaccount.Status, error) {
	panic("evaluation touched collector Start")
}
func (untouchedTraffic) Stop(...string) (udpaccount.Status, error) {
	panic("evaluation touched collector Stop")
}
func TestEmbeddedKernelPartialActivationAndOwnedMutation(t *testing.T) {
	parent, bin := os.Getenv("FLOWGATE_PARENT_NETNS"), os.Getenv("FLOWGATE_EVALUATION_BINARY")
	if parent == "" || parent == identity.NetNS() || os.Geteuid() != 0 || bin == "" {
		t.Skip("requires disposable lab namespace and explicit test daemon")
	}
	dir, err := os.MkdirTemp("../../.workspace/tmp", "embedded-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.Abs(dir)
	api, data, state := filepath.Join(dir, "api"), filepath.Join(dir, "data"), filepath.Join(dir, "state")
	os.Mkdir(api, 0711)
	os.Mkdir(data, 0700)
	if _, err = nft("add", "table", "inet", "unrelated_fixture"); err != nil {
		t.Fatal(err)
	}
	defer nft("delete", "table", "inet", "unrelated_fixture")
	nft("add", "chain", "inet", "unrelated_fixture", "track", "{ type filter hook input priority 0; policy accept; }")
	nft("add", "rule", "inet", "unrelated_fixture", "track", "ct", "state", "established", "counter")
	e := daemon.New(time.Second)
	e.Traffic = untouchedTraffic{}
	m := NewEvaluation(context.Background(), e, state, filepath.Join(api, "s"), filepath.Join(data, "rules.db"))
	defer m.Close()
	m.prepare = func() (string, error) {
		target, err := PrepareSession(state, api, filepath.Join(data, "rules.db"))
		if err != nil {
			return "", err
		}
		b, err := os.ReadFile(bin)
		if err != nil {
			return "", err
		}
		err = os.WriteFile(target, b, 0700)
		return target, err
	}
	m.afterInstall = func() error { return errors.New("injected error after atomic installation, before active publication") }
	if _, err = m.Start("", strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	s := waitEvaluation(t, m, "failed")
	if s.Cleanup != "confirmed" {
		t.Fatal(s)
	}
	tables, _ := nft("list", "tables")
	if strings.Contains(string(tables), Table) || !strings.Contains(string(tables), "unrelated_fixture") {
		t.Fatal(string(tables))
	}
	m.afterInstall = nil
	if _, err = m.Start(s.ID, strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	waitEvaluation(t, m, "active")
	if _, err = nft("add", "rule", "inet", Table, "input", "counter"); err != nil {
		t.Fatal(err)
	}
	s = waitEvaluation(t, m, "failed")
	if s.Cleanup != "confirmed" || !strings.Contains(s.Reason, "changed") {
		t.Fatal(s)
	}
	tables, _ = nft("list", "tables")
	if strings.Contains(string(tables), Table) || !strings.Contains(string(tables), "unrelated_fixture") {
		t.Fatal(string(tables))
	}
	// Shortened only via this private in-package seam; production API is fixed300s.
	m.duration = 2 * time.Second
	if _, err = m.Start(s.ID, strings.Repeat("c", 32)); err != nil {
		t.Fatal(err)
	}
	waitEvaluation(t, m, "active")
	s = waitEvaluation(t, m, "stopped")
	if s.Cleanup != "confirmed" || s.ReasonCode != "expired" {
		t.Fatal(s)
	}

	m.duration = 30 * time.Second
	if _, err = m.Start(s.ID, strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	s = waitEvaluation(t, m, "active")
	if _, err = m.Stop(s.ID); err != nil {
		t.Fatal(err)
	}
	s = waitEvaluation(t, m, "stopped")
	if s.Cleanup != "confirmed" || s.ReasonCode != "stopped" {
		t.Fatal(s)
	}

	// A table that vanishes before its deadline remains a real integrity failure.
	if _, err = m.Start(s.ID, strings.Repeat("f", 32)); err != nil {
		t.Fatal(err)
	}
	waitEvaluation(t, m, "active")
	if _, err = nft("delete", "table", "inet", Table); err != nil {
		t.Fatal(err)
	}
	s = waitEvaluation(t, m, "failed")
	if s.Cleanup != "confirmed" || s.ReasonCode != "activation_failed" || s.Reason != "owned interception table disappeared" {
		t.Fatal(s)
	}

	// Run the same activation and watchdog with an independently controlled
	// context to force watchdog cleanup before the daemon deadline is delivered.
	id := strings.Repeat("e", 32)
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.mu.Lock()
	m.status.ID = id
	m.status.RequestID = id
	m.status.State = "starting"
	m.status.Cleanup = "pending"
	m.status.StopsAt = time.Now().Add(3 * time.Second)
	m.cancel, m.done = cancel, done
	m.mu.Unlock()
	go m.run(ctx, id, false)
	waitEvaluation(t, m, "active")
	// Simulate the wall deadline reaching the watchdog while the daemon's
	// monotonic deadline is still in the future. The on-disk deadline is fixed.
	m.mu.Lock()
	m.status.StopsAt = time.Now().Add(time.Minute)
	m.mu.Unlock()
	select {
	case <-done:
	case <-time.After(9 * time.Second):
		t.Fatal("daemon did not settle after watchdog cleanup", m.Status())
	}
	s = m.Status()
	if s.State != "stopped" || s.Cleanup != "confirmed" || s.ReasonCode != "expired" {
		t.Fatal(s)
	}
	record, err := Read(state)
	if err != nil || record.Token != id || record.State != "stopped" || !record.Expired {
		t.Fatal(record, err)
	}
	tables, err = nft("list", "tables")
	if err != nil || strings.Contains(string(tables), Table) || !strings.Contains(string(tables), "unrelated_fixture") {
		t.Fatal(string(tables), err)
	}

	if e.Traffic.Status().Generation != "independent-collector" {
		t.Fatal("evaluation replaced collector")
	}

}
