package udpaccount

import (
	"context"
	"crypto/sha256"
	"errors"
	"flowgate/internal/identity"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func waitManager(t *testing.T, m *Manager, state string) Status {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		v := m.Status()
		if v.State == state {
			return v
		}
		select {
		case <-deadline:
			t.Fatal(v)
		case <-time.After(time.Millisecond):
		}
	}
}
func TestManagerSerializedLifecycleAndFailure(t *testing.T) {
	var starts atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var live *session
	var liveMu sync.Mutex
	m := &Manager{status: Status{State: "disabled", Available: true, Scope: "machine", NetNS: "test"}}
	m.launch = func(ctx context.Context, _ *os.File, _ uint32, machine bool) (*session, error) {
		starts.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		own, cancel := context.WithCancel(ctx)
		s := &session{ctx: own, cancel: cancel, done: make(chan struct{}), state: identity.UDPSnapshot{State: "active", Machine: machine, Collected: time.Now(), Generation: "helper-internal"}}
		liveMu.Lock()
		live = s
		liveMu.Unlock()
		go func() {
			<-own.Done()
			s.mu.Lock()
			defer s.mu.Unlock()
			select {
			case <-s.done:
			default:
				close(s.done)
			}
		}()
		return s, nil
	}
	defer m.Close()
	first, err := m.Start("")
	if err != nil || first.State != "starting" {
		t.Fatal(first, err)
	}
	<-entered
	repeat, err := m.Start(first.Generation)
	if err != nil || repeat.Generation != first.Generation || starts.Load() != 1 {
		t.Fatal(repeat, err)
	}
	if _, err = m.Stop("old"); !errors.Is(err, ErrCollectorGeneration) {
		t.Fatal(err)
	}
	close(release)
	active := waitManager(t, m, "active")
	if active.Generation != first.Generation || m.Snapshot().Generation != first.Generation {
		t.Fatal("startup changed generation")
	}
	if _, err = m.Stop(first.Generation); err != nil {
		t.Fatal(err)
	}
	disabled := waitManager(t, m, "disabled")
	if m.Snapshot().State != "unavailable" {
		t.Fatal("old counters retained")
	}
	if _, err = m.Stop(disabled.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Start("old"); !errors.Is(err, ErrCollectorGeneration) {
		t.Fatal(err)
	}
	second, err := m.Start(disabled.Generation)
	if err != nil || second.Generation == first.Generation {
		t.Fatal(second, err)
	}
	<-entered
	waitManager(t, m, "active")
	liveMu.Lock()
	s := live
	liveMu.Unlock()
	s.mu.Lock()
	s.err = errors.New("deliberate helper crash")
	close(s.done)
	s.mu.Unlock()
	failed := waitManager(t, m, "failed")
	if failed.ReasonCode != "bpf_load_failed" || m.Snapshot().State != "unavailable" {
		t.Fatal(failed)
	}
}
func TestManagerMissingAndRetryBound(t *testing.T) {
	m := NewManager("/nonexistent-optional-helper", "", t.TempDir())
	defer m.Close()
	if m.Status().Available || m.Status().State != "disabled" {
		t.Fatal(m.Status())
	}
	if _, err := m.Start(""); err == nil {
		t.Fatal("missing helper started")
	}
	m.status.Available = true
	m.launch = func(context.Context, *os.File, uint32, bool) (*session, error) {
		return nil, errors.New("fixture load denied")
	}
	for i := 0; i < 3; i++ {
		s := m.Status()
		if _, err := m.Start(s.Generation); err != nil {
			t.Fatal(err)
		}
		waitManager(t, m, "failed")
	}
	if _, err := m.Start(m.Status().Generation); err == nil {
		t.Fatal("unbounded retry")
	}
}
func TestSessionProtocolFailureAndCancellation(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper")
	// Synthetic protocol/lifecycle only. No BPF/kernel accuracy claim.
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf 'NOT_READY\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := startSession(context.Background(), helper, 0, true); err == nil {
		t.Fatal("bad helper protocol accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := startSession(ctx, helper, 0, true); err == nil {
		t.Fatal("cancelled helper started")
	}
}

func TestManagerPinsOnlyReviewedHelperCopy(t *testing.T) {
	helper := "../../build/udp-collector"
	original, err := os.ReadFile(helper)
	if err != nil {
		t.Skip("optional native helper not built")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "reviewed")
	if err = os.WriteFile(source, original, 0700); err != nil {
		t.Fatal(err)
	}
	trusted := fmt.Sprintf("%x", sha256.Sum256(original))
	m := NewManager(source, trusted, dir)
	if !m.Status().Available {
		m.Close()
		t.Skip("optional helper/BTF prerequisites absent: " + m.Status().Reason)
	}
	pinned := m.pinned
	info, err := pinned.Stat()
	if err != nil || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Nlink != 0 {
		t.Fatal("pin must be an anonymous owner-only executable", info, err)
	}
	if err = os.WriteFile(source, []byte("changed after root configuration"), 0700); err != nil {
		t.Fatal(err)
	}
	copy, err := io.ReadAll(pinned)
	if err != nil || string(copy) != string(original) {
		t.Fatal("reviewed helper not pinned", err)
	}
	m.Close()
	if _, err = pinned.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("owned helper copy retained")
	}
	if b, _ := os.ReadFile(source); string(b) != "changed after root configuration" {
		t.Fatal("cleanup modified source")
	}
}

func TestPackagedPinRejectsChangedBytesAndWritableSource(t *testing.T) {
	original, err := os.ReadFile("../../build/udp-collector")
	if err != nil {
		t.Skip("optional native helper not built")
	}
	directory := t.TempDir()
	name := filepath.Join(directory, "udp-collector")
	expected := fmt.Sprintf("%x", sha256.Sum256(original))
	for _, test := range []struct {
		data []byte
		mode os.FileMode
		want string
	}{
		{append(append([]byte(nil), original...), 0), 0700, "SHA-256"},
		{original, 0720, "non-writable"},
	} {
		if err := os.WriteFile(name, test.data, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(name, test.mode); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		pin, err := pinHelper(source, expected, []string{directory})
		source.Close()
		if pin != nil || err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("wanted %q refusal, got %v", test.want, err)
		}
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 || files[0].Name() != "udp-collector" {
		t.Fatal("refusal left an unexpected file", files, err)
	}
}
