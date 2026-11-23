package uploadshape

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"flowgate/internal/identity"
)

type model struct {
	mu     sync.Mutex
	calls  []string
	closed bool
	block  chan struct{}
}

func (f *model) Call(q map[string]any) (json.RawMessage, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprint(q["op"]))
	f.mu.Unlock()
	if f.block != nil {
		<-f.block
	}
	return json.RawMessage(`{"status":"Partial","apps":{},"bindings":[],"next_minor":1}`), nil
}
func (f *model) Close() error { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }
func until(t *testing.T, f func() bool) {
	t.Helper()
	// Discovery can require three one-second ticks; allow for scheduling delay.
	end := time.Now().Add(6 * time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal("timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSavedOnlySettingsStayOutOfKernelPolicy(t *testing.T) {
	m := newManager(Options{})
	defer m.Close()
	m.start = func() (transport, error) {
		t.Error("saved-only settings started the controller")
		return nil, fmt.Errorf("unexpected controller start")
	}
	edit := &Cap{Application: "app", UID: 1000, BitsPerSecond: 8_000_000, DownloadBitsPerSecond: 16_000_000, TrafficPriority: "high"}
	for i := 0; i < MaxCaps+1; i++ {
		copy := *edit
		copy.UID += uint32(i)
		if _, err := m.Configure(uint64(i+1), Config{Schema: 4, StoredEdit: &copy}); err != nil {
			t.Fatal(err)
		}
	}
	s := m.Snapshot()
	if s.Enabled || s.Status != "Disabled" || len(s.Caps) != MaxCaps+1 || !s.Caps[0].StoredOnly {
		t.Fatalf("unexpected stored settings: %+v", s)
	}
	cfg, _, _ := m.current()
	if len(cfg.Caps) != 0 {
		t.Fatalf("saved-only settings reached the controller: %+v", cfg)
	}
	if _, err := m.Configure(s.Version, Config{Schema: 3}); err == nil {
		t.Fatal("legacy configuration overwrote saved settings")
	}
	removed, err := m.Configure(s.Version, Config{Schema: 4, StoredEdit: &Cap{Application: "app", UID: 1000}})
	if err != nil || len(removed.Caps) != MaxCaps || removed.Caps[0].UID != 1001 {
		t.Fatalf("removal crossed application accounts: %+v, %v", removed, err)
	}
}

func TestSavedNativeSettingBindsWhenItsSocketAppears(t *testing.T) {
	cap := Cap{UID: 1000, Application: "native", BitsPerSecond: 8_000_000}
	previous := newManager(Options{})
	previous.start = func() (transport, error) { return &model{}, nil }
	var saved Preferences
	previous.savePreferences = func(p Preferences) error { saved = p; return nil }
	if _, err := previous.Configure(1, Config{Schema: 4, Enabled: true, Caps: []Cap{cap}}); err != nil {
		previous.Close()
		t.Fatal(err)
	}
	previous.Close()

	m := newManager(Options{})
	if err := m.restorePreferences(saved); err != nil {
		t.Fatal(err)
	}
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	var started atomic.Bool
	sock := censusRows(1)[0]
	sock.UID = 1000
	m.sockets = func() ([]identity.Socket, error) {
		if !started.Load() {
			return nil, nil
		}
		return []identity.Socket{sock}, nil
	}
	m.resolveBatch = func(flows []identity.Flow) []identity.Attribution {
		app := identity.Application{Kind: "native", Key: "native"}
		return []identity.Attribution{{VisibilityComplete: true, Status: "directly-associated", Application: &app,
			Owners: []identity.Process{{PID: 7, ThreadGroup: 7, UID: 1000, Application: app}}, Sockets: []identity.Socket{sock}}}
	}
	defer m.Close()
	cfg := Config{Schema: 4, Enabled: true, Caps: []Cap{cap}}
	s := m.Snapshot()
	if !s.Enabled || len(s.Caps) != 1 || s.Caps[0] != cap || s.Kernel != nil || len(m.pending) != 0 {
		t.Fatalf("restored settings contained missing preferences or stale binding state: %+v", s)
	}
	m.Resume()
	until(t, func() bool { return m.Snapshot().AppliedVersion == s.Version })
	f.mu.Lock()
	hadBind := slices.Contains(f.calls, "bind_many") || slices.Contains(f.calls, "bind")
	f.mu.Unlock()
	if hadBind {
		t.Fatal("restored control must not bind without a new observation")
	}
	cfg.StoredEdit = &Cap{UID: 1000, Application: "runtime", BitsPerSecond: 16_000_000}
	updated, err := m.Configure(s.Version, cfg)
	if err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return m.Snapshot().AppliedVersion == updated.Version })
	started.Store(true)
	until(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return slices.Contains(f.calls, "bind_many")
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(slices.DeleteFunc(slices.Clone(f.calls), func(op string) bool { return op != "policy" })) != 1 {
		t.Fatalf("saved-only edit reapplied the native kernel policy: %v", f.calls)
	}
}

func TestFailedPreferenceSaveLeavesVersionAndSettingsUnchanged(t *testing.T) {
	m := newManager(Options{})
	defer m.Close()
	m.savePreferences = func(Preferences) error { return fmt.Errorf("disk failure") }
	if _, err := m.Configure(1, Config{Schema: 4, StoredEdit: &Cap{
		UID: 1000, Application: "fixture", BitsPerSecond: 8_000_000,
	}}); !errors.Is(err, ErrSavePreferences) {
		t.Fatalf("got %v", err)
	}
	if s := m.Snapshot(); s.Version != 1 || len(s.Caps) != 0 || s.Kernel != nil {
		t.Fatalf("failed write changed active state: %+v", s)
	}
}
func TestDisabledAndCAS(t *testing.T) {
	m := newManager(Options{Interface: "test"})
	defer m.Close()
	starts := 0
	m.start = func() (transport, error) { starts++; return nil, fmt.Errorf("unexpected") }
	s, err := m.Configure(1, Config{})
	if err != nil || s.Status != "Disabled" || s.Version != 2 {
		t.Fatal(s, err)
	}
	if _, err = m.Configure(1, Config{}); err == nil {
		t.Fatal("replayed stale write")
	}
	if starts != 0 || m.running {
		t.Fatal("disabled creates work")
	}
	if _, err = m.Configure(2, Config{Caps: []Cap{{Application: "a", BitsPerSecond: 4_000_000}}}); err == nil {
		t.Fatal("disabled caps accepted")
	}
}
func TestDesiredACKDoesNotClaimAppliedAndLostACKCannotReplay(t *testing.T) {
	m := newManager(Options{Interface: "test"})
	f := &model{block: make(chan struct{})}
	m.start = func() (transport, error) { return f, nil }
	defer m.Close()
	s, err := m.Configure(1, Config{Enabled: true, Caps: []Cap{{Application: "a", BitsPerSecond: 4_000_000}}})
	if err != nil || s.Status != "Applying" || s.AppliedVersion == s.Version {
		t.Fatal(s, err)
	}
	if _, err = m.Configure(1, Config{Enabled: true}); err == nil {
		t.Fatal("lost ack replay accepted")
	}
	close(f.block)
	until(t, func() bool { return m.Snapshot().AppliedVersion == 2 })
	s, err = m.Configure(2, Config{})
	if err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return m.Snapshot().Status == "Disabled" })
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if !closed {
		t.Fatal("disabled retained helper")
	}
}
func TestFaultDoesNotRestartUntilNewVersion(t *testing.T) {
	m := newManager(Options{})
	defer m.Close()
	var mu sync.Mutex
	n := 0
	m.start = func() (transport, error) { mu.Lock(); n++; mu.Unlock(); return nil, fmt.Errorf("foreign objects") }
	m.Configure(1, Config{Enabled: true})
	until(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return !m.running })
	if m.Snapshot().Status != "Unsupported" {
		t.Fatal(m.Snapshot())
	}
	mu.Lock()
	count := n
	mu.Unlock()
	if count != 1 {
		t.Fatal(count)
	}
	m.Configure(2, Config{})
	until(t, func() bool { return m.Snapshot().Status == "Disabled" })
	if m.Snapshot().Status != "Disabled" {
		t.Fatal(m.Snapshot())
	}
}
func TestStaleCoverageNotPresentedAsVerified(t *testing.T) {
	m := newManager(Options{})
	m.snap.Kernel = &KernelStatus{Covered: 2}
	m.snap.Status = "Active"
	m.snap.Updated = time.Now()
	m.snap.VerifiedUntil = time.Now().Add(-time.Second)
	s := m.Snapshot()
	if s.Kernel.Covered != 0 || s.Status != "Partial" || m.snap.Kernel.Covered != 2 {
		t.Fatal(s)
	}
	m.snap.Status = "Applying"
	if m.Snapshot().Status != "Applying" {
		t.Fatal("expiry concealed pending configuration")
	}
	m.snap.VerifiedUntil = time.Now().Add(time.Second)
	if m.Snapshot().Kernel.Covered != 2 {
		t.Fatal("fresh coverage discarded")
	}
}

func TestEnableAcceptedWhileFaultedWorkerExitsIsNotLost(t *testing.T) {
	m := newManager(Options{})
	defer m.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	starts := 0
	m.start = func() (transport, error) {
		mu.Lock()
		starts++
		n := starts
		mu.Unlock()
		if n == 1 {
			close(entered)
			<-release
			return nil, fmt.Errorf("old attempt failed")
		}
		return &model{}, nil
	}
	m.Configure(1, Config{Enabled: true})
	<-entered
	s, err := m.Configure(2, Config{Enabled: true})
	if err != nil || s.Version != 3 {
		t.Fatal(s, err)
	}
	close(release)
	until(t, func() bool { return m.Snapshot().AppliedVersion == 3 })
	mu.Lock()
	count := starts
	mu.Unlock()
	if count != 2 {
		t.Fatal(count)
	}
}

func TestResidualCleanupIsAsyncAndRefusalIsNotDisabled(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		m := newManager(Options{})
		m.dirty = true
		m.snap.Status = "Unsupported"
		entered := make(chan struct{})
		release := make(chan struct{})
		m.cleanup = func() error {
			close(entered)
			<-release
			if refuse {
				return fmt.Errorf("foreign TC changed")
			}
			return nil
		}
		m.start = func() (transport, error) { t.Error("cleanup must not activate"); return nil, fmt.Errorf("unexpected") }
		s, err := m.Configure(1, Config{})
		if err != nil || s.Status != "Applying" {
			t.Fatal(s, err)
		}
		<-entered
		close(release)
		until(t, func() bool { m.mu.Lock(); defer m.mu.Unlock(); return !m.running })
		expected := "Disabled"
		if refuse {
			expected = "Unsupported"
		}
		if m.Snapshot().Status != expected {
			t.Fatal(m.Snapshot())
		}
		m.Close()
	}
}

func TestConfigurationBounds(t *testing.T) {
	c := Config{Enabled: true}
	for i := 0; i < 17; i++ {
		c.Caps = append(c.Caps, Cap{Application: fmt.Sprint(i), BitsPerSecond: 4_000_000})
	}
	if validateConfig(c) == nil {
		t.Fatal("17 concurrent caps accepted")
	}
}
func TestGenerationSpaceExhaustionRotatesAutomatically(t *testing.T) {
	m := newManager(Options{})
	defer m.Close()
	var mu sync.Mutex
	n := 0
	first := &exhaustedModel{}
	m.start = func() (transport, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		if n == 1 {
			return first, nil
		}
		return &model{}, nil
	}
	m.Configure(1, Config{Enabled: true})
	until(t, func() bool { mu.Lock(); defer mu.Unlock(); return n == 2 })
	until(t, func() bool { return m.Snapshot().Gaps["class_generation_rotation"] == 1 })
	first.mu.Lock()
	closed := first.closed
	first.mu.Unlock()
	if !closed {
		t.Fatal("rotation without verified cleanup")
	}
}

type exhaustedModel struct{ model }

func (f *exhaustedModel) Call(map[string]any) (json.RawMessage, error) {
	return json.RawMessage(`{"status":"Partial","apps":{},"bindings":[],"next_minor":65534}`), nil
}

func TestConcurrentDesiredWriterCannotReplaceAcceptedReceipt(t *testing.T) {
	// Each response describes its accepted version, even if another administrator
	// immediately supersedes it. Disabled avoids unrelated scheduling/helpers.
	for i := 0; i < 100; i++ {
		m := newManager(Options{})
		first := make(chan Snapshot, 1)
		second := make(chan Snapshot, 1)
		go func() { s, _ := m.Configure(1, Config{}); first <- s }()
		go func() {
			for m.Snapshot().Version == 1 {
				time.Sleep(time.Microsecond)
			}
			s, _ := m.Configure(2, Config{})
			second <- s
		}()
		a, b := <-first, <-second
		if a.Version != 2 || b.Version != 3 {
			t.Fatalf("receipts lost accepted version: %d %d", a.Version, b.Version)
		}
		m.Close()
	}
}
