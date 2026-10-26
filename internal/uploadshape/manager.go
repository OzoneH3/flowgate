// Package uploadshape publishes shaping-only socket bindings. It is never a
// firewall authority. No goroutine, polling or helper exists while disabled.
package uploadshape

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"flowgate/internal/identity"
)

const MaxCaps = 16

type Cap struct {
	UID           uint32 `json:"uid"`
	Application   string `json:"application"`
	BitsPerSecond uint64 `json:"bits_per_second"`
}

func (c Cap) key() string { return strconv.FormatUint(uint64(c.UID), 10) + ":" + c.Application }

type Config struct {
	Enabled bool  `json:"enabled"`
	Caps    []Cap `json:"caps"`
}
type Binding struct {
	App    string `json:"app"`
	Cookie string `json:"cookie"`
}
type KernelStatus struct {
	Compatibility  json.RawMessage            `json:"compatibility,omitempty"`
	Segmentation   json.RawMessage            `json:"segmentation,omitempty"`
	ValidForMillis int64                      `json:"valid_for_ms"`
	Fault          string                     `json:"fault,omitempty"`
	Limitations    []string                   `json:"limitations,omitempty"`
	Status         string                     `json:"status"`
	Covered        int                        `json:"covered_bindings"`
	Bindings       []Binding                  `json:"bindings"`
	Apps           map[string]json.RawMessage `json:"apps"`
	NextMinor      uint32                     `json:"next_minor"`
	Counters       []struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counters"`
}
type Snapshot struct {
	VerifiedUntil   time.Time         `json:"verified_until"`
	CoverageExpired bool              `json:"coverage_snapshot_expired"`
	Version         uint64            `json:"version"`
	AppliedVersion  uint64            `json:"applied_version"`
	Enabled         bool              `json:"enabled"`
	Interface       string            `json:"interface"`
	Status          string            `json:"status"`
	Caps            []Cap             `json:"configured_caps"`
	Kernel          *KernelStatus     `json:"kernel,omitempty"`
	ApplicationWide bool              `json:"application_wide_guarantee"`
	Gaps            map[string]uint64 `json:"known_gaps"`
	LastError       string            `json:"last_error,omitempty"`
	Updated         time.Time         `json:"updated"`
	Coverage        string            `json:"coverage"`
}
type Options struct {
	Interface, Helpers, State, ParentNetNS string
}
type transport interface {
	Call(map[string]any) (json.RawMessage, error)
	Close() error
}
type hint struct {
	flow        identity.Flow
	app, cookie string
}
type Manager struct {
	mu              sync.Mutex
	opts            Options
	cfg             Config
	snap            Snapshot
	running, closed bool
	dirty           bool
	wake            chan struct{}
	done            chan struct{}
	hints           chan hint
	pending         map[string]bool
	start           func() (transport, error)
	sockets         func() ([]identity.Socket, error)
	cleanup         func() error
	resolve         func(identity.Flow) identity.Attribution
}

func New(o Options) (*Manager, error) {
	if err := validateOptions(o); err != nil {
		return nil, err
	}
	m := newManager(o)
	m.start = func() (transport, error) { return startProcess(o) }
	m.cleanup = func() error { return cleanupProcess(o) }
	if _, err := os.Lstat(filepath.Join(o.State, "owner.json")); err == nil {
		m.dirty = true
		m.snap.Status = "Unsupported"
		m.snap.LastError = "Owned journal remains; explicit configuration required for verified reconciliation"
	}
	return m, nil
}
func newManager(o Options) *Manager {
	m := &Manager{opts: o, wake: make(chan struct{}, 1), hints: make(chan hint, 128), pending: map[string]bool{}, sockets: func() ([]identity.Socket, error) { return identity.SocketsLimited(1024) }, resolve: identity.Resolve}
	m.snap = Snapshot{Version: 1, Interface: o.Interface, Status: "Disabled", Caps: []Cap{}, Gaps: map[string]uint64{}, Coverage: "verified socket bindings only; first packets and unobserved sockets may escape; never application-wide"}
	return m
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}
func (m *Manager) snapshotLocked() Snapshot {
	// Deep copy keeps API serialization independent from worker publication.
	b, _ := json.Marshal(m.snap)
	var s Snapshot
	_ = json.Unmarshal(b, &s)
	if s.Kernel != nil && time.Now().After(m.snap.VerifiedUntil) {
		s.Kernel.Covered = 0
		if s.Status == "Active" {
			s.Status = "Partial"
		}
		s.CoverageExpired = true
	}
	return s
}
func validateConfig(c Config) error {
	if len(c.Caps) > MaxCaps || (!c.Enabled && len(c.Caps) != 0) {
		return fmt.Errorf("at most16 caps; disabled configuration must have no caps")
	}
	seen := map[string]bool{}
	for _, v := range c.Caps {
		if len(v.Application) == 0 || len(v.Application) > 512 || strings.ContainsAny(v.Application, "\x00\r\n") || v.BitsPerSecond < 1_000_000 || v.BitsPerSecond > 1_000_000_000 {
			return fmt.Errorf("invalid native application cap or rate (1..1000Mbit/s)")
		}
		if seen[v.key()] {
			return fmt.Errorf("duplicate application cap")
		}
		seen[v.key()] = true
	}
	return nil
}

// Configure accepts desired state, not a claim that kernel changes completed.
// CAS makes lost acknowledgements reconcilable by reading version/configuration.
func (m *Manager) Configure(expected uint64, c Config) (Snapshot, error) {
	if err := validateConfig(c); err != nil {
		return Snapshot{}, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Snapshot{}, fmt.Errorf("controller closed")
	}
	if expected != m.snap.Version {
		m.mu.Unlock()
		return Snapshot{}, fmt.Errorf("stale_version")
	}
	c.Caps = append([]Cap(nil), c.Caps...)
	m.cfg = c
	m.snap.Version++
	m.snap.Enabled = c.Enabled
	m.snap.Caps = append([]Cap{}, c.Caps...)
	m.snap.Status = "Applying"
	m.snap.LastError = ""
	m.snap.Updated = time.Now()
	if !m.running && (c.Enabled || m.dirty) {
		m.running = true
		m.done = make(chan struct{})
		go m.run()
	}
	if !m.running {
		m.snap.Status = "Disabled"
		m.snap.AppliedVersion = m.snap.Version
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	accepted := m.snapshotLocked()
	m.mu.Unlock()
	return accepted, nil
}
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cfg = Config{}
	done := m.done
	running := m.running
	select {
	case m.wake <- struct{}{}:
	default:
	}
	m.mu.Unlock()
	if running {
		<-done
	}
}
func (m *Manager) gap(reason string) { m.mu.Lock(); m.snap.Gaps[reason]++; m.mu.Unlock() }
func eligible(a identity.Attribution) (string, string) {
	if !a.VisibilityComplete || a.Status != "directly-associated" || len(a.Owners) != 1 || len(a.Sockets) != 1 || a.Application == nil {
		return "", ""
	}
	p := a.Owners[0]
	if p.PID != p.ThreadGroup || p.HolderWitness != "" || p.Application.Kind != "native" || identity.RuntimeRuleBlocked(&p.Application) != "" {
		return "", ""
	}
	return strconv.FormatUint(uint64(p.UID), 10) + ":" + p.Application.Key, a.Sockets[0].Cookie
}

// Offer is a bounded nonblocking hint, not binding authority. The helper always
// performs the full M1 proof again. It is independent of the firewall decision.
func (m *Manager) Offer(f identity.Flow, a identity.Attribution) {
	if f.Direction != "outgoing" {
		return
	}
	app, cookie := eligible(a)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled || !m.running {
		return
	}
	if app == "" {
		m.snap.Gaps["unsupported_or_shared_observation"]++
		return
	}
	wanted := false
	for _, c := range m.cfg.Caps {
		if c.key() == app {
			wanted = true
			break
		}
	}
	if !wanted || m.pending[cookie] {
		return
	}
	if m.snap.Kernel != nil {
		for _, b := range m.snap.Kernel.Bindings {
			if b.Cookie == cookie {
				return
			}
		}
	}
	select {
	case m.hints <- hint{f, app, cookie}:
		m.pending[cookie] = true
	default:
		m.snap.Gaps["hint_capacity"]++
	}
}
func (m *Manager) current() (Config, uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg, m.snap.Version, m.closed
}
func (m *Manager) fail(err error) {
	m.mu.Lock()
	m.snap.Status = "Unsupported"
	if m.snap.LastError != "" {
		m.snap.LastError += "; " + err.Error()
	} else {
		m.snap.LastError = err.Error()
	}
	m.snap.Kernel = nil
	m.snap.Updated = time.Now()
	m.mu.Unlock()
}
func call(t transport, q map[string]any) (json.RawMessage, error) { return t.Call(q) }
func (m *Manager) run() {
	// One worker serializes configuration and all helper commands; no IO under
	// daemon policy lock or Manager.mu. No automatic restart after an unknown fault.
	restartOnEnable := false
	var attemptedVersion uint64
	defer func() {
		m.mu.Lock()
		m.running = false
		close(m.done)
		if (restartOnEnable || m.snap.Version != attemptedVersion) && (m.cfg.Enabled || m.dirty) && !m.closed {
			m.running = true
			m.done = make(chan struct{})
			go m.run()
		}
		m.mu.Unlock()
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var t transport
	var applied uint64
	var bound = map[string]bool{}
	var cursor int
	defer func() {
		if t != nil {
			if err := t.Close(); err != nil {
				m.fail(err)
			} else {
				m.mu.Lock()
				m.dirty = false
				m.mu.Unlock()
			}
		}
	}()
	for {
		cfg, version, closed := m.current()
		attemptedVersion = version
		if !cfg.Enabled || closed {
			m.mu.Lock()
			dirty := m.dirty
			m.mu.Unlock()
			if t == nil && dirty && m.cleanup != nil {
				if err := m.cleanup(); err != nil {
					m.fail(err)
					return
				}
			}
			if t != nil {
				err := t.Close()
				t = nil
				if err != nil {
					m.fail(err)
					return
				}
			}
			m.mu.Lock()
			m.dirty = false
			// An enable arriving during cleanup must be processed by this same worker.
			if m.cfg.Enabled && !m.closed {
				m.mu.Unlock()
				continue
			}
			m.snap.Status = "Disabled"
			m.snap.Kernel = nil
			m.snap.AppliedVersion = m.snap.Version
			m.pending = map[string]bool{}
			for len(m.hints) > 0 {
				<-m.hints
			}
			restartOnEnable = true
			m.mu.Unlock()
			return
		}
		if t == nil {
			var err error
			m.mu.Lock()
			m.dirty = true
			m.mu.Unlock()
			t, err = m.start()
			if err != nil {
				m.fail(err)
				return
			}
			m.gap("first_packet_binding_race")
		}
		if applied != version {
			raw, err := call(t, map[string]any{"op": "status"})
			if err != nil {
				m.fail(err)
				return
			}
			var s KernelStatus
			if err = json.Unmarshal(raw, &s); err != nil {
				m.fail(err)
				return
			}
			desired := map[string]Cap{}
			for _, c := range cfg.Caps {
				desired[c.key()] = c
			}
			for app := range s.Apps {
				q := map[string]any{"op": "remove", "app": app}
				if c, ok := desired[app]; ok {
					q = map[string]any{"op": "cap", "app": app, "rate": c.BitsPerSecond}
				}
				if _, err = call(t, q); err != nil {
					m.fail(err)
					return
				}
			}
			applied = version
			bound = map[string]bool{}
			cursor = 0
			m.mu.Lock()
			m.snap.AppliedVersion = version
			m.mu.Unlock()
		}
		// Refresh the published kernel truth before accepting more hints. An expired
		// lease or missing map entry is never presented as Active by userspace alone.
		sampleStart := time.Now()
		raw, err := call(t, map[string]any{"op": "status"})
		if err != nil {
			m.fail(err)
			return
		}
		var ks KernelStatus
		if err = json.Unmarshal(raw, &ks); err != nil {
			m.fail(err)
			return
		}
		if ks.Status == "Unsupported" || ks.Fault != "" {
			m.fail(fmt.Errorf("controller unsupported: %s", ks.Fault))
			return
		}
		if ks.NextMinor > 0xfffd {
			if err = t.Close(); err != nil {
				m.fail(err)
				return
			}
			t = nil
			applied = 0
			bound = map[string]bool{}
			m.gap("class_generation_rotation")
			continue
		}
		bound = map[string]bool{}
		for _, b := range ks.Bindings {
			bound[b.Cookie] = true
		}
		m.mu.Lock()
		m.snap.Kernel = &ks
		m.snap.VerifiedUntil = sampleStart.Add(time.Duration(ks.ValidForMillis) * time.Millisecond)
		m.snap.Status = "Partial"
		m.snap.Updated = time.Now()
		// Automatic discovery cannot enumerate every new/unconnected socket before
		// first traffic; retain Partial even if the requested subset is fully bound.
		if m.snap.Version != applied {
			m.snap.Status = "Applying"
		}
		m.mu.Unlock()
		select {
		case <-m.wake:
			continue
		case h := <-m.hints:
			m.mu.Lock()
			delete(m.pending, h.cookie)
			m.mu.Unlock()
			if !bound[h.cookie] {
				m.bind(t, h, version)
			}
		case <-tick.C:
			ss, er := m.sockets()
			if er != nil {
				m.gap("discovery_failed")
				continue
			}
			if len(ss) == 0 {
				continue
			}
			// At most8 socket inspections per cycle, round robin, finite1024-row census.
			for i := 0; i < 8 && i < len(ss); i++ {
				s := ss[cursor%len(ss)]
				cursor++
				_, v, stop := m.current()
				if stop || v != version {
					break
				}
				if s.Inode == 0 || bound[s.Cookie] {
					continue
				}
				uidWanted := false
				for _, c := range cfg.Caps {
					if c.UID == s.UID {
						uidWanted = true
						break
					}
				}
				if !uidWanted {
					continue
				}
				if !s.Remote.IsValid() || s.Remote.Port() == 0 || s.Remote.Addr().IsUnspecified() || !s.Local.IsValid() || s.Local.Addr().IsUnspecified() {
					m.gap("unconnected_or_listener_needs_observed_peer")
					continue
				}
				f := identity.Flow{Protocol: s.Protocol, Direction: "outgoing", Local: s.Local, Remote: s.Remote, NetNS: s.NetNS, Interface: s.Interface}
				app, cookie := eligible(m.resolve(f))
				if app == "" {
					m.gap("unsupported_or_shared_discovery")
					continue
				}
				if cookie != s.Cookie {
					m.gap("discovery_generation_changed")
					continue
				}
				m.bind(t, hint{f, app, cookie}, version)
			}
		}
	}
}
func (m *Manager) bind(t transport, h hint, version uint64) {
	cfg, v, closed := m.current()
	if v != version || closed || !cfg.Enabled {
		return
	}
	var rate uint64
	for _, c := range cfg.Caps {
		if c.key() == h.app {
			rate = c.BitsPerSecond
		}
	}
	if rate == 0 {
		return
	}
	if !validFlow(h.flow) {
		m.gap("unsupported_flow")
		return
	}
	_, err := call(t, map[string]any{"op": "bind", "protocol": h.flow.Protocol, "local": h.flow.Local.String(), "remote": h.flow.Remote.String(), "rate": rate, "expected_app": h.app, "expected_cookie": h.cookie})
	if err != nil {
		m.gap("binding_refused")
		m.mu.Lock()
		m.snap.LastError = err.Error()
		m.mu.Unlock()
	}
}
func validFlow(f identity.Flow) bool {
	return (f.Protocol == "tcp" || f.Protocol == "udp") && f.Local.IsValid() && f.Remote.IsValid() && f.Remote.Port() != 0 && !f.Remote.Addr().IsUnspecified()
}
