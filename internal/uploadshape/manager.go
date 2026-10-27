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
	App     string `json:"app"`
	Cookie  string `json:"cookie"`
	Covered bool   `json:"covered"`
}
type KernelStatus struct {
	Compatibility json.RawMessage `json:"compatibility,omitempty"`
	// Observation of the controller's last successful verification, measured by
	// the controller at report time (age since the verification STARTED).
	VerifiedAgeMillis        *int64                     `json:"verified_age_ms"`
	Verification             string                     `json:"verification,omitempty"`
	Verifications            uint64                     `json:"verifications,omitempty"`
	StatusReports            uint64                     `json:"status_reports,omitempty"`
	ExistencePassMillis      *int64                     `json:"existence_pass_ms,omitempty"`
	MaintenanceCycles        uint64                     `json:"maintenance_cycles"`
	MaxMaintenancePassMillis int64                      `json:"max_maintenance_pass_ms"`
	MaxCompletionGapMillis   int64                      `json:"max_completion_gap_ms"`
	MaxRenewalSpanMillis     int64                      `json:"max_renewal_span_ms"`
	MaintenancePassMillis    *int64                     `json:"maintenance_pass_ms,omitempty"`
	ExistenceQueries         int                        `json:"existence_queries"`
	Segmentation             json.RawMessage            `json:"segmentation,omitempty"`
	ValidForMillis           int64                      `json:"valid_for_ms"`
	Fault                    string                     `json:"fault,omitempty"`
	Limitations              []string                   `json:"limitations,omitempty"`
	Status                   string                     `json:"status"`
	Covered                  int                        `json:"covered_bindings"`
	Bindings                 []Binding                  `json:"bindings"`
	Apps                     map[string]json.RawMessage `json:"apps"`
	NextMinor                uint32                     `json:"next_minor"`
	Counters                 []struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counters"`
}
type Snapshot struct {
	DeploymentMode      string    `json:"deployment_mode"`
	VerifiedUntil       time.Time `json:"verified_until"`
	CoverageValidMillis int64     `json:"coverage_valid_for_ms"`
	CoverageExpired     bool      `json:"coverage_snapshot_expired"`
	// Reader-side view of the controller's last successful verification: the
	// controller-observed age plus the time this snapshot has been held, derived
	// at read time; "unknown" is a sentinel, never upgraded.
	VerificationAgeMinMillis *int64            `json:"verification_age_min_ms,omitempty"`
	ObservationHeldMillis    *int64            `json:"observation_held_ms,omitempty"`
	ObservationRPCMillis     *int64            `json:"observation_rpc_ms,omitempty"`
	VerificationAgeMillis    *int64            `json:"verification_age_ms,omitempty"`
	Verification             string            `json:"verification,omitempty"`
	Version                  uint64            `json:"version"`
	AppliedVersion           uint64            `json:"applied_version"`
	Enabled                  bool              `json:"enabled"`
	Interface                string            `json:"interface"`
	Status                   string            `json:"status"`
	Caps                     []Cap             `json:"configured_caps"`
	Kernel                   *KernelStatus     `json:"kernel,omitempty"`
	ApplicationWide          bool              `json:"application_wide_guarantee"`
	Gaps                     map[string]uint64 `json:"known_gaps"`
	Discovery                DiscoveryStats    `json:"discovery"`
	DiscoverySnapshot        DiscoveryProgress `json:"discovery_snapshot"`
	Priority                 PriorityProgress  `json:"priority_discovery"`
	LastError                string            `json:"last_error,omitempty"`
	Updated                  time.Time         `json:"updated"`
	Coverage                 string            `json:"coverage"`
}

// DiscoveryStats are monotonic activity counters for the census-driven discovery
// path. They describe work performed, never uncovered traffic, and are kept
// apart from known_gaps for that reason.
type DiscoveryStats struct {
	CensusAttempts     uint64 `json:"census_attempts"`     // ticks that asked for a socket census
	CensusErrors       uint64 `json:"census_errors"`       // census calls that returned an error (partial rows unused)
	CensusPasses       uint64 `json:"census_passes"`       // successful complete censuses, including empty ones
	RowsVisited        uint64 `json:"rows_visited"`        // rows examined, skipped ones included (<= 512 per turn)
	SkippedUnusable    uint64 `json:"skipped_unusable"`    // rows without an inode
	SkippedBound       uint64 `json:"skipped_bound"`       // rows already bound in the kernel
	SkippedUID         uint64 `json:"skipped_uid"`         // rows of a UID without any cap
	SkippedUnconnected uint64 `json:"skipped_unconnected"` // unconnected/wildcard rows
	CandidateRows      uint64 `json:"candidate_rows"`      // rows handed to the shared resolution
	SharedResolutions  uint64 `json:"shared_resolutions"`  // ResolveBatch calls (each may census twice on retry)
	FlowsResolved      uint64 `json:"flows_resolved"`      // attributions returned by those calls
	EligibleCandidates uint64 `json:"eligible_candidates"` // candidates whose attribution was eligible (capped or not)
	BindRequests       uint64 `json:"bind_requests"`       // controller bind RPCs actually issued
	StaleBatches       uint64 `json:"stale_batches"`       // batches discarded because the configuration changed meanwhile
}

type Options struct {
	Interface, Helpers, State, ParentNetNS string
	HostTrial                              bool
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
	sampleStart     time.Time // monotonic request anchor of the published kernel status
	sampleReceived  time.Time // monotonic response receipt; bounds observation timing
	wake            chan struct{}
	done            chan struct{}
	hints           chan hint
	pending         map[string]bool
	start           func() (transport, error)
	sockets         func() ([]identity.Socket, error)
	cleanup         func() error
	resolve         func(identity.Flow) identity.Attribution
	resolveBatch    func([]identity.Flow) []identity.Attribution
	priorityHints   func([]Cap) priorityHints
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
	m := &Manager{opts: o, wake: make(chan struct{}, 1), hints: make(chan hint, 128), pending: map[string]bool{}, sockets: func() ([]identity.Socket, error) { return identity.SocketsLimited(DiscoveryCapacity) }, resolve: identity.Resolve, resolveBatch: identity.ResolveBatch, priorityHints: nativePriorityHints}
	mode := "isolated"
	if o.HostTrial {
		mode = "host-trial"
	}
	m.snap = Snapshot{DeploymentMode: mode, Version: 1, Interface: o.Interface, Status: "Disabled", Caps: []Cap{}, Gaps: map[string]uint64{}, Coverage: "verified socket bindings only; first packets and unobserved sockets may escape; never application-wide"}
	return m
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}
func (m *Manager) snapshotLocked() Snapshot {
	now := time.Now()
	// Deep copy keeps API serialization independent from worker publication.
	b, _ := json.Marshal(m.snap)
	var s Snapshot
	_ = json.Unmarshal(b, &s)
	if s.Kernel != nil && now.After(m.snap.VerifiedUntil) {
		s.Kernel.Covered = 0
		if s.Status == "Active" {
			s.Status = "Partial"
		}
		s.CoverageExpired = true
	}
	if s.Kernel != nil && (s.CoverageExpired || s.Status == "Unsupported" || s.Status == "Disabled" || s.Kernel.Status == "Unsupported" || s.Kernel.Fault != "") {
		s.Kernel.Covered = 0
		for i := range s.Kernel.Bindings {
			s.Kernel.Bindings[i].Covered = false
		}
	}
	if s.Kernel != nil {
		s.VerificationAgeMinMillis, s.VerificationAgeMillis, s.ObservationHeldMillis, s.ObservationRPCMillis = verificationInterval(m.snap.Kernel, m.sampleStart, m.sampleReceived, now)
		k := *m.snap.Kernel
		k.VerifiedAgeMillis = s.VerificationAgeMillis
		_, s.Verification = verificationView(&k, time.Time{}, now)
		// Stale/unknown verification can only downgrade Active; Applying and
		// Unsupported are preserved as published.
		if s.Status == "Active" && s.Verification != "fresh" {
			s.Status = "Partial"
		}
	}
	// Remaining lifetime at this read, not the immutable controller TTL. A UI
	// may anchor this conservative floor at its request start; rereads cannot
	// resurrect an old observation. It is reporting only, never authority.
	if s.Kernel != nil && s.Kernel.Covered > 0 && !s.CoverageExpired {
		s.CoverageValidMillis = m.snap.VerifiedUntil.Sub(now).Milliseconds()
		if s.CoverageValidMillis < 0 {
			s.CoverageValidMillis = 0
		}
		if s.CoverageValidMillis > 5000 {
			s.CoverageValidMillis = 5000
		}
	}
	return s
}

// verificationInterval brackets the age since verification START. The controller
// floors its age to milliseconds at an instant between request and receipt.
// Keep transit uncertainty explicit; neither bound is controller/lease health.
func verificationInterval(k *KernelStatus, start, received, now time.Time) (lower, upper, held, rpc *int64) {
	if k == nil || k.VerifiedAgeMillis == nil || *k.VerifiedAgeMillis < 0 || start.IsZero() || received.IsZero() || received.Before(start) || now.Before(received) {
		return
	}
	base := *k.VerifiedAgeMillis
	// A controller report is bounded by its RPC deadline; reject corrupt ages
	// instead of wrapping arithmetic into apparently fresh evidence.
	const maxMillis = int64(1 << 62)
	if base > maxMillis {
		return
	}
	h := now.Sub(received).Milliseconds()
	r := (received.Sub(start) + time.Millisecond - 1) / time.Millisecond
	l := base + h
	u := base + 1 + int64((now.Sub(start)+time.Millisecond-1)/time.Millisecond)
	rr := int64(r)
	return &l, &u, &h, &rr
}

// verificationView ages the controller-observed verification by the time the
// snapshot has been held (monotonic anchor), and labels it with the controller's
// own thresholds: fresh <= 1 s, stale <= 2 s, otherwise unknown. A controller
// that reported no observation (older controller, or never verified) stays
// unknown with no age; a label is never upgraded beyond what the controller said.
func verificationView(k *KernelStatus, sampleStart, now time.Time) (*int64, string) {
	if k == nil || k.VerifiedAgeMillis == nil {
		return nil, "unknown"
	}
	age := *k.VerifiedAgeMillis
	if !sampleStart.IsZero() && now.After(sampleStart) {
		age += now.Sub(sampleStart).Milliseconds()
	}
	label := "unknown"
	if k.Verification == "fresh" || k.Verification == "stale" {
		switch {
		case age <= 1000:
			label = "fresh"
		case age <= 2000:
			label = "stale"
		}
		if k.Verification == "stale" && label == "fresh" {
			label = "stale"
		}
	}
	return &age, label
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
func (m *Manager) discovered(d DiscoveryStats) {
	m.mu.Lock()
	s := &m.snap.Discovery
	s.CensusAttempts += d.CensusAttempts
	s.CensusErrors += d.CensusErrors
	s.CensusPasses += d.CensusPasses
	s.RowsVisited += d.RowsVisited
	s.SkippedUnusable += d.SkippedUnusable
	s.SkippedBound += d.SkippedBound
	s.SkippedUID += d.SkippedUID
	s.SkippedUnconnected += d.SkippedUnconnected
	s.CandidateRows += d.CandidateRows
	s.SharedResolutions += d.SharedResolutions
	s.FlowsResolved += d.FlowsResolved
	s.EligibleCandidates += d.EligibleCandidates
	s.BindRequests += d.BindRequests
	s.StaleBatches += d.StaleBatches
	m.mu.Unlock()
}
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
	var discovery discoverySnapshot
	var priority priorityQueue
	previousCaps := map[string]uint64{}
	discovery.reset()
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
			discovery.reset()
			m.publishDiscovery(&discovery)
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
			var changed []Cap
			for _, c := range cfg.Caps {
				if previousCaps[c.key()] != c.BitsPerSecond {
					changed = append(changed, c)
				}
			}
			previousCaps = map[string]uint64{}
			for _, c := range cfg.Caps {
				previousCaps[c.key()] = c.BitsPerSecond
			}
			priority = priorityQueue{}
			if len(changed) > 0 {
				priority.hints = m.priorityHints(changed)
			}
			priority.hints.view.Version = version
			m.publishPriority(&priority)
			applied = version
			discovery.clearRetry() // cap edits may request a fresh attempt, never reset progress
			bound = map[string]bool{}
			m.mu.Lock()
			m.snap.AppliedVersion = version
			m.mu.Unlock()
		}
		// Refresh the published kernel truth before accepting more hints. An expired
		// lease or missing map entry is never presented as Active by userspace alone.
		sampleStart := time.Now()
		raw, err := call(t, map[string]any{"op": "status"})
		sampleReceived := time.Now()
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
		m.sampleStart = sampleStart
		m.sampleReceived = sampleReceived
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
			if len(cfg.Caps) == 0 {
				discovery.reset()
				m.publishDiscovery(&discovery)
				continue
			}
			if discovery.view.Pending == 0 {
				if time.Now().Before(discovery.view.NextRetry) {
					continue
				}
				m.discovered(DiscoveryStats{CensusAttempts: 1})
				start := time.Now()
				rows, er := m.sockets()
				er = discovery.load(rows, er, start)
				m.publishDiscovery(&discovery)
				if er != nil {
					m.discovered(DiscoveryStats{CensusErrors: 1})
					m.gap("discovery_failed")
					if discovery.view.Overloaded {
						m.gap("discovery_overloaded")
					}
					continue
				}
				m.discovered(DiscoveryStats{CensusPasses: 1})
			}
			// Retained rows are hints only. Advance even across cap edits;
			// fresh resolution and the version guard still precede binding.
			priority.selectRows(&discovery)
			seen := map[string]bool{}
			var candidates []identity.Socket
			var flows []identity.Flow
			stats := DiscoveryStats{}
			stop := false
			for i := 0; i < DiscoveryScanBudget && len(candidates) < identity.MaxResolveBatch; i++ {
				var s identity.Socket
				var ok bool
				// At most four priority attempts; the remainder always advances
				// background discovery, including during repeated configuration edits.
				if i < 4 {
					s, ok = priority.next()
				}
				if !ok {
					s, ok = discovery.next()
				}
				if !ok {
					break
				}
				_, v, closed := m.current()
				if closed || v != version {
					stop = true
					break
				}
				stats.RowsVisited++
				if seen[s.Cookie] {
					continue
				}
				seen[s.Cookie] = true
				if s.Inode == 0 {
					stats.SkippedUnusable++
					continue
				}
				if bound[s.Cookie] {
					stats.SkippedBound++
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
					stats.SkippedUID++
					continue
				}
				if !s.Remote.IsValid() || s.Remote.Port() == 0 || s.Remote.Addr().IsUnspecified() || !s.Local.IsValid() || s.Local.Addr().IsUnspecified() {
					stats.SkippedUnconnected++
					m.gap("unconnected_or_listener_needs_observed_peer")
					continue
				}
				candidates = append(candidates, s)
				flows = append(flows, identity.Flow{Protocol: s.Protocol, Direction: "outgoing", Local: s.Local, Remote: s.Remote, NetNS: s.NetNS, Interface: s.Interface})
			}
			m.publishDiscovery(&discovery)
			m.publishPriority(&priority)
			stats.CandidateRows = uint64(len(candidates))
			if stop || len(candidates) == 0 {
				m.discovered(stats)
				continue
			}
			stats.SharedResolutions = 1
			attributions := m.resolveBatch(flows)
			stats.FlowsResolved = uint64(len(attributions))
			if len(attributions) != len(flows) {
				// Resolver contract violation: treat as a failed pass, never index past it.
				m.gap("discovery_failed")
				m.discovered(stats)
				continue
			}
			// The configuration may have changed while the census ran: never act on,
			// or publish as current, results obtained under an older version.
			if _, v, closed := m.current(); closed || v != version {
				stats.StaleBatches = 1
				m.discovered(stats)
				continue
			}
			for i, s := range candidates {
				app, cookie := eligible(attributions[i])
				if app == "" {
					m.gap("unsupported_or_shared_discovery")
					continue
				}
				if cookie != s.Cookie {
					m.gap("discovery_generation_changed")
					continue
				}
				stats.EligibleCandidates++
				if m.bind(t, hint{flows[i], app, cookie}, version) {
					stats.BindRequests++
				}
			}
			m.discovered(stats)
		}
	}
}

// bind asks the controller to prove and bind one socket; it reports whether a
// controller request was actually issued (false for stale/uncapped/invalid).
func (m *Manager) bind(t transport, h hint, version uint64) bool {
	cfg, v, closed := m.current()
	if v != version || closed || !cfg.Enabled {
		return false
	}
	var rate uint64
	for _, c := range cfg.Caps {
		if c.key() == h.app {
			rate = c.BitsPerSecond
		}
	}
	if rate == 0 {
		return false
	}
	if !validFlow(h.flow) {
		m.gap("unsupported_flow")
		return false
	}
	_, err := call(t, map[string]any{"op": "bind", "protocol": h.flow.Protocol, "local": h.flow.Local.String(), "remote": h.flow.Remote.String(), "rate": rate, "expected_app": h.app, "expected_cookie": h.cookie})
	if err != nil {
		m.gap("binding_refused")
		m.mu.Lock()
		m.snap.LastError = err.Error()
		m.mu.Unlock()
	}
	return true
}
func validFlow(f identity.Flow) bool {
	return (f.Protocol == "tcp" || f.Protocol == "udp") && f.Local.IsValid() && f.Remote.IsValid() && f.Remote.Port() != 0 && !f.Remote.Addr().IsUnspecified()
}
