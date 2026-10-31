package identity

// Explicit daemon startup configuration authorizes observation, never a rule.
// Helpers run as the selected desktop UID, not with daemon privileges.
import (
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type WineObserverOptions struct {
	ReserveRenewalCapacity bool
	Discover               bool
	Helper                 string
	RuntimeBins            []string
	Prefixes               []string
	UID                    uint32
	Scratch                string
}
type observedWine struct {
	broker  Process
	table   *WineTable
	failure string
	scratch *wineNamespace
	ready   chan struct{} // closed once setup stored table or failure
	pins    int           // in-flight users; release happens at the last unpin
	closed  bool
	// resolve runs one census on this session; wait=false must not block.
	resolve  func(f Flow, initial Attribution, wait bool) (Attribution, bool)
	released bool
}
type WineObservers struct {
	pendingDispatchStored atomic.Uint64
	pendingDispatchUsed   atomic.Uint64
	renewalPhases         renewalPhaseLog
	ordinaryPhases        renewalPhaseLog
	queueCensus           chan struct{} // prototype reservation: at most one ordinary census
	renewalCount          atomic.Uint64
	renewalTotalNS        atomic.Uint64
	renewalWaitNS         atomic.Uint64
	renewalServiceNS      atomic.Uint64
	renewalCensusCount    atomic.Uint64
	renewalWaitMax        atomic.Uint64
	renewalServiceMax     atomic.Uint64
	admissionDemand       atomic.Int64 // waiting or running censuses; presentation yields to these

	mu       sync.Mutex // guards sessions/closed/pins only; never held across setup or a census
	options  WineObserverOptions
	sessions map[string]*observedWine
	dispatch map[string]*wineDispatchHint
	closed   bool
	census   chan struct{} // bounds concurrent session setups plus runtime censuses
	// setupSession prepares a new session outside m.mu (tests substitute it).
	setupSession func(record *observedWine, broker *Process, bin string)
}

// WineCensusLimit bounds concurrent runtime censuses and helper setups. Callers
// that must not wait use TryResolve; Resolve waits for a slot.
const WineCensusLimit = 2

func NewWineObservers(o WineObserverOptions) (*WineObservers, error) {
	if o.Helper == "" || !filepath.IsAbs(o.Helper) || !filepath.IsAbs(o.Scratch) || (!o.Discover && (len(o.RuntimeBins) == 0 || len(o.Prefixes) == 0)) || len(o.RuntimeBins) > 4 || len(o.Prefixes) > 32 || (o.Discover && (len(o.RuntimeBins) > 0 || len(o.Prefixes) > 0)) {
		return nil, fmt.Errorf("explicit helper and scratch plus either runtime discovery or 1..4 trusted runtime bins and 1..32 authorized prefixes required")
	}
	var err error
	o.Helper, err = filepath.EvalSymlinks(o.Helper)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(o.Helper)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 2<<20 || st.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("bounded non-writable PE observer required")
	}
	b := readBound(o.Helper, 2)
	if string(b) != "MZ" {
		return nil, fmt.Errorf("PE observer required")
	}
	for _, list := range [][]string{o.RuntimeBins, o.Prefixes} {
		for i, p := range list {
			if !filepath.IsAbs(p) {
				return nil, fmt.Errorf("absolute runtime/prefix paths required")
			}
			list[i], err = filepath.EvalSymlinks(p)
			if err != nil {
				return nil, err
			}
		}
	}
	if st, err := os.Stat(o.Scratch); err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private existing observer scratch directory required")
	}
	m := &WineObservers{options: o, sessions: map[string]*observedWine{}, census: make(chan struct{}, WineCensusLimit)}
	if o.ReserveRenewalCapacity {
		m.queueCensus = make(chan struct{}, 1)
	}
	return m, nil
}

// cleanup closes a retired session's helper and scratch. It runs outside m.mu,
// exactly once, after retireLocked or unpinLocked handed the session over.
func (s *observedWine) cleanup() {
	if s.table != nil {
		s.table.Close()
	}
	if s.scratch != nil {
		s.scratch.removePrivateScratch()
		s.scratch.scratchDir.Close()
		s.scratch = nil
	}
}

// retireLocked removes a session from lookup. An unused session is returned for
// cleanup outside m.mu; otherwise its last user cleans it up.
func (m *WineObservers) retireLocked(key string, s *observedWine) []*observedWine {
	delete(m.sessions, key)
	s.closed = true
	if s.pins == 0 && !s.released {
		s.released = true
		return []*observedWine{s}
	}
	return nil
}

func cleanupAll(sessions []*observedWine) {
	for _, s := range sessions {
		s.cleanup()
	}
}

func (m *WineObservers) Close() {
	m.mu.Lock()
	m.closed = true
	m.dispatch = nil
	var retired []*observedWine
	for k, s := range m.sessions {
		retired = append(retired, m.retireLocked(k, s)...)
	}
	m.mu.Unlock()
	cleanupAll(retired)
}

// unpin ends one use. It reports whether the session was retired meanwhile, in
// which case that use's result must not be returned as evidence.
func (m *WineObservers) unpin(s *observedWine) (retired bool) {
	m.mu.Lock()
	s.pins--
	retired = s.closed || m.closed
	last := s.pins == 0 && s.closed && !s.released
	if last {
		s.released = true
	}
	m.mu.Unlock()
	if last {
		s.cleanup()
	}
	return retired
}

func (m *WineObservers) Resolve(f Flow) Attribution {
	a, _ := m.resolve(f, true)
	return a
}

// ResolveObserved retains ordinary census admission and dispatch hint behavior.
// The nonzero BOOTTIME start identifies a full native initial observation actually
// performed during THIS call. Hint-only success returns zero. Trusted callers
// must still validate complete identity, current policy and ticket generation.
func (m *WineObservers) ResolveObserved(f Flow) (Attribution, uint64) {
	return m.resolveObserved(f, Resolve)
}

// ResolveObservedAfter waits only before an actual full initial scan. Dispatch
// hint hits never invoke before; the fresh witness is stamped after the wait.
func (m *WineObservers) ResolveObservedAfter(f Flow, before func()) (Attribution, uint64) {
	return m.resolveObservedBefore(f, Resolve, before)
}
func (m *WineObservers) resolveObserved(f Flow, native func(Flow) Attribution) (Attribution, uint64) {
	return m.resolveObservedBefore(f, native, nil)
}
func (m *WineObservers) resolveObservedBefore(f Flow, native func(Flow) Attribution, before func()) (Attribution, uint64) {
	var start uint64
	a, done := m.resolveDispatch(f, true, func(flow Flow) Attribution {
		if before != nil {
			before()
		}
		start = renewalBootNow()
		return native(flow)
	})
	if !done {
		return a, 0
	}
	return a, start
}

// ResolveFresh is for the isolated socket authorization experiment. Unlike the
// ordinary dispatch path it starts with a new kernel/holder observation, so a
// grant deadline anchored before this call cannot hide an older initial hint.
func (m *WineObservers) ResolveFresh(f Flow) (result Attribution) {
	defer func() { result.renewalPhase = nil }()
	started := time.Now()
	defer func() { m.renewalCount.Add(1); m.renewalTotalNS.Add(uint64(time.Since(started))) }()
	phase := &renewalPhase{Flow: f.Key(), Start: renewalBootNow(), GroupSize: 1}
	defer func() { phase.Finished = renewalBootNow(); m.renewalPhases.add(*phase) }()
	a := Resolve(f)
	phase.InitialDone = renewalBootNow()
	a.renewalPhase = phase
	a.diagnosticSource = "fresh_socket_authorization"
	result, _ = m.resolveAttributionPriority(f, a, true, true)
	return result
}

// TryResolve never waits for a census slot, a session being set up, or a table
// held by another census: it reports false instead. false is not evidence and
// carries no verdict; the caller resolves later with Resolve or drops explicitly.
// Sockets without a configured Wine broker never need a census and report true.
func (m *WineObservers) TryResolve(f Flow) (Attribution, bool) {
	return m.resolve(f, false)
}

func (m *WineObservers) resolve(f Flow, wait bool) (Attribution, bool) {
	return m.resolveDispatch(f, wait, Resolve)
}

func (m *WineObservers) resolveDispatch(f Flow, wait bool, resolveNative func(Flow) Attribution) (result Attribution, done bool) {
	var phase *renewalPhase
	if wait && m.queueCensus != nil {
		phase = &renewalPhase{Flow: f.Key(), Start: renewalBootNow(), GroupSize: 1}
	}
	defer func() {
		result.renewalPhase = nil
		if phase != nil {
			phase.Finished = renewalBootNow()
			phase.Status = result.Status
			m.ordinaryPhases.add(*phase)
		}
	}()
	fallback := false
	if hint := m.dispatchHint(f, time.Now()); hint != nil {
		diagnostics.Count(diagnostics.WineHintHit, 1)
		if hint.pending {
			m.pendingDispatchUsed.Add(1)
		}
		initial := copyWineInitial(hint.initial)
		initial.renewalPhase = phase
		if phase != nil {
			phase.InitialDone = renewalBootNow()
			phase.InitialSource = "hint"
		}
		initial.diagnosticSource = "dispatch_hint"
		initial.diagnosticHintAge = time.Since(hint.observed)
		result, done := m.resolveAttribution(f, initial, wait)
		if !done {
			diagnostics.Count(diagnostics.WineBusy, 1)
			return Attribution{}, false
		}
		if positiveWineDispatch(result) {
			return result, true
		}
		diagnostics.Count(diagnostics.WineHintFallback, 1)
		m.forgetDispatch(f, hint)
		fallback = true
		// A hint never supplies a refusal or a permission: retry once from
		// fresh discovery. Queue deadlines remain checked by the caller.
	}
	a := resolveNative(f)
	a.renewalPhase = phase
	if phase != nil {
		phase.InitialDone = renewalBootNow()
		phase.InitialSource = "fresh"
		if fallback {
			phase.InitialSource = "hint_then_fresh"
		}
	}
	a.diagnosticSource = "fresh_dispatch"
	if fallback {
		a.diagnosticSource = "fresh_fallback"
	}
	if a.ReasonCode == ReasonNoSocketObserved {
		diagnostics.EvidenceKey(true, "dispatch:"+f.Key(), func() any {
			return map[string]any{"kind": "dispatch_no_socket", "flow": f, "initial": diagnosticAttribution(a), "observation_only": true}
		})
	}
	observed := time.Now()
	result, done = m.resolveAttribution(f, a, wait)
	if done {
		m.rememberDispatch(f, a, result, observed, time.Now())
	} else if !wait {
		m.rememberRoutingDispatch(f, a, observed, time.Now(), true)
	}
	return result, done
}

func (m *WineObservers) resolveAttribution(f Flow, a Attribution, wait bool) (Attribution, bool) {
	return m.resolveAttributionPriority(f, a, wait, false)
}
func (m *WineObservers) resolveAttributionPriority(f Flow, a Attribution, wait, priority bool) (Attribution, bool) {
	broker, bin, a := m.selectBroker(a)
	if broker == nil {
		return a, true
	}
	return m.sessionResolvePriority(f, a, broker, bin, wait, priority)
}

func (m *WineObservers) selectBroker(a Attribution) (*Process, string, Attribution) {
	var broker *Process
	var bin string
	candidates := a.Owners
	for pass := 0; pass < 2; pass++ {
		if pass == 1 {
			if broker != nil || !directUnresolved(a) {
				break
			}
			candidates = directBrokerCandidates(a)
		}
		for i := range candidates {
			p := &candidates[i]
			if p.UID != m.options.UID || p.Application.Prefix == "" || p.NetNS != NetNS() {
				continue
			}
			prefixAllowed := m.options.Discover
			for _, prefix := range m.options.Prefixes {
				if p.Application.Prefix == prefix {
					prefixAllowed = true
				}
			}
			if !prefixAllowed {
				continue
			}
			actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", p.PID))
			if err != nil {
				continue
			}
			bins := m.options.RuntimeBins
			if m.options.Discover {
				if filepath.Base(p.Executable) != "wineserver" {
					continue
				}
				bins = []string{filepath.Dir(p.Executable)}
			}
			for _, v := range bins {
				trusted, err := os.Stat(filepath.Join(v, "wineserver"))
				if err == nil && os.SameFile(actual, trusted) {
					if broker != nil {
						a.Application = nil
						a.Association = nil
						a.setReason(ReasonRuntimeOwnerAmbiguous, "multiple configured Wine brokers hold this socket")
						return nil, "", a
					}
					broker = p
					bin = v
					break
				}
			}
		}
	}
	if broker == nil {
		return nil, "", a
	}
	return broker, bin, a
}

// sessionResolve attributes a broker-held socket through its runtime session. The slot
// is taken first; m.mu only guards lookup and pins and is never held while a
// session is set up or a census runs.
func (m *WineObservers) sessionResolve(f Flow, a Attribution, broker *Process, bin string, wait bool) (Attribution, bool) {
	return m.sessionResolvePriority(f, a, broker, bin, wait, false)
}
func (m *WineObservers) sessionResolvePriority(f Flow, a Attribution, broker *Process, bin string, wait, priority bool, grouped ...*wineGroupSession) (Attribution, bool) {
	m.admissionDemand.Add(1)
	defer m.admissionDemand.Add(-1)
	fail := func(reason string) Attribution {
		a.Application = nil
		a.Association = nil
		a.Status = "unidentified"
		a.setReason(ReasonRuntimeObserverUnavailable, "Wine owner observer: "+reason)
		return a
	}
	if a.renewalPhase != nil {
		a.renewalPhase.SlotRequested = renewalBootNow()
	}
	waitStarted := time.Now()
	slot := diagnostics.Begin(diagnostics.WineSlotWait)
	release, ok := m.acquireCensus(wait, priority)
	slot.End()
	if !ok {
		return Attribution{}, false
	}
	defer release()
	if a.renewalPhase != nil {
		a.renewalPhase.SlotAcquired = renewalBootNow()
		defer func() { a.renewalPhase.SessionDone = renewalBootNow() }()
	}
	if priority {
		waitNS := uint64(time.Since(waitStarted))
		m.renewalWaitNS.Add(waitNS)
		renewalMaximum(&m.renewalWaitMax, waitNS)
		serviceStarted := time.Now()
		defer func() {
			elapsed := uint64(time.Since(serviceStarted))
			m.renewalServiceNS.Add(elapsed)
			m.renewalCensusCount.Add(1)
			renewalMaximum(&m.renewalServiceMax, elapsed)
		}()
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fail("stopped"), true
	}
	// Expired generations never donate evidence or revive a stopped collector.
	var retired []*observedWine
	for k, s := range m.sessions {
		exited := false
		select {
		case <-s.ready:
			exited = s.table != nil && s.table.lifecycleExited()
		default:
		}
		if exited || !InstanceRunning(s.broker.PID, s.broker.Start) {
			retired = append(retired, m.retireLocked(k, s)...)
		}
	}
	defer cleanupAll(retired)
	key := fmt.Sprintf("%d:%s:%s:%s", broker.PID, broker.Start, broker.ExecutableRevision, broker.Application.Prefix)
	record := m.sessions[key]
	setup := record == nil
	if setup {
		if len(m.sessions) >= 32 {
			m.mu.Unlock()
			return fail("session limit"), true
		}
		record = &observedWine{broker: *broker, ready: make(chan struct{})}
		m.sessions[key] = record
	}
	record.pins++
	m.mu.Unlock()
	result, ok := m.useSession(f, a, record, broker, bin, setup, wait, fail, grouped...)
	// A session retired by Close or prune while in use never donates evidence.
	if m.unpin(record) && ok {
		if len(grouped) > 0 {
			grouped[0].retired = true
		}
		return fail("session retired during census"), true
	}
	return result, ok
}

func (m *WineObservers) useSession(f Flow, initial Attribution, record *observedWine, broker *Process, bin string, setup, wait bool, fail func(string) Attribution, grouped ...*wineGroupSession) (Attribution, bool) {
	sessionWait := diagnostics.Begin(diagnostics.WineSessionWait)
	defer func() { sessionWait.End() }()
	if setup {
		if m.setupSession != nil {
			m.setupSession(record, broker, bin)
		} else {
			m.setup(record, broker, bin)
		}
	} else if wait {
		<-record.ready
	} else {
		select {
		case <-record.ready:
		default:
			return Attribution{}, false
		}
	}
	if record.resolve == nil {
		return fail(record.failure), true
	}
	sessionWait.End()
	sessionWait = diagnostics.Span{}
	if len(grouped) > 0 && record.table != nil {
		return grouped[0].resolve(record.table), true
	}
	return record.resolve(f, initial, wait)
}

// setup starts the census helper for one broker generation outside m.mu and
// publishes the table or failure to every waiter.
func (m *WineObservers) setup(record *observedWine, broker *Process, bin string) {
	defer close(record.ready)
	fail := func(reason string) { record.failure = reason }
	// Discover every broker build. The helper negotiates the supported census
	// contract after joining this exact generation; a filename is not authority.
	version := ""
	runner, err := observerRunner(bin)
	if err != nil {
		fail(err.Error())
		return
	}
	session := RuntimeSession{Broker: *broker, Runner: runner, Build: fileHash(filepath.Join(bin, "wineserver"))}
	if !session.current() {
		fail("broker generation changed")
		return
	}
	// Only rendezvous paths and bounded boolean synchronization settings are copied. No inherited preload, DLL search path,
	// shell command, launcher arguments or root environment enters the Wine child.
	tmp := "/tmp"
	runtime := ""
	var syncEnv []string
	for _, pair := range strings.Split(string(readBound(fmt.Sprintf("/proc/%d/environ", broker.PID), 1<<20)), "\x00") {
		k, v, ok := strings.Cut(pair, "=")
		if ok && (v == "0" || v == "1") && (k == "WINEESYNC" || k == "WINEFSYNC" || k == "WINE_DISABLE_FAST_SYNC" || k == "WINE_NTSYNC") {
			syncEnv = append(syncEnv, k+"="+v)
		}
		if ok && filepath.IsAbs(v) {
			if k == "TMPDIR" {
				tmp = v
			}
			if k == "XDG_RUNTIME_DIR" {
				runtime = v
			}
		}
	}
	env := []string{"PATH=/usr/bin:/bin", "WINEPREFIX=" + broker.Application.Prefix, "WINESERVER=/usr/bin/false", "WINEDEBUG=-all", "WINELOADERNOEXEC=1", "WINEDLLOVERRIDES=mscoree,mshtml=", "DISPLAY=", "WAYLAND_DISPLAY=", "TMPDIR=" + tmp, "HOME=" + m.options.Scratch, "XDG_CACHE_HOME=" + m.options.Scratch, "XDG_CONFIG_HOME=" + m.options.Scratch, "XDG_DATA_HOME=" + m.options.Scratch}
	env = append(env, syncEnv...)
	if runtime != "" {
		env = append(env, "XDG_RUNTIME_DIR="+runtime)
	}
	var credential *syscall.Credential
	if uint32(os.Geteuid()) != broker.UID {
		if os.Geteuid() != 0 {
			fail("observer cannot change user")
			return
		}
		st, err := os.Stat(fmt.Sprintf("/proc/%d", broker.PID))
		if err != nil {
			fail("broker exited")
			return
		}
		credential = &syscall.Credential{Uid: broker.UID, Gid: st.Sys().(*syscall.Stat_t).Gid, Groups: []uint32{}}
	}
	var namespace *wineNamespace
	if broker.MountNS != SelfMountNS() {
		var er error
		namespace, er = prepareWineNamespace(*broker, session.Runner, m.options.Helper, m.options.Scratch, runtime)
		if er != nil {
			fail(er.Error())
			return
		}
		defer namespace.close()
		if namespace.removeScratch {
			record.scratch = namespace
		}
		for i, pair := range env {
			k, _, _ := strings.Cut(pair, "=")
			if k == "HOME" || k == "XDG_CACHE_HOME" || k == "XDG_CONFIG_HOME" || k == "XDG_DATA_HOME" {
				env[i] = k + "=" + namespace.scratch
			}
		}
	}
	w, err := newWineTableConfigured(session.Runner, m.options.Helper, filepath.Join(bin, "wineserver"), broker.Application.Prefix, version, env, credential, namespace)
	if err != nil {
		fail(err.Error())
		return
	}
	w.session = &session
	w.startupDeadline = time.Now().Add(4 * time.Second)
	if _, err = w.snapshot("tcp"); err != nil {
		w.Close()
		fail(err.Error())
		return
	}
	if !session.current() || !w.sameServer(broker) {
		w.Close()
		fail("helper did not join the selected existing broker")
		return
	}
	session.Version = w.version
	session.Supported = true
	w.startupDeadline = time.Time{}
	record.table = w
	record.resolve = func(f Flow, initial Attribution, wait bool) (Attribution, bool) {
		return w.resolveInitial(f, initial, wait)
	}
}

// Lab-only CLI boundary; production configuration is explicit root startup input.
func WorkspaceObserverScratch(path string) (string, error) { return workspacePath(path) }

// RenewalStatus reports cumulative wall time, not CPU. Post-slot time includes
// session/table serialization and verification. Total includes initial discovery.
func (m *WineObservers) RenewalStatus() map[string]any {
	rows, overwritten := m.renewalPhases.snapshot()
	ordinary, ordinaryLost := m.ordinaryPhases.snapshot()
	return map[string]any{"pending_dispatch_stored": m.pendingDispatchStored.Load(), "pending_dispatch_used": m.pendingDispatchUsed.Load(), "ordinary_phase_timeline": ordinary, "ordinary_phase_overwritten": ordinaryLost, "phase_timeline": rows, "phase_timeline_overwritten": overwritten, "reserved": m.queueCensus != nil, "completed": m.renewalCount.Load(),
		"total_wall_ns": m.renewalTotalNS.Load(), "slot_wait_wall_ns": m.renewalWaitNS.Load(),
		"post_slot_wall_ns": m.renewalServiceNS.Load(), "census_completed": m.renewalCensusCount.Load(), "max_slot_wait_wall_ns": m.renewalWaitMax.Load(), "max_post_slot_wall_ns": m.renewalServiceMax.Load()}
}

// acquireCensus retains the total two-slot bound. In prototype reservation mode,
// ordinary censuses hold at most one slot; fresh renewals can use either slot.
// Nonwaiting callers never retain a partial admission on failure.
func (m *WineObservers) acquireCensus(wait, priority bool) (func(), bool) {
	ordinary := !priority && m.queueCensus != nil
	if ordinary {
		if wait {
			m.queueCensus <- struct{}{}
		} else {
			select {
			case m.queueCensus <- struct{}{}:
			default:
				return nil, false
			}
		}
	}
	if wait {
		m.census <- struct{}{}
	} else {
		select {
		case m.census <- struct{}{}:
		default:
			if ordinary {
				<-m.queueCensus
			}
			return nil, false
		}
	}
	return func() {
		<-m.census
		if ordinary {
			<-m.queueCensus
		}
	}, true
}

func renewalMaximum(dst *atomic.Uint64, value uint64) {
	for old := dst.Load(); value > old; old = dst.Load() {
		if dst.CompareAndSwap(old, value) {
			return
		}
	}
}
