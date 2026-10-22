package identity

// Explicit daemon startup configuration authorizes observation, never a rule.
// Helpers run as the selected desktop UID, not with daemon privileges.
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type WineObserverOptions struct {
	Discover    bool
	Helper      string
	RuntimeBins []string
	Prefixes    []string
	UID         uint32
	Scratch     string
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
	resolve  func(f Flow, wait bool) (Attribution, bool)
	released bool
}
type WineObservers struct {
	mu       sync.Mutex // guards sessions/closed/pins only; never held across setup or a census
	options  WineObserverOptions
	sessions map[string]*observedWine
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
	return &WineObservers{options: o, sessions: map[string]*observedWine{}, census: make(chan struct{}, WineCensusLimit)}, nil
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

// TryResolve never waits for a census slot, a session being set up, or a table
// held by another census: it reports false instead. false is not evidence and
// carries no verdict; the caller resolves later with Resolve or drops explicitly.
// Sockets without a configured Wine broker never need a census and report true.
func (m *WineObservers) TryResolve(f Flow) (Attribution, bool) {
	return m.resolve(f, false)
}

func (m *WineObservers) resolve(f Flow, wait bool) (Attribution, bool) {
	a := Resolve(f)
	var broker *Process
	var bin string
	for i := range a.Owners {
		p := &a.Owners[i]
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
					a.Reason = "multiple configured Wine brokers hold this socket"
					return a, true
				}
				broker = p
				bin = v
				break
			}
		}
	}
	if broker == nil {
		return a, true
	}
	return m.sessionResolve(f, a, broker, bin, wait)
}

// sessionResolve attributes a broker-held socket through its runtime session. The slot
// is taken first; m.mu only guards lookup and pins and is never held while a
// session is set up or a census runs.
func (m *WineObservers) sessionResolve(f Flow, a Attribution, broker *Process, bin string, wait bool) (Attribution, bool) {
	fail := func(reason string) Attribution {
		a.Application = nil
		a.Association = nil
		a.Status = "unidentified"
		a.Reason = "Wine owner observer: " + reason
		return a
	}
	if wait {
		m.census <- struct{}{}
	} else {
		select {
		case m.census <- struct{}{}:
		default:
			return Attribution{}, false
		}
	}
	defer func() { <-m.census }()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return fail("stopped"), true
	}
	// Expired generations never donate evidence or revive a stopped collector.
	var retired []*observedWine
	for k, s := range m.sessions {
		if !InstanceRunning(s.broker.PID, s.broker.Start) {
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
	result, ok := m.useSession(f, record, broker, bin, setup, wait, fail)
	// A session retired by Close or prune while in use never donates evidence.
	if m.unpin(record) && ok {
		return fail("session retired during census"), true
	}
	return result, ok
}

func (m *WineObservers) useSession(f Flow, record *observedWine, broker *Process, bin string, setup, wait bool, fail func(string) Attribution) (Attribution, bool) {
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
	return record.resolve(f, wait)
}

// setup starts the census helper for one broker generation outside m.mu and
// publishes the table or failure to every waiter.
func (m *WineObservers) setup(record *observedWine, broker *Process, bin string) {
	defer close(record.ready)
	fail := func(reason string) { record.failure = reason }
	// Discover every broker build. The helper negotiates the supported census
	// contract after joining this exact generation; a filename is not authority.
	version := ""
	session := RuntimeSession{Broker: *broker, Runner: filepath.Join(bin, "wine"), Build: fileHash(filepath.Join(bin, "wineserver"))}
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
	env := []string{"PATH=/usr/bin:/bin", "WINEPREFIX=" + broker.Application.Prefix, "WINESERVER=/usr/bin/false", "WINEDEBUG=-all", "WINEDLLOVERRIDES=mscoree,mshtml=", "DISPLAY=", "WAYLAND_DISPLAY=", "TMPDIR=" + tmp, "HOME=" + m.options.Scratch, "XDG_CACHE_HOME=" + m.options.Scratch, "XDG_CONFIG_HOME=" + m.options.Scratch, "XDG_DATA_HOME=" + m.options.Scratch}
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
	record.resolve = func(f Flow, wait bool) (Attribution, bool) {
		if wait {
			return w.Resolve(f), true
		}
		return w.tryResolve(f)
	}
}

// Lab-only CLI boundary; production configuration is explicit root startup input.
func WorkspaceObserverScratch(path string) (string, error) { return workspacePath(path) }
