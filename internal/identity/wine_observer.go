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
	scratch string
}
type WineObservers struct {
	mu       sync.Mutex
	options  WineObserverOptions
	sessions map[string]*observedWine
	closed   bool
}

func NewWineObservers(o WineObserverOptions) (*WineObservers, error) {
	if o.Helper == "" || !filepath.IsAbs(o.Helper) || !filepath.IsAbs(o.Scratch) || len(o.RuntimeBins) == 0 || len(o.RuntimeBins) > 4 || len(o.Prefixes) == 0 || len(o.Prefixes) > 32 {
		return nil, fmt.Errorf("explicit helper, scratch, 1..4 trusted runtime bins and 1..32 authorized prefixes required")
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
	return &WineObservers{options: o, sessions: map[string]*observedWine{}}, nil
}
func (m *WineObservers) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, s := range m.sessions {
		if s.table != nil {
			s.table.Close()
		}
		if s.scratch != "" {
			os.RemoveAll(s.scratch)
		}
	}
	m.sessions = nil
}
func (m *WineObservers) Resolve(f Flow) Attribution {
	a := Resolve(f)
	var broker *Process
	var bin string
	for i := range a.Owners {
		p := &a.Owners[i]
		if p.UID != m.options.UID || p.Application.Prefix == "" || p.NetNS != NetNS() {
			continue
		}
		prefixAllowed := false
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
		for _, v := range m.options.RuntimeBins {
			trusted, err := os.Stat(filepath.Join(v, "wineserver"))
			if err == nil && os.SameFile(actual, trusted) {
				if broker != nil {
					a.Application = nil
					a.Association = nil
					a.Reason = "multiple configured Wine brokers hold this socket"
					return a
				}
				broker = p
				bin = v
				break
			}
		}
	}
	if broker == nil {
		return a
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fail := func(reason string) Attribution {
		a.Application = nil
		a.Association = nil
		a.Status = "unidentified"
		a.Reason = "Wine owner observer: " + reason
		return a
	}
	if m.closed {
		return fail("stopped")
	}
	// Expired generations never donate evidence or revive a stopped collector.
	for k, s := range m.sessions {
		if !InstanceRunning(s.broker.PID, s.broker.Start) {
			if s.table != nil {
				s.table.Close()
			}
			if s.scratch != "" {
				os.RemoveAll(s.scratch)
			}
			delete(m.sessions, k)
		}
	}
	key := fmt.Sprintf("%d:%s:%s:%s", broker.PID, broker.Start, broker.ExecutableRevision, broker.Application.Prefix)
	if s := m.sessions[key]; s != nil {
		if s.table == nil {
			return fail(s.failure)
		}
		return s.table.Resolve(f)
	}
	if len(m.sessions) >= 32 {
		return fail("session limit")
	}
	record := &observedWine{broker: *broker}
	m.sessions[key] = record
	stop := func(reason string) Attribution { record.failure = reason; return fail(reason) }
	version := supportedBrokers[fileHash(fmt.Sprintf("/proc/%d/exe", broker.PID))]
	if version == "" {
		return stop("unsupported broker build; no executable identity inferred")
	}
	session := RuntimeSession{Broker: *broker, Runner: filepath.Join(bin, "wine"), Build: fileHash(filepath.Join(bin, "wineserver")), Version: version, Supported: true}
	if !session.current() {
		return stop("broker generation changed")
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
			return stop("observer cannot change user")
		}
		st, err := os.Stat(fmt.Sprintf("/proc/%d", broker.PID))
		if err != nil {
			return stop("broker exited")
		}
		credential = &syscall.Credential{Uid: broker.UID, Gid: st.Sys().(*syscall.Stat_t).Gid, Groups: []uint32{}}
	}
	var namespace *wineNamespace
	if broker.MountNS != SelfMountNS() {
		var er error
		namespace, er = prepareWineNamespace(*broker, session.Runner, m.options.Helper, m.options.Scratch, runtime)
		if er != nil {
			return stop(er.Error())
		}
		defer namespace.close()
		if namespace.removeScratch {
			record.scratch = namespace.scratch
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
		return stop(err.Error())
	}
	w.session = &session
	w.startupDeadline = time.Now().Add(4 * time.Second)
	if _, err = w.snapshot("tcp"); err != nil || !session.current() || !w.sameServer(broker) {
		w.Close()
		return stop("helper did not join the selected existing broker")
	}
	w.startupDeadline = time.Time{}
	record.table = w
	return w.Resolve(f)
}

// Lab-only CLI boundary; production configuration is explicit root startup input.
func WorkspaceObserverScratch(path string) (string, error) { return workspacePath(path) }
