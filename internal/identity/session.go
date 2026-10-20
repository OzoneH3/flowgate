package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RuntimeSession is a broker generation, not a game or launch-group identity.
type RuntimeSession struct {
	HelperPeers    int     `json:"helper_peer_count"`
	ID             string  `json:"id"`
	Broker         Process `json:"broker"`
	Runner         string  `json:"runner"`
	Build          string  `json:"broker_sha256"`
	Version        string  `json:"version"`
	Supported      bool    `json:"supported"`
	HelperAttached bool    `json:"helper_peer_detected"`
	Reason         string  `json:"reason"`
}

var supportedBrokers = map[string]string{
	"c9a0c615ddd8ba168b9fdf5efaaa4769cb2369782c766b579157ed0a5520977e": "11.20",
	"b724233cd9e71f529c0ae30c090c862ac0d0ecfe760e604a2e1cdae160ab9fa6": "11.19",
	"3f84ad1bc5116a82ec54ee15588f000dbc5d570c9c77c6007d82545d375fd792": "11.0",
}

func fileHash(path string) string {
	f, e := os.Open(path)
	if e != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 32<<20))
	if e != nil || n == 32<<20 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (s RuntimeSession) current() bool {
	p, e := Inspect(s.Broker.PID)
	return e == nil && p.Start == s.Broker.Start && p.ExecutableRevision == s.Broker.ExecutableRevision && p.UID == s.Broker.UID && p.NetNS == s.Broker.NetNS && p.MountNS == s.Broker.MountNS && p.Application.Prefix == s.Broker.Application.Prefix
}

// DiscoverRuntimes only reads proc and files. Runtime directories are explicitly
// trusted CLI input, never taken from application environment/command lines.
func DiscoverRuntimes(bins []string, helper string) ([]RuntimeSession, error) {
	if len(bins) == 0 || len(bins) > 4 {
		return nil, fmt.Errorf("select 1..4 trusted runtime bin directories")
	}
	deadline := time.Now().Add(5 * time.Second)
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	out := []RuntimeSession{}
	seen := map[int]bool{}
	for _, bin := range bins {
		bin, e = filepath.EvalSymlinks(bin)
		if e != nil {
			return nil, e
		}
		trusted, e := os.Stat(filepath.Join(bin, "wineserver"))
		if e != nil {
			return nil, e
		}
		build := fileHash(filepath.Join(bin, "wineserver"))
		version := supportedBrokers[build]
		for _, entry := range entries {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("runtime discovery deadline")
			}
			pid, e := strconv.Atoi(entry.Name())
			if e != nil || seen[pid] {
				continue
			}
			actual, e := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
			if e != nil || !os.SameFile(trusted, actual) {
				continue
			}
			p, e := Inspect(pid)
			if e != nil {
				continue
			}
			seen[pid] = true
			s := RuntimeSession{Broker: p, Runner: filepath.Join(bin, "wine"), Build: build, Version: version, Supported: version != "", Reason: "read-only broker executable/build and process-generation observation"}
			s.ID = digest(fmt.Sprintf("%d:%s:%s:%s:%s", pid, p.Start, p.NetNS, p.Application.Prefix, p.ExecutableRevision))
			if p.Application.Prefix == "" || p.NetNS != NetNS() || p.MountNS != link("/proc/self/ns/mnt") {
				s.Supported = false
				s.Reason = "missing prefix or foreign namespaces"
			}
			if version == "" {
				s.Reason = "unvalidated broker build"
			}
			if helper != "" {
				helperPath, _ := filepath.Abs(helper)
				helperPath, _ = filepath.EvalSymlinks(helperPath)
				w := WineTable{helper: helperPath, prefix: p.Application.Prefix}
				s.HelperPeers = w.helperPeers(&p)
				s.HelperAttached = s.HelperPeers > 0
				if s.HelperPeers < 0 {
					s.Supported = false
					s.Reason = "helper peer visibility unavailable"
				}
			}
			out = append(out, s)
			if len(out) > 32 {
				return nil, fmt.Errorf("discovery session limit exceeded")
			}
		}
	}
	return out, nil
}

type RuntimeObservers struct {
	sessions  []RuntimeSession
	observers []*WineTable
}

func (m *RuntimeObservers) Close() {
	for _, w := range m.observers {
		w.Close()
	}
}
func workspacePath(path string) (string, error) {
	root, e := filepath.Abs(".workspace")
	if e == nil {
		root, e = filepath.EvalSymlinks(root)
	}
	if e != nil {
		return "", e
	}
	path, e = filepath.Abs(path)
	if e == nil {
		path, e = filepath.EvalSymlinks(path)
	}
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(root, path)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("attachment is restricted to selected workspace paths")
	}
	return path, nil
}
func safeAttachmentUID(uid uint32) bool {
	if uid != uint32(os.Geteuid()) {
		return false
	}
	if uid != 0 {
		return true
	}
	// UID zero is allowed only when it maps to an unprivileged host UID in the lab.
	fields := strings.Fields(string(readBound("/proc/self/uid_map", 4096)))
	return len(fields) == 3 && fields[0] == "0" && fields[1] != "0" && fields[2] == "1"
}
func AttachRuntimes(prefixes, bins []string, helper string) (*RuntimeObservers, error) {
	if len(prefixes) == 0 || len(prefixes) > 4 {
		return nil, fmt.Errorf("select 1..4 workspace prefixes")
	}
	helper, e := workspacePath(helper)
	if e != nil {
		return nil, e
	}
	sessions, e := DiscoverRuntimes(bins, helper)
	if e != nil {
		return nil, e
	}
	m := &RuntimeObservers{}
	deadline := time.Now().Add(10 * time.Second)
	seen := map[string]bool{}
	for _, prefix := range prefixes {
		if time.Now().After(deadline) {
			m.Close()
			return nil, fmt.Errorf("runtime attachment deadline")
		}
		prefix, e = workspacePath(prefix)
		if e != nil {
			m.Close()
			return nil, e
		}
		if seen[prefix] {
			m.Close()
			return nil, fmt.Errorf("duplicate prefix")
		}
		seen[prefix] = true
		candidates := []RuntimeSession{}
		for _, s := range sessions {
			if s.Broker.Application.Prefix == prefix {
				candidates = append(candidates, s)
			}
		}
		if len(candidates) != 1 {
			m.Close()
			return nil, fmt.Errorf("prefix must have exactly one already-running broker: %s", prefix)
		}
		s := candidates[0]
		if !s.Supported || s.HelperAttached || !safeAttachmentUID(s.Broker.UID) || !s.current() {
			m.Close()
			return nil, fmt.Errorf("session unsupported, replaced, already attached or not owned by caller: %s", s.ID)
		}
		// Minimal explicit environment plus the server's temporary rendezvous directory.
		// No shell, application arguments, LD_PRELOAD or arbitrary environment is executed.
		env := []string{"PATH=/usr/bin:/bin", "WINEPREFIX=" + prefix, "WINEDEBUG=-all", "WINESERVER=/usr/bin/false", "WINEDLLOVERRIDES=mscoree,mshtml=", "DISPLAY=", "WAYLAND_DISPLAY="}
		haveTmp := false
		for _, pair := range strings.Split(string(readBound(fmt.Sprintf("/proc/%d/environ", s.Broker.PID), 1<<20)), "\x00") {
			k, v, ok := strings.Cut(pair, "=")
			if ok && (k == "TMPDIR" || k == "XDG_RUNTIME_DIR") {
				if p, err := workspacePath(v); err == nil {
					env = append(env, k+"="+p)
					if k == "TMPDIR" {
						haveTmp = true
					}
				}
			}
		}
		if !haveTmp {
			m.Close()
			return nil, fmt.Errorf("selected broker needs a workspace TMPDIR for attachment")
		}
		root, _ := filepath.Abs(".workspace")
		env = append(env, "XDG_CACHE_HOME="+root+"/cache", "XDG_CONFIG_HOME="+root+"/config", "XDG_DATA_HOME="+root+"/data")
		w, err := newWineTable(s.Runner, helper, s.Broker.Executable, prefix, s.Version, env)
		if err != nil {
			m.Close()
			return nil, err
		}
		w.session = &s
		w.startupDeadline = deadline
		// One bounded attempt. Never claim success if Wine joined/created another server.
		_, err = w.snapshot("tcp")
		if err != nil || time.Now().After(deadline) || !s.current() || !w.sameServer(&s.Broker) {
			w.Close()
			m.Close()
			return nil, fmt.Errorf("helper did not join selected live broker: %v", err)
		}
		w.startupDeadline = time.Time{}
		m.sessions = append(m.sessions, s)
		m.observers = append(m.observers, w)
	}
	return m, nil
}
func (m *RuntimeObservers) Sessions() []RuntimeSession {
	out := append([]RuntimeSession(nil), m.sessions...)
	for i := range out {
		out[i].HelperAttached = true
		out[i].HelperPeers = 1
	}
	return out
}
func (m *RuntimeObservers) Resolve(f Flow) Attribution {
	a := Resolve(f)
	selected := -1
	for _, p := range a.Owners {
		for i, s := range m.sessions {
			if p.Application.Prefix == s.Broker.Application.Prefix {
				if selected >= 0 && selected != i {
					a.Application = nil
					a.Association = nil
					a.Reason = "owners span attached runtime sessions"
					return a
				}
				selected = i
			}
		}
	}
	if selected < 0 {
		return a
	}
	return m.observers[selected].Resolve(f)
}

// Explicit recovery creates a new observer; no background retry resurrects state.
