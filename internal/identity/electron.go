package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// A shared runtime's basename, process chain, argv and readable bundle metadata
// do not prove that it executes that bundle. The explicitly best-effort contract
// below combines these observations; it must not be described as code attestation.
// Unresolved and legacy hints never grant application-wide runtime access.

var electronRuntimeName = regexp.MustCompile(`^electron[0-9]*$`)

// IsElectronRuntime is a conservative shared-runtime name hint, not proof of
// Electron execution. Renamed bundled applications retain their own executable.
func IsElectronRuntime(exe string) bool {
	return electronRuntimeName.MatchString(filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
}

// HostedStep is one observed process of the chain from the socket owner to
// the runtime's main process.
type HostedStep struct {
	PID   int    `json:"pid"`
	Start string `json:"start_ticks"`
	Type  string `json:"type"` // Electron --type, "main" for the main process
}

// Hosted describes an application hosted by a shared runtime (Electron).
type Hosted struct {
	State       string       `json:"state"` // best-effort or unverified; legacy records may say verified
	Runtime     string       `json:"runtime"`
	Bundle      string       `json:"bundle,omitempty"`
	PackageName string       `json:"package_name,omitempty"`
	ProductName string       `json:"product_name,omitempty"`
	Version     string       `json:"version,omitempty"`
	Integrity   string       `json:"integrity,omitempty"` // asar package.json SHA-256 verified | not provided
	Chain       []HostedStep `json:"chain,omitempty"`
	Reason      string       `json:"reason"`
	matched     bool
	revision    string
}

const maxElectronChain = 6

// electronUnsafe are main-process options that let other code run inside the
// runtime (Node mode, inspector, preloaded modules): the bundle no longer
// determines what runs.
var electronUnsafe = []string{"--inspect", "--inspect-brk", "--remote-debugging-port", "--remote-debugging-pipe", "--require", "-r", "--js-flags", "--no-sandbox-and-elevated"}

func cmdlineArgs(base string) []string {
	raw := strings.TrimRight(string(readBound(base+"/cmdline", 65536)), "\x00")
	if raw == "" {
		return nil
	}
	args := strings.Split(raw, "\x00")
	// Chromium rewrites argv in place as one space-joined string. Split it only
	// when the first token is exactly the process's own executable path; a
	// bundle path containing spaces then fails verification instead of being guessed.
	if len(args) == 1 && strings.Contains(raw, " ") {
		exe := strings.TrimSuffix(link(base+"/exe"), " (deleted)")
		if f := strings.Fields(raw); len(f) > 1 && f[0] == exe {
			return f
		}
	}
	return args
}

func electronType(args []string) string {
	for _, a := range args[min(1, len(args)):] {
		if v, ok := strings.CutPrefix(a, "--type="); ok {
			return v
		}
	}
	return "main"
}

type procFacts struct {
	start, exe, mountNS string
	parent              int
	uid                 uint32
}

func readFacts(pid int) (procFacts, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	start, parent, err := processStat(base)
	if err != nil {
		return procFacts{}, err
	}
	st, err := os.Stat(base)
	if err != nil {
		return procFacts{}, err
	}
	return procFacts{start: start, parent: parent, exe: link(base + "/exe"), mountNS: link(base + "/ns/mnt"), uid: st.Sys().(*syscall.Stat_t).Uid}, nil
}

// ResolveElectronApp gathers a claimed bundle and a generation-checked process
// chain for a best-effort application match. It does not attest application code.
func ResolveElectronApp(pid int, start string) *Hosted {
	h := &Hosted{State: "unverified"}
	first, err := readFacts(pid)
	if err != nil || first.start != start {
		h.Reason = "the process changed while it was inspected"
		return h
	}
	h.Runtime = strings.TrimSuffix(first.exe, " (deleted)")
	cur, facts := pid, first
	var main int
	for i := 0; i < maxElectronChain; i++ {
		args := cmdlineArgs(fmt.Sprintf("/proc/%d", cur))
		if len(args) == 0 {
			h.Reason = fmt.Sprintf("the command line of PID %d is unavailable", cur)
			return h
		}
		t := electronType(args)
		h.Chain = append(h.Chain, HostedStep{PID: cur, Start: facts.start, Type: t})
		if t == "main" {
			main = cur
			break
		}
		parent, err := readFacts(facts.parent)
		switch {
		case facts.parent <= 1 || err != nil:
			h.Reason = fmt.Sprintf("the parent of %s process %d is gone; its Electron main process cannot be verified", t, cur)
			return h
		case parent.exe != first.exe:
			h.Reason = fmt.Sprintf("the parent of %s process %d runs %s, not the same Electron runtime", t, cur, filepath.Base(parent.exe))
			return h
		case parent.uid != first.uid || parent.mountNS != first.mountNS:
			h.Reason = fmt.Sprintf("the parent of PID %d belongs to another user or mount namespace", cur)
			return h
		}
		cur, facts = facts.parent, parent
	}
	if main == 0 {
		h.Reason = "no Electron main process within the verified parent chain"
		return h
	}
	base := fmt.Sprintf("/proc/%d", main)
	args := cmdlineArgs(base)
	if len(args) == 0 {
		h.Reason = "main process command line became unavailable"
		return h
	}
	for _, a := range args[1:] {
		name, _, _ := strings.Cut(a, "=")
		for _, u := range electronUnsafe {
			if name == u {
				h.Reason = fmt.Sprintf("the Electron main process %d was started with %s; other code may run inside it", main, name)
				return h
			}
		}
	}
	environment := readBound(base+"/environ", 1<<20)
	if environment == nil {
		h.Reason = "main process environment is unavailable"
		return h
	}
	for _, v := range strings.Split(string(environment), "\x00") {
		if strings.HasPrefix(v, "NODE_OPTIONS=") && v != "NODE_OPTIONS=" {
			h.Reason = "NODE_OPTIONS may load unrelated code; application matching unavailable"
			return h
		}
		if strings.HasPrefix(v, "ELECTRON_RUN_AS_NODE=") && v != "ELECTRON_RUN_AS_NODE=" && v != "ELECTRON_RUN_AS_NODE=0" {
			h.Reason = fmt.Sprintf("the Electron main process %d runs in Node mode (ELECTRON_RUN_AS_NODE)", main)
			return h
		}
	}
	app := ""
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			app = a
			break
		}
	}
	if app == "" {
		h.Reason = fmt.Sprintf("the Electron main process %d names no application bundle", main)
		return h
	}
	if !filepath.IsAbs(app) {
		app = filepath.Join(link(base+"/cwd"), app)
	}
	app = filepath.Clean(app)
	// Resolve aliases only when the path resolves to the same visible file.
	// A foreign mount namespace with an inaccessible canonical path stays unknown.
	canonical, canonicalErr := filepath.EvalSymlinks(base + "/root" + app)
	if canonicalErr != nil {
		h.Reason = "application path not found or cannot be resolved"
		return h
	}
	visible, visibleErr := os.Stat(base + "/root" + canonical)
	original, originalErr := os.Stat(base + "/root" + app)
	if visibleErr != nil || originalErr != nil || !os.SameFile(visible, original) {
		h.Reason = "application canonical path is ambiguous in this namespace"
		return h
	}
	app = canonical
	h.Bundle = app
	// The bundle as the main process sees it (its mount namespace).
	host := base + "/root" + app
	packageHost := host
	script := false
	if st, err := os.Stat(host); err == nil && st.Mode().IsRegular() && (strings.HasSuffix(host, ".js") || strings.HasSuffix(host, ".mjs") || strings.HasSuffix(host, ".cjs")) {
		script = true
		packageHost = filepath.Dir(host)
	}
	pkg, revision, integrity, err := cachedBundlePackage(packageHost)
	if script {
		revision = digest(revision + "|" + stamp(host))
		integrity = "script with adjacent package.json (best-effort association)"
	}
	if err != nil {
		h.Reason = fmt.Sprintf("application bundle %s: %v", app, err)
		return h
	}
	var meta struct {
		Name        string `json:"name"`
		ProductName string `json:"productName"`
		Version     string `json:"version"`
	}
	if json.Unmarshal(pkg, &meta) != nil || strings.TrimSpace(meta.Name) == "" {
		h.Reason = fmt.Sprintf("application bundle %s has no valid package.json name", app)
		return h
	}
	// No PID of the chain may have been reused meanwhile.
	for _, s := range h.Chain {
		f, err := readFacts(s.PID)
		if err != nil || f.start != s.Start || f.exe != first.exe || f.uid != first.uid || f.mountNS != first.mountNS {
			h.Reason = fmt.Sprintf("PID %d changed while its chain was verified", s.PID)
			return h
		}
	}
	h.PackageName = clip(meta.Name)
	h.ProductName = clip(meta.ProductName)
	h.Version = clip(meta.Version)
	h.Integrity = integrity
	h.revision = revision
	// Only known runtime capabilities and a fresh, corroborated candidate may
	// mint the new best-effort identity. Legacy verified labels stay refused.
	eligible := electronRuntimeCapable(fmt.Sprintf("/proc/%d/exe", pid))
	for _, step := range h.Chain {
		stepArgs := cmdlineArgs(fmt.Sprintf("/proc/%d", step.PID))
		if step.Type == "utility" && !hasArgument(stepArgs, "--utility-sub-type=network.mojom.NetworkService") {
			eligible = false
		}
		if step.Type != "main" && step.Type != "utility" && step.Type != "renderer" && step.Type != "zygote" && step.Type != "gpu-process" {
			eligible = false
		}
	}
	if strings.HasSuffix(host, ".asar") && !openArchiveMatches(main, host) {
		eligible = false
	}
	// Recheck package/entry after FD inspection, including package edits in an
	// unchanged directory (directory mtime alone is not a package revision).
	_, checkRevision, _, checkErr := cachedBundlePackage(packageHost)
	if script {
		checkRevision = digest(checkRevision + "|" + stamp(host))
	}
	if checkErr != nil || checkRevision != revision {
		eligible = false
	}
	for _, step := range h.Chain {
		f, err := readFacts(step.PID)
		if err != nil || f.start != step.Start || f.exe != first.exe || f.uid != first.uid || f.mountNS != first.mountNS {
			eligible = false
		}
	}
	if eligible {
		h.State, h.matched = "best-effort", true
		h.Reason = "Best-effort application match from runtime capability, generation-checked process chain and canonical package entry; not verified code execution"
		return h
	}
	h.Reason = fmt.Sprintf("process %d names bundle %s; command line and package metadata do not verify bundle execution", main, app)
	if main != pid {
		h.Reason = fmt.Sprintf("%s process %d → %s (parent chain and start times observed)", h.Chain[0].Type, pid, h.Reason)
	}
	return h
}

// Bundle parsing is cached by path and file stamp: Activity inspects every
// Electron process each scan, and an archive index can be hundreds of KB.
type bundleEntry struct {
	stamp, revision, integrity string
	pkg                        []byte
}

var bundleCache = struct {
	sync.Mutex
	m map[string]bundleEntry
}{m: map[string]bundleEntry{}}

func cachedBundlePackage(path string) ([]byte, string, string, error) {
	stampPath := path
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		stampPath = filepath.Join(path, "package.json")
	}
	now := stamp(stampPath)
	if now == "" {
		return readBundlePackage(path)
	}
	bundleCache.Lock()
	e, ok := bundleCache.m[path]
	bundleCache.Unlock()
	if ok && e.stamp == now {
		return e.pkg, e.revision, e.integrity, nil
	}
	pkg, revision, integrity, err := readBundlePackage(path)
	if err != nil || revision != now {
		return pkg, revision, integrity, err
	}
	bundleCache.Lock()
	if len(bundleCache.m) >= 64 {
		bundleCache.m = map[string]bundleEntry{}
	}
	bundleCache.m[path] = bundleEntry{stamp: now, revision: revision, integrity: integrity, pkg: pkg}
	bundleCache.Unlock()
	return pkg, revision, integrity, nil
}

// readBundlePackage returns package.json of an .asar archive or an app
// directory, the bundle's revision stamp and the integrity state.
func readBundlePackage(path string) ([]byte, string, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("not found")
	}
	if st.IsDir() {
		b := readBound(filepath.Join(path, "package.json"), 256<<10)
		if b == nil {
			return nil, "", "", fmt.Errorf("no package.json")
		}
		return b, stamp(filepath.Join(path, "package.json")), "directory (no archive integrity)", nil
	}
	if !st.Mode().IsRegular() || !strings.HasSuffix(path, ".asar") {
		return nil, "", "", fmt.Errorf("not an .asar archive or app directory")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("unreadable")
	}
	defer f.Close()
	var head [16]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return nil, "", "", fmt.Errorf("truncated archive")
	}
	pickle := binary.LittleEndian.Uint32(head[4:8])
	size := binary.LittleEndian.Uint32(head[12:16])
	if binary.LittleEndian.Uint32(head[0:4]) != 4 || size == 0 || size > 32<<20 || size > pickle {
		return nil, "", "", fmt.Errorf("invalid archive header")
	}
	header := make([]byte, size)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, "", "", fmt.Errorf("truncated archive header")
	}
	var index struct {
		Files map[string]struct {
			Size      int64  `json:"size"`
			Offset    string `json:"offset"`
			Unpacked  bool   `json:"unpacked"`
			Integrity *struct {
				Algorithm string `json:"algorithm"`
				Hash      string `json:"hash"`
			} `json:"integrity"`
		} `json:"files"`
	}
	if json.Unmarshal(header, &index) != nil {
		return nil, "", "", fmt.Errorf("invalid archive index")
	}
	e, ok := index.Files["package.json"]
	off, err := strconv.ParseInt(e.Offset, 10, 64)
	if !ok || e.Unpacked || err != nil || e.Size <= 0 || e.Size > 256<<10 || off < 0 {
		return nil, "", "", fmt.Errorf("no package.json in the archive")
	}
	pkg := make([]byte, e.Size)
	if _, err := f.ReadAt(pkg, 8+int64(pickle)+off); err != nil {
		return nil, "", "", fmt.Errorf("package.json outside the archive")
	}
	integrity := "not provided by the archive"
	if e.Integrity != nil && strings.EqualFold(e.Integrity.Algorithm, "SHA256") {
		sum := sha256.Sum256(pkg)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), e.Integrity.Hash) {
			return nil, "", "", fmt.Errorf("package.json does not match the archive's SHA-256 integrity")
		}
		integrity = "package.json SHA-256 matches the archive index"
	}
	return pkg, stamp(path), integrity, nil
}

// RuntimeRuleBlocked also rejects legacy "verified" hosted records. No current
// mechanism proves bundle execution, so a legacy label cannot restore authority.
func BestEffortElectron(a Application) bool {
	return a.bestEffortElectron && a.Kind == "electron" && a.Hosted != nil && a.Hosted.State == "best-effort" && a.Runtime == a.Hosted.Runtime && a.Executable == a.Hosted.Bundle && a.Revision != ""
}
func RuntimeRuleBlocked(a *Application) string {
	if a != nil && BestEffortElectron(*a) {
		return ""
	}
	if a == nil || (a.Hosted == nil && a.Kind != "electron") {
		return ""
	}
	if a.Hosted == nil {
		return "Electron bundle execution is unverified; an application-wide rule cannot be bound to bundle metadata"
	}
	return fmt.Sprintf("%s is a possible shared runtime; bundle execution is unverified (%s); an application-wide rule cannot be bound to this hint", filepath.Base(a.Hosted.Runtime), a.Hosted.Reason)
}

// LiveRuleable: a live process identity that can bind an application rule.
func LiveRuleable(a Application) bool {
	return (a.Kind == "native" || a.Kind == "electron") && a.Key != "" && a.Revision != "" && RuntimeRuleBlocked(&a) == ""
}
