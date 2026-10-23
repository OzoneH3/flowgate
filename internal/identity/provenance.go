package identity

// Launch provenance: a bounded, display-only record of how an attributed socket
// owner was launched (umu-run, Proton, pressure-vessel, Steam reaper, Wine).
// It is captured from /proc while the owner is alive, by walking real parent
// links with start-time checks, and is retained with the attribution/event so
// an ended helper keeps what was observed. It never changes application keys,
// revisions, rule matching or any enforcement decision.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	provenanceMaxDepth   = 12
	provenanceMaxString  = 512
	provenanceMaxArgs    = 32
	provenanceMaxCmdline = 8192
	provenanceMaxEnviron = 256 << 10
	provenanceCacheMax   = 4096
)

// ProvenanceEnvKeys is the complete set of environment keys ever read. No other
// environment value is retained or exposed.
var ProvenanceEnvKeys = []string{"WINEPREFIX", "STEAM_COMPAT_DATA_PATH", "SteamAppId", "SteamGameId", "PROTONPATH", "UMU_ID", "GAMEID"}

type ProvenanceAncestor struct {
	PID        int    `json:"pid"`
	Start      string `json:"start_ticks"`
	UID        uint32 `json:"uid"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Revision   string `json:"revision,omitempty"`
	Marker     string `json:"marker,omitempty"`
}

type LaunchGame struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Executable string `json:"executable"`
	Revision   string `json:"revision,omitempty"`
	// verified-file: the argument resolved to an existing regular file (stamped);
	// not-found: an argument was named but no file could be verified.
	Status string `json:"status"`
	Source string `json:"source"`
}

type Launch struct {
	Kind          string      `json:"kind"` // umu | proton | steam | wine
	LauncherPID   int         `json:"launcher_pid"`
	LauncherStart string      `json:"launcher_start_ticks"`
	LauncherName  string      `json:"launcher_name"`
	Game          *LaunchGame `json:"game,omitempty"`
	Prefix        string      `json:"prefix,omitempty"`
	PrefixID      string      `json:"prefix_id,omitempty"` // device:inode of the canonical prefix directory
	PrefixSource  string      `json:"prefix_source,omitempty"`
	Runtime       string      `json:"runtime,omitempty"`
	SteamAppID    string      `json:"steam_app_id,omitempty"`
	GameID        string      `json:"game_id,omitempty"`
	Markers       []string    `json:"markers"`
}

type Provenance struct {
	Invocation *Invocation `json:"invocation,omitempty"`
	// verified: unbroken parent chain from the owner to the launcher (start
	// times checked). unavailable: the chain broke before any launcher was
	// found. none: the complete chain contains no launcher.
	Evidence string               `json:"evidence"`
	Reason   string               `json:"reason"`
	Role     string               `json:"role,omitempty"` // launcher | game | runtime | helper
	Group    string               `json:"group,omitempty"`
	Stop     string               `json:"stop"`
	Ancestry []ProvenanceAncestor `json:"ancestry"`
	Launch   *Launch              `json:"launch,omitempty"`
	// Parent: the nearest ancestor that is another program (not session or
	// shell infrastructure), e.g. Heroic for its nile helper. Display only;
	// the owner keeps its own application identity for every rule.
	Parent     *LaunchParent `json:"parent,omitempty"`
	CapturedAt time.Time     `json:"captured_at"`
}

// LaunchParent is the program that started the owner, through the verified chain.
type LaunchParent struct {
	Invocation *Invocation `json:"invocation,omitempty"`
	PID        int         `json:"pid"`
	Start      string      `json:"start_ticks"`
	Depth      int         `json:"depth"` // ancestors between owner and parent + 1
	Name       string      `json:"name"`
	Executable string      `json:"executable"`
	// Application: the parent's identity when it is a verified Electron app.
	Application *Application `json:"application,omitempty"`
	Note        string       `json:"note,omitempty"`
}

// procNode is one bounded /proc observation.
type procNode struct {
	invocation *Invocation
	pid, ppid  int
	start      string
	uid        uint32
	exe        string
	revision   string
	argv       []string
	env        map[string]string
	cwd        string
	foreignMnt bool
}

type procSource interface {
	node(pid int) (procNode, error)
	stat(pid int) (start string, ppid int, err error)
}

type liveProc struct{}

func (liveProc) stat(pid int) (string, int, error) { return processStat(fmt.Sprintf("/proc/%d", pid)) }
func (liveProc) node(pid int) (procNode, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	start, ppid, err := processStat(base)
	if err != nil {
		return procNode{}, err
	}
	st, err := os.Stat(base)
	if err != nil {
		return procNode{}, err
	}
	n := procNode{pid: pid, ppid: ppid, start: start, uid: st.Sys().(*syscall.Stat_t).Uid, exe: link(base + "/exe"), cwd: link(base + "/cwd")}
	if n.exe != "" {
		n.revision = stamp(base + "/exe")
	}
	n.argv = boundedArgs(readBound(base+"/cmdline", provenanceMaxCmdline))
	n.env = whitelistedEnv(readBound(base+"/environ", provenanceMaxEnviron))
	n.foreignMnt = link(base+"/ns/mnt") != link("/proc/self/ns/mnt")
	n.invocation = captureInvocation(n)
	again, _, err := processStat(base)
	if err != nil || again != start {
		return procNode{}, fmt.Errorf("process changed during provenance read")
	}
	return n, nil
}

func clip(s string) string {
	if len(s) <= provenanceMaxString {
		return strings.Clone(s)
	}
	return strings.Clone(s[:provenanceMaxString-3]) + "..."
}

func boundedArgs(raw []byte) []string {
	out := []string{}
	for _, a := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
		if len(out) >= provenanceMaxArgs {
			break
		}
		if len(a) > 2048 {
			a = "" // oversized arguments are never interpreted
		}
		out = append(out, strings.Clone(a))
	}
	return out
}

func whitelistedEnv(raw []byte) map[string]string {
	out := map[string]string{}
	for _, v := range strings.Split(string(raw), "\x00") {
		k, val, ok := strings.Cut(v, "=")
		if !ok || len(val) > 1024 {
			continue
		}
		for _, allowed := range ProvenanceEnvKeys {
			if k == allowed {
				out[k] = strings.Clone(val)
			}
		}
	}
	return out
}

func ticks(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// walkAncestry returns [owner, parent, ...] and why the walk stopped. A parent
// that started after its child means the parent PID was reused: stop without
// inventing a parent. PID 1 (init or the namespace's init) ends the chain.
func walkAncestry(src procSource, pid int, start string, max int) ([]procNode, string) {
	owner, err := src.node(pid)
	if err != nil || owner.start != start {
		return nil, "owner-changed"
	}
	nodes := []procNode{owner}
	cur := owner
	for {
		if cur.ppid <= 1 {
			if cur.ppid == 1 {
				return nodes, "init"
			}
			return nodes, "root"
		}
		if len(nodes)-1 >= max {
			return nodes, "depth-cap"
		}
		parent, err := src.node(cur.ppid)
		if err != nil {
			return nodes, "parent-unavailable"
		}
		cs, _ := ticks(cur.start)
		ps, ok := ticks(parent.start)
		if !ok || ps > cs {
			return nodes, "pid-reused"
		}
		// The child must still name this parent after the parent was read.
		again, ppid, err := src.stat(cur.pid)
		if err != nil || again != cur.start || ppid != parent.pid {
			return nodes, "reparented-during-walk"
		}
		nodes = append(nodes, parent)
		cur = parent
	}
}

var protonVerbs = map[string]bool{"run": true, "waitforexitandrun": true, "runinprefix": true, "waitforexit": false}
var pressureVessel = map[string]bool{"srt-bwrap": true, "pv-adverb": true, "pressure-vessel-wrap": true, "pressure-vessel-adverb": true, "pressure-vessel-launch": true}
var wineLoaders = map[string]bool{"wine": true, "wine64": true, "wine-preloader": true, "wine64-preloader": true}

type marker struct {
	kind    string // umu-run | proton | pressure-vessel | wineserver | steam-reaper | wine
	arg     string // launched program argument, if any
	source  string
	runtime string
	appID   string
}

func isWindowsPath(s string) bool {
	return len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z'))
}
func winBase(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	return filepath.Base(s)
}

// markerOf detects launch markers from argv and the executable link only.
func markerOf(n procNode) (marker, bool) {
	exeBase := filepath.Base(strings.TrimSuffix(n.exe, " (deleted)"))
	limit := len(n.argv)
	if limit > 4 {
		limit = 4
	}
	for i := 0; i < limit; i++ {
		b := filepath.Base(n.argv[i])
		next := func(from int) string {
			for _, a := range n.argv[from:] {
				if a != "" && !strings.HasPrefix(a, "-") {
					return a
				}
			}
			return ""
		}
		if b == "umu-run" || b == "umu_run.py" {
			arg := next(i + 1)
			if arg == "winetricks" {
				arg = ""
			}
			return marker{kind: "umu-run", arg: arg, source: "umu-run argument"}, true
		}
		if b == "proton" && i+1 < len(n.argv) {
			if protonVerbs[n.argv[i+1]] {
				arg := ""
				if i+2 < len(n.argv) {
					arg = n.argv[i+2]
				}
				return marker{kind: "proton", arg: arg, source: "proton " + n.argv[i+1] + " argument", runtime: filepath.Base(filepath.Dir(n.argv[i]))}, true
			}
		}
		if b == "reaper" {
			for j, a := range n.argv {
				if a == "SteamLaunch" {
					m := marker{kind: "steam-reaper", source: "Steam reaper"}
					for k, x := range n.argv[j:] {
						if strings.HasPrefix(x, "AppId=") {
							m.appID = strings.TrimPrefix(x, "AppId=")
						}
						if x == "--" && j+k+1 < len(n.argv) {
							m.arg = n.argv[j+k+1]
							break
						}
					}
					return m, true
				}
			}
		}
	}
	argv0 := ""
	if len(n.argv) > 0 {
		argv0 = filepath.Base(n.argv[0])
	}
	if pressureVessel[exeBase] || pressureVessel[argv0] {
		return marker{kind: "pressure-vessel"}, true
	}
	if exeBase == "wineserver" || argv0 == "wineserver" {
		return marker{kind: "wineserver"}, true
	}
	if wineLoaders[exeBase] || wineLoaders[argv0] {
		m := marker{kind: "wine", source: "Wine process image argument"}
		for _, a := range n.argv {
			if strings.HasSuffix(strings.ToLower(a), ".exe") {
				m.arg = a
				break
			}
		}
		return m, true
	}
	return marker{}, false
}

// statLaunchFile verifies a launch argument as a regular file. Paths are
// interpreted in the launching process's view: relative to its cwd, through
// /proc/PID/root when it runs in another mount namespace, and Windows drive
// paths through the prefix's dosdevices.
var statLaunchFile = func(n procNode, path string) (string, os.FileInfo, error) {
	view := path
	if n.foreignMnt && n.pid > 0 {
		view = fmt.Sprintf("/proc/%d/root%s", n.pid, path)
	}
	st, err := os.Stat(view)
	return view, st, err
}

func resolveLaunchArg(n procNode, arg, prefix string) (string, string, os.FileInfo, bool) {
	if arg == "" {
		return "", "", nil, false
	}
	path := arg
	if isWindowsPath(arg) {
		if prefix == "" {
			return "", "", nil, false
		}
		path = filepath.Join(prefix, "dosdevices", strings.ToLower(arg[:1])+":", strings.ReplaceAll(arg[3:], "\\", "/"))
	} else if !filepath.IsAbs(path) {
		if n.cwd == "" {
			return "", "", nil, false
		}
		path = filepath.Join(n.cwd, path)
	}
	view, st, err := statLaunchFile(n, filepath.Clean(path))
	if err != nil || !st.Mode().IsRegular() {
		return filepath.Clean(path), "", nil, false
	}
	return filepath.Clean(path), view, st, true
}

func canonicalPrefix(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	if c, err := filepath.EvalSymlinks(p); err == nil {
		return c
	}
	return p
}

func dirIdentity(p string) string {
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return ""
	}
	s := st.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
}

func runtimeFromPath(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if (part == "compatibilitytools.d" || part == "common") && i+1 < len(parts) && parts[i+1] != "" {
			return parts[i+1]
		}
	}
	return ""
}

// deriveProvenance builds the record from an ancestry walk. owner is the
// already-inspected attributed process (its Application supplies the prefix).
func deriveProvenance(owner Process, nodes []procNode, stop string, now time.Time) *Provenance {
	p := &Provenance{Stop: stop, Ancestry: []ProvenanceAncestor{}, CapturedAt: now}
	if len(nodes) == 0 {
		p.Evidence, p.Reason = "unavailable", "owner exited or changed before its ancestry could be read"
		return p
	}
	markers := make([]*marker, len(nodes))
	for i, n := range nodes {
		if m, ok := markerOf(n); ok {
			markers[i] = &m
		}
		if i == 0 {
			continue
		}
		a := ProvenanceAncestor{PID: n.pid, Start: n.start, UID: n.uid, Name: clip(filepath.Base(n.exe)), Executable: clip(n.exe), Revision: n.revision}
		if n.exe == "" {
			a.Name = "(executable unreadable)"
		}
		if len(n.argv) > 1 && (strings.HasPrefix(a.Name, "python") || a.Name == "bash" || a.Name == "sh") {
			a.Name = clip(a.Name + " " + filepath.Base(n.argv[1]))
		}
		if markers[i] != nil {
			a.Marker = markers[i].kind
		}
		p.Ancestry = append(p.Ancestry, a)
	}
	// Launcher: outermost umu-run, else outermost proton, else steam reaper,
	// else the outermost Wine process. Runtime-only markers never launch.
	pick := func(kind string) int {
		at := -1
		for i, m := range markers {
			if m != nil && m.kind == kind {
				at = i
			}
		}
		return at
	}
	kind, at := "", -1
	for _, c := range []struct{ marker, kind string }{{"umu-run", "umu"}, {"proton", "proton"}, {"steam-reaper", "steam"}, {"wine", "wine"}} {
		i := pick(c.marker)
		// A Wine process alone is not a launch: it needs a Wine parent and the
		// complete chain (an unseen umu/Proton launcher may sit above a break).
		if c.marker == "wine" && (i < 1 || (stop != "init" && stop != "root")) {
			i = -1
		}
		if i >= 0 {
			kind, at = c.kind, i
			break
		}
	}
	if at < 0 {
		if stop == "init" || stop == "root" {
			p.Evidence, p.Reason = "none", "complete parent chain contains no game launcher"
		} else {
			p.Evidence, p.Reason = "unavailable", "parent chain ended before any launcher ("+stop+")"
		}
		return p
	}
	launcher := nodes[at]
	l := &Launch{Kind: kind, LauncherPID: launcher.pid, LauncherStart: launcher.start, LauncherName: clip(filepath.Base(launcher.exe)), Markers: []string{}}
	if len(launcher.argv) > 1 && strings.HasPrefix(l.LauncherName, "python") {
		l.LauncherName = clip(l.LauncherName + " " + filepath.Base(launcher.argv[1]))
	}
	seen := map[string]bool{}
	for _, m := range markers[:at+1] {
		if m != nil && !seen[m.kind] {
			seen[m.kind] = true
			l.Markers = append(l.Markers, m.kind)
		}
	}
	env := func(k string) string {
		for _, n := range nodes[:at+1] {
			if v := n.env[k]; v != "" {
				return v
			}
		}
		return ""
	}
	switch {
	case owner.Application.Prefix != "":
		l.Prefix, l.PrefixSource = owner.Application.Prefix, "owner Wine identity"
	case env("WINEPREFIX") != "":
		l.Prefix, l.PrefixSource = canonicalPrefix(env("WINEPREFIX")), "WINEPREFIX"
	case env("STEAM_COMPAT_DATA_PATH") != "":
		l.Prefix, l.PrefixSource = canonicalPrefix(filepath.Join(env("STEAM_COMPAT_DATA_PATH"), "pfx")), "STEAM_COMPAT_DATA_PATH/pfx"
	}
	l.Prefix = clip(l.Prefix)
	if l.Prefix != "" {
		l.PrefixID = dirIdentity(l.Prefix)
	}
	for _, m := range markers[:at+1] {
		if m != nil && m.kind == "proton" && m.runtime != "" {
			l.Runtime = clip(m.runtime)
		}
		if m != nil && m.appID != "" {
			l.SteamAppID = clip(m.appID)
		}
	}
	if l.Runtime == "" && env("PROTONPATH") != "" {
		l.Runtime = clip(filepath.Base(strings.TrimRight(env("PROTONPATH"), "/")))
	}
	if l.Runtime == "" {
		l.Runtime = clip(runtimeFromPath(owner.Application.Runtime))
	}
	if v := env("SteamAppId"); v != "" {
		l.SteamAppID = clip(v)
	} else if v := env("SteamGameId"); v != "" && l.SteamAppID == "" {
		l.SteamAppID = clip(v)
	}
	if v := env("UMU_ID"); v != "" {
		l.GameID = clip(v)
	} else if v := env("GAMEID"); v != "" {
		l.GameID = clip(v)
	}
	// Game: first verified argument, nearest launch layer first (proton, then
	// umu-run, then reaper, then the outermost Wine process image).
	var gameInfo os.FileInfo
	for _, kind := range []string{"proton", "umu-run", "steam-reaper", "wine"} {
		i := pick(kind)
		if kind == "wine" {
			i = -1 // outermost Wine process image that names an .exe
			for j := 0; j <= at; j++ {
				if markers[j] != nil && markers[j].kind == "wine" && markers[j].arg != "" {
					i = j
				}
			}
		}
		if i < 0 || i > at || markers[i].arg == "" {
			continue
		}
		path, view, st, ok := resolveLaunchArg(nodes[i], markers[i].arg, l.Prefix)
		name := winBase(markers[i].arg)
		if !ok {
			if l.Game == nil {
				l.Game = &LaunchGame{Name: clip(name), Executable: clip(path), Status: "not-found", Source: markers[i].source}
			}
			continue
		}
		l.Game = &LaunchGame{Name: clip(filepath.Base(path)), Executable: clip(path), Revision: stamp(view), Status: "verified-file", Source: markers[i].source, Title: productName(view)}
		gameInfo = st
		break
	}
	p.Launch = l
	p.Evidence = "verified"
	p.Reason = fmt.Sprintf("unbroken parent chain (start times checked) from PID %d to %s launcher PID %d", owner.PID, kind, launcher.pid)
	// Role of the owner within the launch.
	switch {
	case markers[0] != nil && (markers[0].kind == "umu-run" || markers[0].kind == "proton" || markers[0].kind == "steam-reaper"):
		p.Role = "launcher"
	case markers[0] != nil && (markers[0].kind == "pressure-vessel" || markers[0].kind == "wineserver"):
		p.Role = "runtime"
	case gameInfo != nil && ownerIsFile(owner, nodes[0], gameInfo):
		p.Role = "game"
	default:
		p.Role = "helper"
	}
	game := ""
	if l.Game != nil {
		game = l.Game.Executable
	}
	p.Group = digest(fmt.Sprintf("%d|%s|%d|%s|%s", owner.UID, kind, l.LauncherPID, l.LauncherStart, game))[:24]
	return p
}

func ownerIsFile(owner Process, n procNode, game os.FileInfo) bool {
	candidates := []string{}
	if owner.Application.Kind == "wine" && owner.Application.Executable != "" {
		candidates = append(candidates, owner.Application.Executable)
	}
	if owner.PID > 0 {
		candidates = append(candidates, fmt.Sprintf("/proc/%d/exe", owner.PID))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && os.SameFile(st, game) {
			return true
		}
	}
	return false
}

// Provenance cache: per (boot, pid, start). Results are kept while the
// process is alive so a short-lived helper is captured at first sight and
// later attributions reuse that observation even after its parents exit.
type provenanceCacheEntry struct {
	value *Provenance
	pid   int
	start string
	added time.Time
}

var provenanceCache = struct {
	sync.Mutex
	m map[string]provenanceCacheEntry
}{m: map[string]provenanceCacheEntry{}}

var provenanceSource procSource = liveProc{}
var provenanceRunning = InstanceRunning

func cloneProvenance(p *Provenance) *Provenance {
	if p == nil {
		return nil
	}
	c := *p
	if p.Invocation != nil {
		v := *p.Invocation
		c.Invocation = &v
	}
	c.Ancestry = append([]ProvenanceAncestor(nil), p.Ancestry...)
	if p.Launch != nil {
		l := *p.Launch
		l.Markers = append([]string(nil), p.Launch.Markers...)
		if p.Launch.Game != nil {
			g := *p.Launch.Game
			l.Game = &g
		}
		c.Launch = &l
	}
	if p.Parent != nil {
		pa := *p.Parent
		if pa.Invocation != nil {
			v := *pa.Invocation
			pa.Invocation = &v
		}
		if p.Parent.Application != nil {
			a := *p.Parent.Application
			pa.Application = &a
		}
		c.Parent = &pa
	}
	return &c
}

// CaptureProvenance returns the (cached) launch provenance of an inspected
// owner. It is display/explanation data only.
func CaptureProvenance(owner Process) *Provenance {
	if owner.PID <= 0 || owner.Start == "" {
		return nil
	}
	key := fmt.Sprintf("%s|%s|%d|%s", owner.BootID, owner.PIDNS, owner.PID, owner.Start)
	provenanceCache.Lock()
	if e, ok := provenanceCache.m[key]; ok {
		provenanceCache.Unlock()
		return cloneProvenance(e.value)
	}
	provenanceCache.Unlock()
	nodes, stop := walkAncestry(provenanceSource, owner.PID, owner.Start, provenanceMaxDepth)
	p := spliceCached(owner, nodes, stop)
	if p == nil {
		p = deriveProvenance(owner, nodes, stop, time.Now())
	}
	// Always the owner's own chain (a spliced ancestor provenance carries its parent).
	p.Parent = launchedBy(owner, nodes, ResolveElectronApp)
	if len(nodes) > 0 {
		p.Invocation = nodes[0].invocation
	}
	if p.Evidence == "unavailable" {
		return p // transient failures are not cached
	}
	provenanceCache.Lock()
	defer provenanceCache.Unlock()
	if len(provenanceCache.m) >= provenanceCacheMax {
		for k, e := range provenanceCache.m {
			if !provenanceRunning(e.pid, e.start) {
				delete(provenanceCache.m, k)
			}
		}
		for len(provenanceCache.m) >= provenanceCacheMax {
			var oldest string
			var at time.Time
			for k, e := range provenanceCache.m {
				if oldest == "" || e.added.Before(at) {
					oldest, at = k, e.added
				}
			}
			delete(provenanceCache.m, oldest)
		}
	}
	provenanceCache.m[key] = provenanceCacheEntry{value: cloneProvenance(p), pid: owner.PID, start: owner.Start, added: time.Now()}
	return p
}

// spliceCached: when the walk broke above an ancestor whose own verified
// provenance was captured earlier, the owner inherits that launch through the
// verified links up to that ancestor (transitively unbroken).
func spliceCached(owner Process, nodes []procNode, stop string) *Provenance {
	if stop == "init" || stop == "root" || len(nodes) < 2 {
		return nil
	}
	provenanceCache.Lock()
	var found *Provenance
	at := -1
	for i := len(nodes) - 1; i >= 1 && found == nil; i-- {
		for _, e := range provenanceCache.m {
			if e.pid == nodes[i].pid && e.start == nodes[i].start && e.value.Evidence == "verified" && e.value.Launch != nil {
				found, at = cloneProvenance(e.value), i
				break
			}
		}
	}
	provenanceCache.Unlock()
	if found == nil {
		return nil
	}
	direct := deriveProvenance(owner, nodes, stop, time.Now())
	if direct.Evidence == "verified" {
		return direct
	}
	p := direct
	p.Launch = found.Launch
	p.Evidence = "verified"
	p.Group = found.Group
	p.Reason = fmt.Sprintf("parent chain unbroken (start times checked) to PID %d, whose launch was verified when first observed; above it: %s", nodes[at].pid, stop)
	p.Ancestry = append(p.Ancestry, found.Ancestry...)
	if len(p.Ancestry) > provenanceMaxDepth {
		p.Ancestry = p.Ancestry[:provenanceMaxDepth]
	}
	p.Role = "helper"
	if l := p.Launch; l.Game != nil && l.Game.Status == "verified-file" {
		if _, view, st, ok := resolveLaunchArg(procNode{}, l.Game.Executable, ""); ok && view != "" && ownerIsFile(owner, nodes[0], st) {
			p.Role = "game"
		}
	}
	return p
}

// Session, shell and sandbox infrastructure never counts as the launching program.
var launchInfrastructure = map[string]bool{
	"init": true, "systemd": true, "sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true, "tcsh": true,
	"env": true, "sudo": true, "doas": true, "pkexec": true, "setsid": true, "nohup": true, "timeout": true, "systemd-run": true,
	"bwrap": true, "flatpak-session-helper": true, "xdg-dbus-proxy": true, "dbus-daemon": true, "dbus-broker": true, "dbus-broker-launch": true,
	"plasmashell": true, "kwin_wayland": true, "kwin_x11": true, "kwin_wayland_wrapper": true, "ksmserver": true, "startplasma-wayland": true,
	"startplasma-x11": true, "plasma_session": true, "sddm": true, "sddm-helper": true, "gnome-shell": true, "gnome-session-binary": true,
	"kded5": true, "kded6": true, "krunner": true, "kioworker": true, "kdeinit5": true, "xdg-desktop-portal": true, "xdg-desktop-portal-kde": true,
	"xdg-desktop-portal-gnome": true, "xdg-desktop-portal-gtk": true, "gamemoded": true,
	// Terminals and multiplexers: where a command was typed, not what launched it.
	"tmux": true, "tmux: server": true, "screen": true, "zellij": true, "konsole": true, "yakuake": true, "alacritty": true, "kitty": true,
	"foot": true, "wezterm-gui": true, "xterm": true, "gnome-terminal-server": true, "ptyxis-agent": true, "ghostty": true,
}

// launchedBy picks the nearest verified ancestor that is another program. A
// Shared-runtime bundle observations remain display hints, never applications.
func launchedBy(owner Process, nodes []procNode, resolve func(int, string) *Hosted) *LaunchParent {
	for i := 1; i < len(nodes); i++ {
		n := nodes[i]
		if n.exe == "" || (n.exe == owner.Executable && n.invocation == nil) || n.uid != owner.UID {
			if n.uid != owner.UID {
				return nil // another principal (e.g. a system service) did not launch it as this user's app
			}
			continue
		}
		base := filepath.Base(strings.TrimSuffix(n.exe, " (deleted)"))
		if launchInfrastructure[base] {
			continue
		}
		l := &LaunchParent{Invocation: n.invocation, PID: n.pid, Start: n.start, Depth: i, Name: clip(base), Executable: clip(n.exe)}
		if len(n.argv) > 1 && (strings.HasPrefix(base, "python") || base == "node" || base == "perl") {
			l.Name = clip(base + " " + filepath.Base(n.argv[1]))
		}
		if IsElectronRuntime(n.exe) && resolve != nil {
			if h := resolve(n.pid, n.start); h != nil {
				l.Note = "Electron application unverified: " + h.Reason
			}
		}
		return l
	}
	return nil
}
