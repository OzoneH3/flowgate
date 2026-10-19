package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PIDs above the kernel maximum so no live /proc entry can ever match.
const fakeBase = 5000000

type fakeProc struct {
	nodes map[int]procNode
	// statPPID overrides the ppid reported on the re-check of a child.
	statPPID map[int]int
}

func (f fakeProc) node(pid int) (procNode, error) {
	n, ok := f.nodes[pid]
	if !ok {
		return procNode{}, fmt.Errorf("no such process")
	}
	return n, nil
}
func (f fakeProc) stat(pid int) (string, int, error) {
	n, ok := f.nodes[pid]
	if !ok {
		return "", 0, fmt.Errorf("gone")
	}
	if p, ok := f.statPPID[pid]; ok {
		return n.start, p, nil
	}
	return n.start, n.ppid, nil
}

func chain(nodes ...procNode) fakeProc {
	f := fakeProc{nodes: map[int]procNode{}, statPPID: map[int]int{}}
	for _, n := range nodes {
		f.nodes[n.pid] = n
	}
	return f
}

type ds2 struct {
	root, prefix, game, runtime string
	src                         fakeProc
	owner                       Process
}

// Mirrors the observed DEATH STRANDING 2 launch: bash lwp -> python3 umu-run
// DS2.exe -> srt-bwrap -> pv-adverb -> python3 .../proton waitforexitandrun ->
// umu.exe -> DS2.exe -> rundll32.exe (owner).
func ds2Launch(t *testing.T) ds2 {
	t.Helper()
	root := t.TempDir()
	d := ds2{root: root, prefix: filepath.Join(root, "Games", "pfx"), game: filepath.Join(root, "Games", "DS2", "DS2.exe"), runtime: filepath.Join(root, "compatibilitytools.d", "dwproton-11.0-4")}
	os.MkdirAll(d.prefix, 0o755)
	os.MkdirAll(filepath.Dir(d.game), 0o755)
	os.WriteFile(d.game, []byte("MZ not a real image"), 0o644)
	wine := filepath.Join(d.runtime, "files", "bin", "wine")
	n := func(pid, ppid int, start, exe string, argv []string, env map[string]string, cwd string) procNode {
		return procNode{pid: fakeBase + pid, ppid: ppid, start: start, uid: 1000, exe: exe, revision: "1:2:3:4:5", argv: argv, env: env, cwd: cwd}
	}
	env := map[string]string{"WINEPREFIX": d.prefix + "/", "PROTONPATH": d.runtime}
	d.src = chain(
		n(1, fakeBase+2, "4938796", wine, []string{`C:\windows\system32\rundll32.exe`, "printui.dll"}, env, "/"),
		n(2, fakeBase+3, "4938000", wine, []string{`S:\Games\DS2\DS2.exe`}, env, "/"),
		n(3, fakeBase+4, "4937500", wine, []string{`c:\windows\system32\umu.exe`, `S:\Games\DS2\DS2.exe`}, env, "/"),
		n(4, fakeBase+5, "4937000", "/usr/bin/python3.14", []string{"python3", filepath.Join(d.runtime, "proton"), "waitforexitandrun", d.game}, env, filepath.Dir(d.game)),
		n(5, fakeBase+6, "4936900", "/usr/lib/pressure-vessel/from-host/bin/pv-adverb", []string{"pv-adverb", "--exit-with-parent"}, env, "/"),
		n(6, fakeBase+7, "4936800", "/usr/lib/pressure-vessel/from-host/bin/srt-bwrap", []string{"srt-bwrap", "--args", "12"}, env, "/"),
		n(7, fakeBase+8, "4936638", "/usr/bin/python3.14", []string{"python3", "/usr/bin/umu-run", "DS2.exe"}, env, filepath.Dir(d.game)),
		n(8, 1, "4936600", "/usr/bin/bash", []string{"bash", "/home/u/user_config/scripts/lwp", "DS2.exe"}, nil, filepath.Dir(d.game)),
	)
	d.owner = Process{PID: fakeBase + 1, Start: "4938796", UID: 1000, Application: Application{Kind: "wine", Name: "rundll32.exe", Prefix: d.prefix, Executable: filepath.Join(d.runtime, "files/lib/wine/x86_64-windows/rundll32.exe"), Key: "k", Revision: "r"}}
	return d
}

func derive(src fakeProc, owner Process) *Provenance {
	nodes, stop := walkAncestry(src, owner.PID, owner.Start, provenanceMaxDepth)
	return deriveProvenance(owner, nodes, stop, time.Unix(0, 0))
}

func TestProvenanceUmuProtonHelper(t *testing.T) {
	d := ds2Launch(t)
	p := derive(d.src, d.owner)
	if p.Evidence != "verified" || p.Launch == nil || p.Stop != "init" {
		t.Fatalf("expected verified launch, got %+v", p)
	}
	l := p.Launch
	if l.Kind != "umu" || l.LauncherPID != fakeBase+7 || l.LauncherStart != "4936638" || l.LauncherName != "python3.14 umu-run" {
		t.Fatalf("launcher %+v", l)
	}
	if l.Game == nil || l.Game.Status != "verified-file" || l.Game.Name != "DS2.exe" || l.Game.Executable != d.game || l.Game.Revision == "" || l.Game.Source != "proton waitforexitandrun argument" {
		t.Fatalf("game %+v", l.Game)
	}
	if l.Runtime != "dwproton-11.0-4" || l.Prefix != d.prefix || l.PrefixID == "" || l.PrefixSource != "owner Wine identity" {
		t.Fatalf("runtime/prefix %+v", l)
	}
	if p.Role != "helper" || p.Group == "" || len(p.Ancestry) != 7 {
		t.Fatalf("role/group/ancestry %q %q %d", p.Role, p.Group, len(p.Ancestry))
	}
	want := map[string]bool{"wine": true, "proton": true, "pressure-vessel": true, "umu-run": true}
	for _, m := range l.Markers {
		delete(want, m)
	}
	if len(want) != 0 {
		t.Fatalf("missing markers %v in %v", want, l.Markers)
	}
	// The same launch observed from the launcher process itself (case a).
	launcher := Process{PID: fakeBase + 7, Start: "4936638", UID: 1000, Application: Application{Kind: "native", Name: "python3.14", Executable: "/usr/bin/python3.14"}}
	lp := derive(d.src, launcher)
	if lp.Evidence != "verified" || lp.Role != "launcher" || lp.Group != p.Group {
		t.Fatalf("launcher provenance %+v (group %q vs %q)", lp, lp.Group, p.Group)
	}
	if lp.Launch.Game == nil || lp.Launch.Game.Source != "umu-run argument" || lp.Launch.Game.Executable != d.game {
		t.Fatalf("umu-run relative argument not resolved through cwd: %+v", lp.Launch.Game)
	}
}

func TestProvenanceUnrelatedNativePythonGetsNone(t *testing.T) {
	src := chain(
		procNode{pid: fakeBase + 1, ppid: fakeBase + 2, start: "4936700", exe: "/usr/bin/python3.14", argv: []string{"python3", "/home/u/fetch.py", "34.126.228.17"}},
		procNode{pid: fakeBase + 2, ppid: fakeBase + 3, start: "4936000", exe: "/usr/bin/fish", argv: []string{"fish"}},
		procNode{pid: fakeBase + 3, ppid: 1, start: "100", exe: "/usr/lib/systemd/systemd", argv: []string{"/usr/lib/systemd/systemd", "--user"}},
	)
	p := derive(src, Process{PID: fakeBase + 1, Start: "4936700", Application: Application{Kind: "native", Name: "python3.14"}})
	if p.Evidence != "none" || p.Launch != nil || p.Group != "" || p.Role != "" {
		t.Fatalf("unrelated python must get no provenance, got %+v", p)
	}
}

func TestAncestryStopsOnPIDReuse(t *testing.T) {
	d := ds2Launch(t)
	// The DS2.exe parent PID now belongs to a newer process: never adopt it.
	n := d.src.nodes[fakeBase+2]
	n.start = "4999999"
	d.src.nodes[fakeBase+2] = n
	p := derive(d.src, d.owner)
	if p.Stop != "pid-reused" || p.Evidence != "unavailable" || p.Launch != nil || len(p.Ancestry) != 0 {
		t.Fatalf("pid reuse must stop the walk: %+v", p)
	}
}

func TestAncestryReparentedHelperHasNoLaunch(t *testing.T) {
	d := ds2Launch(t)
	n := d.src.nodes[fakeBase+1]
	n.ppid = 1 // parent exited; adopted by init
	d.src.nodes[fakeBase+1] = n
	p := derive(d.src, d.owner)
	if p.Stop != "init" || p.Evidence != "none" || p.Launch != nil {
		t.Fatalf("reparented helper must not invent a parent: %+v", p)
	}
	// A child that is reparented between reading parent and re-check stops too.
	d = ds2Launch(t)
	d.src.statPPID[fakeBase+1] = 1
	p = derive(d.src, d.owner)
	if p.Stop != "reparented-during-walk" || p.Evidence != "unavailable" {
		t.Fatalf("reparent race: %+v", p)
	}
}

func TestAncestryDepthCapAndMissingEntries(t *testing.T) {
	var nodes []procNode
	for i := 1; i <= 30; i++ {
		nodes = append(nodes, procNode{pid: fakeBase + i, ppid: fakeBase + i + 1, start: fmt.Sprint(1000 - i), exe: "/usr/bin/sh"})
	}
	p := derive(chain(nodes...), Process{PID: fakeBase + 1, Start: "999"})
	if p.Stop != "depth-cap" || len(p.Ancestry) != provenanceMaxDepth || p.Evidence != "unavailable" {
		t.Fatalf("depth cap: stop %q ancestry %d evidence %q", p.Stop, len(p.Ancestry), p.Evidence)
	}
	d := ds2Launch(t)
	delete(d.src.nodes, fakeBase+3)
	p = derive(d.src, d.owner)
	if p.Stop != "parent-unavailable" || p.Evidence != "unavailable" || len(p.Ancestry) != 1 {
		t.Fatalf("missing parent: %+v", p)
	}
	p = derive(d.src, Process{PID: fakeBase + 77, Start: "1"})
	if p.Stop != "owner-changed" || p.Evidence != "unavailable" {
		t.Fatalf("missing owner: %+v", p)
	}
	p = derive(d.src, Process{PID: fakeBase + 1, Start: "1"}) // start mismatch
	if p.Stop != "owner-changed" {
		t.Fatalf("owner start mismatch: %+v", p)
	}
}

func TestMarkers(t *testing.T) {
	cases := []struct {
		n          procNode
		kind, arg  string
		runtime    string
		steamAppID string
	}{
		{procNode{exe: "/usr/bin/python3.14", argv: []string{"python3", "/usr/bin/umu-run", "game.exe"}}, "umu-run", "game.exe", "", ""},
		{procNode{exe: "/usr/bin/python3.14", argv: []string{"/usr/bin/umu-run", "winetricks", "x"}}, "umu-run", "", "", ""},
		{procNode{exe: "/usr/bin/python3.14", argv: []string{"python3", "/c/dwproton-11.0-4/proton", "waitforexitandrun", "/g/DS2.exe"}}, "proton", "/g/DS2.exe", "dwproton-11.0-4", ""},
		{procNode{exe: "/usr/bin/python3.14", argv: []string{"python3", "/c/Proton 9.0/proton", "runinprefix", "x.exe"}}, "proton", "x.exe", "Proton 9.0", ""},
		{procNode{exe: "/srt/srt-bwrap", argv: []string{"srt-bwrap"}}, "pressure-vessel", "", "", ""},
		{procNode{exe: "/x/files/bin/wineserver", argv: []string{"/x/files/bin/wineserver"}}, "wineserver", "", "", ""},
		{procNode{exe: "/s/reaper", argv: []string{"/s/reaper", "SteamLaunch", "AppId=1850570", "--", "/g/game"}}, "steam-reaper", "/g/game", "", "1850570"},
		{procNode{exe: "/usr/bin/wine", argv: []string{`Z:\g\Game.exe`, "-x"}}, "wine", `Z:\g\Game.exe`, "", ""},
	}
	for _, c := range cases {
		m, ok := markerOf(c.n)
		if !ok || m.kind != c.kind || m.arg != c.arg || m.runtime != c.runtime || m.appID != c.steamAppID {
			t.Errorf("%v: got %+v", c.n.argv, m)
		}
	}
	for _, n := range []procNode{
		{exe: "/usr/bin/python3.14", argv: []string{"python3", "/home/u/proton.py"}},
		{exe: "/usr/bin/python3.14", argv: []string{"python3", "-c", "print('umu-run proton wine')"}},
		{exe: "/usr/bin/curl", argv: []string{"curl", "https://x/proton"}},
		{exe: "/usr/bin/python3.14", argv: []string{"python3", "/x/proton", "--help"}},
	} {
		if m, ok := markerOf(n); ok {
			t.Errorf("unexpected marker %+v for %v", m, n.argv)
		}
	}
}

func TestWineExeArgumentResolvesThroughPrefix(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "pfx")
	game := filepath.Join(root, "games", "Game.exe")
	os.MkdirAll(filepath.Join(prefix, "dosdevices"), 0o755)
	os.MkdirAll(filepath.Dir(game), 0o755)
	os.WriteFile(game, []byte("x"), 0o644)
	os.Symlink(filepath.Join(root, "games"), filepath.Join(prefix, "dosdevices", "g:"))
	src := chain(
		procNode{pid: fakeBase + 1, ppid: fakeBase + 2, start: "20", exe: "/usr/bin/wine", argv: []string{`C:\windows\system32\rundll32.exe`}, env: map[string]string{"WINEPREFIX": prefix}},
		procNode{pid: fakeBase + 2, ppid: 1, start: "10", exe: "/usr/bin/wine", argv: []string{`G:\Game.exe`}, env: map[string]string{"WINEPREFIX": prefix}},
	)
	p := derive(src, Process{PID: fakeBase + 1, Start: "20", Application: Application{Kind: "wine", Prefix: prefix}})
	if p.Evidence != "verified" || p.Launch.Kind != "wine" || p.Launch.LauncherPID != fakeBase+2 || p.Launch.Game == nil || p.Launch.Game.Status != "verified-file" || p.Launch.Game.Name != "Game.exe" || p.Role != "helper" {
		t.Fatalf("wine launch %+v game %+v", p, p.Launch)
	}
	// A named but missing executable is never reported as verified.
	n := src.nodes[fakeBase+2]
	n.argv = []string{`G:\Missing.exe`}
	src.nodes[fakeBase+2] = n
	p = derive(src, Process{PID: fakeBase + 1, Start: "20", Application: Application{Kind: "wine", Prefix: prefix}})
	if p.Launch.Game == nil || p.Launch.Game.Status != "not-found" || p.Launch.Game.Revision != "" {
		t.Fatalf("missing game %+v", p.Launch.Game)
	}
}

func TestEnvironmentWhitelist(t *testing.T) {
	raw := []byte("HOME=/home/u\x00WINEPREFIX=/p\x00STEAM_COMPAT_DATA_PATH=/c\x00SteamAppId=1\x00SteamGameId=2\x00PROTONPATH=/r\x00UMU_ID=umu-1\x00GAMEID=g\x00GITHUB_TOKEN=secret\x00AWS_SECRET_ACCESS_KEY=s\x00WINEPREFIXX=no\x00WINEPREFIX2=no\x00")
	env := whitelistedEnv(raw)
	if len(env) != 7 || env["WINEPREFIX"] != "/p" || env["UMU_ID"] != "umu-1" {
		t.Fatalf("whitelist %v", env)
	}
	for k := range env {
		if strings.Contains(k, "TOKEN") || strings.Contains(k, "SECRET") || k == "HOME" {
			t.Fatalf("non-whitelisted key retained: %s", k)
		}
	}
	long := whitelistedEnv([]byte("WINEPREFIX=" + strings.Repeat("a", 2000)))
	if len(long) != 0 {
		t.Fatal("oversized value retained")
	}
	args := boundedArgs([]byte(strings.Repeat("a\x00", 100)))
	if len(args) != provenanceMaxArgs {
		t.Fatalf("args not bounded: %d", len(args))
	}
}

func TestCaptureProvenanceCacheAndSplice(t *testing.T) {
	d := ds2Launch(t)
	oldSrc, oldRunning := provenanceSource, provenanceRunning
	provenanceSource = d.src
	provenanceRunning = func(int, string) bool { return true }
	defer func() { provenanceSource, provenanceRunning = oldSrc, oldRunning }()
	provenanceCache.Lock()
	provenanceCache.m = map[string]provenanceCacheEntry{}
	provenanceCache.Unlock()

	// DS2.exe observed first (game role) while the chain is intact.
	gameOwner := Process{PID: fakeBase + 2, Start: "4938000", UID: 1000, Application: Application{Kind: "wine", Prefix: d.prefix, Executable: d.game}}
	first := CaptureProvenance(gameOwner)
	if first.Evidence != "verified" || first.Role != "game" {
		t.Fatalf("game capture %+v", first)
	}
	// Short-lived helper: captured once, the cached value survives its parent's exit.
	h := CaptureProvenance(d.owner)
	if h.Evidence != "verified" {
		t.Fatalf("helper %+v", h)
	}
	delete(d.src.nodes, fakeBase+1)
	again := CaptureProvenance(d.owner)
	if again.Evidence != "verified" || again.Group != h.Group {
		t.Fatalf("cached helper provenance lost: %+v", again)
	}
	// The launcher above DS2.exe exits; a NEW helper under DS2.exe still links
	// to DS2.exe's verified provenance captured at first sight.
	delete(d.src.nodes, fakeBase+3)
	d.src.nodes[fakeBase+9] = procNode{pid: fakeBase + 9, ppid: fakeBase + 2, start: "4940000", uid: 1000, exe: d.src.nodes[fakeBase+2].exe, argv: []string{`C:\windows\system32\crs-handler.exe`}}
	late := CaptureProvenance(Process{PID: fakeBase + 9, Start: "4940000", UID: 1000, Application: Application{Kind: "wine", Prefix: d.prefix}})
	if late.Evidence != "verified" || late.Group != first.Group || late.Role != "helper" || !strings.Contains(late.Reason, "first observed") {
		t.Fatalf("splice %+v", late)
	}
	// Unavailable results are not cached.
	if _, ok := provenanceCache.m[fmt.Sprintf("||%d|%s", fakeBase+77, "1")]; ok {
		t.Fatal("unexpected cache entry")
	}
}

func appKey(uid uint32, kind, prefix, exe string) string {
	return digest(fmt.Sprintf("%d|%s|%s|%s", uid, kind, prefix, exe))
}

func TestPermissionTargetWineHelperPerPrefix(t *testing.T) {
	d := ds2Launch(t)
	p := derive(d.src, d.owner)
	exe := d.owner.Application.Executable
	mk := func(prefix string) Attribution {
		o := d.owner
		o.BootID = "boot"
		o.Application.Prefix = prefix
		o.Application.Key = appKey(1000, "wine", prefix, exe)
		o.Provenance = p
		app := o.Application
		return Attribution{Status: "corroborated", VisibilityComplete: true, Owners: []Process{o}, Application: &app}
	}
	a, b := mk(d.prefix), mk(filepath.Join(d.root, "Games", "pfx-b"))
	if a.Application.Key == b.Application.Key {
		t.Fatal("same helper path in different prefixes must produce different keys")
	}
	ta := DescribePermissionTarget(a)
	if ta.Kind != "helper" || !strings.Contains(ta.Label, "rundll32.exe in prefix") || !strings.Contains(ta.Label, "shared by every game using this prefix") {
		t.Fatalf("label %q", ta.Label)
	}
	if !strings.Contains(ta.SharedWithNote, "not only DS2.exe") || strings.Contains(strings.ToLower(ta.Label+ta.Remember), "this game only") {
		t.Fatalf("note %q", ta.SharedWithNote)
	}
	if !strings.Contains(ta.ForAWhile, fmt.Sprintf("rundll32.exe PID %d, same direction", fakeBase+1)) || !strings.Contains(ta.ForAWhile, "relaunch") {
		t.Fatalf("for a while %q", ta.ForAWhile)
	}
	if ta.KeyBasis != "uid+wine+prefix+executable path; revision = file stamp" {
		t.Fatalf("key basis %q", ta.KeyBasis)
	}
	// Two holders (broker model): For a while is truthfully unavailable.
	two := a
	two.Owners = append(append([]Process{}, a.Owners...), Process{PID: fakeBase + 50, UID: 1000})
	two.Association = &Association{ClientPID: fakeBase + 1}
	if tt := DescribePermissionTarget(two); !strings.HasPrefix(tt.ForAWhile, "Unavailable: 2 visible") || tt.Kind != "helper" {
		t.Fatalf("two holders %+v", tt)
	}
	// The serialized attribution carries provenance and the target.
	raw, _ := json.Marshal(a)
	var out map[string]any
	json.Unmarshal(raw, &out)
	if out["provenance"] == nil || out["permission_target"] == nil || out["owners"] == nil {
		t.Fatalf("serialization %s", raw)
	}
	// Game executable itself: per-executable application target.
	game := mk(d.prefix)
	game.Owners[0].Provenance = &Provenance{Evidence: "verified", Role: "game", Launch: p.Launch}
	if tg := DescribePermissionTarget(game); tg.Kind != "application" || strings.Contains(tg.Label, "shared") {
		t.Fatalf("game target %+v", tg)
	}
}

func TestPermissionTargetNativeInterpreterAndUnavailable(t *testing.T) {
	d := ds2Launch(t)
	launcher := Process{PID: fakeBase + 7, Start: "4936638", UID: 1000, BootID: "b", Application: Application{Kind: "native", Name: "python3.14", Executable: "/usr/bin/python3.14", Key: "k", Revision: "r"}}
	launcher.Provenance = derive(d.src, launcher)
	app := launcher.Application
	tt := DescribePermissionTarget(Attribution{VisibilityComplete: true, Owners: []Process{launcher}, Application: &app})
	if tt.Kind != "interpreter" || !strings.Contains(tt.SharedWithNote, "not only python3.14 umu-run") || !strings.Contains(tt.Label, "every script") {
		t.Fatalf("interpreter %+v", tt)
	}
	none := DescribePermissionTarget(Attribution{Owners: []Process{{PID: 1}}})
	if none.Kind != "unavailable" || !strings.HasPrefix(none.Remember, "Unavailable") {
		t.Fatalf("unavailable %+v", none)
	}
	if !isInterpreter("python3.14") || !isInterpreter("bash") || isInterpreter("rundll32.exe") || isInterpreter("shotwell") {
		t.Fatal("interpreter detection")
	}
}

func TestShortPrefix(t *testing.T) {
	if got := ShortPrefix("/home/someone/Games/pfx"); got != "~/Games/pfx" {
		t.Fatalf("got %q", got)
	}
	if got := ShortPrefix("/mnt/very/long/path/to/some/steam/library/steamapps/compatdata/1850570/pfx"); got != "…/1850570/pfx" {
		t.Fatalf("got %q", got)
	}
}

func TestProductNameFromInstalledProton(t *testing.T) {
	versionBlob := append(append([]byte{0, 0, 0, 0, 0, 0}, utf16le("ProductName")...), 0, 0)
	for len(versionBlob)%4 != 0 {
		versionBlob = append(versionBlob, 0)
	}
	versionBlob = append(versionBlob, utf16le("DEATH STRANDING 2")...)
	if v := versionString(versionBlob, "ProductName"); v != "DEATH STRANDING 2" {
		t.Fatalf("synthetic version string %q", v)
	}
	if productName("/nonexistent.exe") != "" {
		t.Fatal("missing file must yield empty")
	}
	path := os.Getenv("FLOWGATE_TEST_PE")
	if path == "" {
		t.Skip("set FLOWGATE_TEST_PE to an installed PE image to read its version resource")
	}
	if v := productName(path); v == "" {
		t.Fatalf("no product name read from %s", path)
	} else {
		t.Logf("%s: %q", path, v)
	}
}
