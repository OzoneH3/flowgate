package identity

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Fake Electron runtime: this test binary copied as ".../electron". Mode "main"
// starts a "--type=utility" child of itself and prints its PID; "orphan" does
// the same and exits, so the child loses its verified parent.
func TestMain(m *testing.M) {
	switch os.Getenv("FLOWGATE_FAKE_ELECTRON") {
	case "main", "orphan":
		c := exec.Command(os.Args[0], "--type=utility", "--utility-sub-type=network.mojom.NetworkService")
		c.Env = append(os.Environ(), "FLOWGATE_FAKE_ELECTRON=child")
		if err := c.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Println(c.Process.Pid)
		if os.Getenv("FLOWGATE_FAKE_ELECTRON") == "orphan" {
			os.Exit(0)
		}
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "launcher":
		// Electron main process that starts another program (like Heroic → nile).
		c := exec.Command(os.Getenv("FLOWGATE_FAKE_HELPER"), "library", "sync")
		c.Env = append(os.Environ(), "FLOWGATE_FAKE_ELECTRON=child")
		if err := c.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Println(c.Process.Pid)
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "child":
		time.Sleep(60 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writeAsar writes a minimal Electron archive holding package.json.
func writeAsar(t *testing.T, path string, pkg string, integrity string) {
	t.Helper()
	sum := sha256.Sum256([]byte(pkg))
	if integrity == "" {
		integrity = hex.EncodeToString(sum[:])
	}
	idx, _ := json.Marshal(map[string]any{"files": map[string]any{
		"package.json": map[string]any{"size": len(pkg), "offset": "0", "integrity": map[string]any{"algorithm": "SHA256", "hash": integrity}},
	}})
	jsonLen := uint32(len(idx))
	pickle := (jsonLen + 4 + 3) &^ 3 // string length prefix + payload, 4-byte aligned
	buf := make([]byte, 16, 16+int(pickle))
	binary.LittleEndian.PutUint32(buf[0:], 4)
	binary.LittleEndian.PutUint32(buf[4:], pickle+4)
	binary.LittleEndian.PutUint32(buf[8:], pickle)
	binary.LittleEndian.PutUint32(buf[12:], jsonLen)
	buf = append(buf, idx...)
	for uint32(len(buf)) < 8+pickle+4 {
		buf = append(buf, 0)
	}
	buf = append(buf, pkg...)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeRuntime(t *testing.T, name string) string {
	t.Helper()
	self, _ := os.Executable()
	dst := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return dst
}

// startMain runs the fake runtime as an Electron main process and returns the
// main and utility child PIDs.
func startMain(t *testing.T, runtime, mode string, env []string, args ...string) (int, int) {
	t.Helper()
	c := exec.Command(runtime, args...)
	c.Env = append(append(os.Environ(), "FLOWGATE_FAKE_ELECTRON="+mode), env...)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	child, _ := strconv.Atoi(strings.TrimSpace(line))
	t.Cleanup(func() { _ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL); _ = c.Wait() })
	if mode == "orphan" {
		_ = c.Wait()
		t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	}
	// Let exec settle (argv of the child is final once it runs Go code).
	time.Sleep(150 * time.Millisecond)
	return c.Process.Pid, child
}

func TestElectronBundleClaimIsDisplayOnly(t *testing.T) {
	runtime := fakeRuntime(t, "electron")
	bundle := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bundle, `{"name":"synthetic-alpha","main":"main.js"}`, "")
	mainPID, child := startMain(t, runtime, "main", nil, bundle)
	p, err := Inspect(child)
	if err != nil {
		t.Fatal(err)
	}
	a := p.Application
	if a.Kind != "native" || a.Executable != runtime || a.Key != ApplicationKey(p.UID, Application{Kind: "native", Executable: runtime}) || a.Revision != p.ExecutableRevision {
		t.Fatalf("must retain actual executable identity: %+v", a)
	}
	h := a.Hosted
	if h == nil || h.State != "unverified" || h.Bundle != bundle || len(h.Chain) != 2 || h.Chain[1].PID != mainPID || h.PackageName != "synthetic-alpha" {
		t.Fatalf("observed bundle/chain hint lost: %+v", h)
	}
	if !strings.Contains(h.Integrity, "SHA-256 matches") || RuntimeRuleBlocked(&a) == "" || LiveRuleable(a) {
		t.Fatalf("metadata integrity must not confer execution authority: %+v", h)
	}
	// A second claimed bundle on this same executable does not mint another
	// permission identity. Both claims remain ineligible for app-wide rules.
	other := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, other, `{"name":"synthetic-beta"}`, "")
	_, child2 := startMain(t, runtime, "main", nil, other)
	p2, err := Inspect(child2)
	if err != nil || p2.Application.Key != a.Key || LiveRuleable(p2.Application) {
		t.Fatalf("bundle argument became authority: %+v %v", p2.Application, err)
	}
	// A different actual executable claiming the same bundle stays distinct.
	runtime2 := fakeRuntime(t, "electron")
	_, child3 := startMain(t, runtime2, "main", nil, bundle)
	p3, err := Inspect(child3)
	if err != nil || p3.Application.Key == a.Key || p3.Application.Revision == a.Revision || LiveRuleable(p3.Application) {
		t.Fatalf("different executable inherited bundle identity: %+v %v", p3.Application, err)
	}
	target := DescribePermissionTarget(Attribution{Application: &a, Owners: []Process{p}, VisibilityComplete: true})
	if target.Kind != "runtime-unverified" || !strings.HasPrefix(target.Remember, "This process only") {
		t.Fatalf("target: %+v", target)
	}
}

func TestElectronUnverifiedKeepsRuntimeAndBlocksRules(t *testing.T) {
	runtime := fakeRuntime(t, "electron43")
	bundle := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bundle, `{"name":"heroic"}`, "")
	bad := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bad, `{"name":"heroic"}`, strings.Repeat("0", 64))
	cases := []struct {
		name, mode, want string
		env              []string
		args             []string
	}{
		{"no bundle argument", "main", "names no application bundle", nil, []string{"--enable-features=X"}},
		{"inspector", "main", "started with --inspect", nil, []string{"--inspect=9229", bundle}},
		{"node mode", "main", "Node mode", []string{"ELECTRON_RUN_AS_NODE=1"}, []string{bundle}},
		{"integrity mismatch", "main", "does not match the archive's SHA-256", nil, []string{bad}},
		{"missing bundle", "main", "not found", nil, []string{filepath.Join(t.TempDir(), "gone.asar")}},
		{"parent gone", "orphan", "the parent of utility process", nil, []string{bundle}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, child := startMain(t, runtime, c.mode, c.env, c.args...)
			p, err := Inspect(child)
			if err != nil {
				t.Fatal(err)
			}
			a := p.Application
			if a.Kind != "native" || a.Executable != runtime || a.Hosted == nil || a.Hosted.State != "unverified" || !strings.Contains(a.Hosted.Reason, c.want) {
				t.Fatalf("want unverified runtime (%s): %+v hosted %+v", c.want, a, a.Hosted)
			}
			if why := RuntimeRuleBlocked(&a); why == "" || LiveRuleable(a) {
				t.Fatal("an unverified runtime must not bind an application-wide rule")
			}
			target := DescribePermissionTarget(Attribution{Application: &a, Owners: []Process{p}, VisibilityComplete: true})
			if target.Kind != "runtime-unverified" || !strings.HasPrefix(target.Remember, "This process only") || !strings.HasPrefix(target.ForAWhile, "This verified native process") {
				t.Fatalf("permission target: %+v", target)
			}
		})
	}
}

func TestNonRuntimeExecutableIsUntouched(t *testing.T) {
	exe := fakeRuntime(t, "heroic-bundled")
	bundle := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bundle, `{"name":"heroic"}`, "")
	_, child := startMain(t, exe, "main", nil, bundle)
	p, err := Inspect(child)
	if err != nil || p.Application.Kind != "native" || p.Application.Hosted != nil || !LiveRuleable(p.Application) {
		t.Fatalf("an app shipping its own executable keeps its executable identity: %+v %v", p.Application, err)
	}
}

func TestElectronRuntimeNames(t *testing.T) {
	for exe, want := range map[string]bool{"/usr/bin/electron": true, "/usr/lib/electron43/electron": true, "/usr/bin/electron43": true, "/opt/Heroic/heroic": false, "/usr/bin/electronic": false} {
		if IsElectronRuntime(exe) != want {
			t.Errorf("%s: want %v", exe, want)
		}
	}
}

func TestLaunchedByElectronClaimHasNoApplicationAuthority(t *testing.T) {
	runtime := fakeRuntime(t, "electron43")
	helper := fakeRuntime(t, "synthetic-helper")
	bundle := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bundle, `{"name":"synthetic-alpha"}`, "")
	mainPID, child := startMain(t, runtime, "launcher", []string{"FLOWGATE_FAKE_HELPER=" + helper}, bundle)
	p, err := Inspect(child)
	if err != nil {
		t.Fatal(err)
	}
	if p.Application.Kind != "native" || p.Application.Executable != helper || p.Application.Hosted != nil {
		t.Fatalf("helper identity: %+v", p.Application)
	}
	prov := CaptureProvenance(p)
	if prov == nil || prov.Parent == nil {
		t.Fatalf("missing observed parent: %+v", prov)
	}
	pa := prov.Parent
	if pa.PID != mainPID || pa.Depth != 1 || pa.Application != nil || !strings.Contains(pa.Note, "unverified") {
		t.Fatalf("parent hint must not mint authority: %+v", pa)
	}
	again := CaptureProvenance(p)
	again.Parent.Note = "changed"
	if CaptureProvenance(p).Parent.Note == "changed" {
		t.Fatal("cache shares parent")
	}
}

func TestLaunchedBySkipsInfrastructure(t *testing.T) {
	owner := Process{PID: 10, Start: "1", UID: 1000, Executable: "/usr/bin/nile"}
	nodes := []procNode{
		{pid: 10, start: "1", uid: 1000, exe: "/usr/bin/nile"},
		{pid: 9, start: "1", uid: 1000, exe: "/usr/bin/fish"},
		{pid: 8, start: "1", uid: 1000, exe: "/usr/bin/tmux"},
		{pid: 7, start: "1", uid: 1000, exe: "/usr/bin/konsole"},
		{pid: 6, start: "1", uid: 1000, exe: "/usr/bin/plasmashell"},
	}
	if p := launchedBy(owner, nodes, nil); p != nil {
		t.Fatalf("infrastructure only: %+v", p)
	}
	nodes = append(nodes[:2], procNode{pid: 5, start: "1", uid: 1000, exe: "/usr/bin/python3", argv: []string{"python3", "/opt/x/launcher.py"}})
	if p := launchedBy(owner, nodes, nil); p == nil || p.Name != "python3 launcher.py" || p.Depth != 2 {
		t.Fatalf("script launcher: %+v", p)
	}
	nodes[1] = procNode{pid: 9, start: "1", uid: 0, exe: "/usr/bin/sudo"}
	if p := launchedBy(owner, nodes, nil); p != nil {
		t.Fatalf("another principal never launches as this user: %+v", p)
	}
}

func TestElectronClaimAllowsOnlyNativeProcessBinding(t *testing.T) {
	runtime := fakeRuntime(t, "electron")
	bundle := filepath.Join(t.TempDir(), "app.asar")
	writeAsar(t, bundle, `{"name":"synthetic-alpha"}`, "")
	for _, args := range [][]string{{bundle}, {"--enable-features=X"}} {
		_, child := startMain(t, runtime, "main", nil, args...)
		p, err := Inspect(child)
		if err != nil {
			t.Fatal(err)
		}
		b, err := BindInstance("session", p)
		if err != nil || !b.Matches(p) {
			t.Fatalf("native process binding: %v", err)
		}
		if LiveRuleable(p.Application) {
			t.Fatal("bundle hints granted application authority")
		}
		other := p
		other.PID++
		other.ThreadGroup = other.PID
		if b.Matches(other) {
			t.Fatal("permission transferred to another process")
		}
		other = p
		other.Start += "0"
		if b.Matches(other) {
			t.Fatal("permission transferred after relaunch")
		}
		other = p
		other.Application.Kind = "electron"
		if _, err := BindInstance("session", other); err == nil {
			t.Fatal("legacy bundle identity revived")
		}
	}
}

// Large single-file CLIs (codex ~290 MB, claude ~240 MB) run sandboxed in their
// own mount namespace; their identity must stay re-verifiable after exit.
func TestDigestCapCoversLargeCLIs(t *testing.T) {
	if MaxExecutableDigestBytes < 512<<20 || digestBudgetBytes < 2*MaxExecutableDigestBytes {
		t.Fatalf("digest cap %d / budget %d too small for large CLIs", MaxExecutableDigestBytes, digestBudgetBytes)
	}
}
