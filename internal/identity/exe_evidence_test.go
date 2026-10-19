package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evidenceApp(t *testing.T, path string, uid uint32) Application {
	t.Helper()
	a := Application{Kind: "native", Name: filepath.Base(path), Executable: path, Revision: stamp(path)}
	a.Key = ApplicationKey(uid, a)
	return a
}

func hostResolver(host string) func(string, uint64, uint64) (string, string, string) {
	return func(string, uint64, uint64) (string, string, string) {
		if host == "" {
			return "", "", "no host-visible file (test sandbox)"
		}
		return host, "mountinfo", ""
	}
}

func alive() error { return nil }

func capture(t *testing.T, path, nsPath string, uid uint32, host string) (*RetainedExecutable, Application) {
	t.Helper()
	a := evidenceApp(t, path, uid)
	r, err := captureEvidence(path, nsPath, Process{PID: 4242, Start: "77", UID: uid, MountNS: "mnt:[sandbox]"}, a, alive, hostResolver(host))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Wait(5 * time.Second) {
		t.Fatal("digest did not finish")
	}
	return r, a
}

func code(err error) string {
	var re *RetainedError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

func TestCaptureEvidenceDigestCacheAndReferenceCleanup(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "steamerrorreporter")
	content := []byte("\x7fELF fixture executable content")
	if err := os.WriteFile(exe, content, 0o755); err != nil {
		t.Fatal(err)
	}
	base := OpenExecutableReferences()
	before := digestsComputed()
	r, a := capture(t, exe, "/run/pressure-vessel/x/steamerrorreporter", 1000, exe)
	ev := r.Evidence()
	sum := sha256.Sum256(content)
	if ev.DigestState != "done" || ev.SHA256 != hex.EncodeToString(sum[:]) || ev.Stamp != a.Revision || ev.Visibility != VisibilityHost || ev.HostPath != exe || ev.PID != 4242 || ev.Start != "77" || ev.UID != 1000 {
		t.Fatalf("evidence %+v", ev)
	}
	if r.HeldReference() || OpenExecutableReferences() != base {
		t.Fatal("executable reference not closed after the digest", OpenExecutableReferences(), base)
	}
	if digestsComputed() != before+1 {
		t.Fatal("digest not computed exactly once")
	}
	// Same file (same stamp): served from the cache, no second hash, no fd kept.
	r2, _ := capture(t, exe, exe, 1000, exe)
	if r2.Evidence().SHA256 != ev.SHA256 || digestsComputed() != before+1 || r2.HeldReference() {
		t.Fatal("digest cache not used", digestsComputed(), before)
	}
	r.Release()
	r.Release() // idempotent
	if OpenExecutableReferences() != base {
		t.Fatal("reference count drifted")
	}
	if err := VerifyRetainedEvidence(a, 1000, ev); err != nil {
		t.Fatal("unchanged host backing file refused:", err)
	}
}

func TestCaptureRefusesChangedProcessOrRevisionWithoutLeak(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	os.WriteFile(exe, []byte("one"), 0o755)
	a := evidenceApp(t, exe, 1000)
	base := OpenExecutableReferences()
	calls := 0
	reused := func() error {
		calls++
		if calls > 1 {
			return errors.New("pid reused")
		}
		return nil
	}
	if _, err := captureEvidence(exe, exe, Process{PID: 1, Start: "1", UID: 1000}, a, reused, hostResolver(exe)); err == nil {
		t.Fatal("PID reuse between attribution and open accepted")
	}
	stale := a
	stale.Revision = "1:2:3:4:5"
	if _, err := captureEvidence(exe, exe, Process{PID: 1, Start: "1", UID: 1000}, stale, alive, hostResolver(exe)); err == nil {
		t.Fatal("executable changed since attribution accepted")
	}
	if OpenExecutableReferences() != base {
		t.Fatal("refused capture leaked a reference")
	}
}

func TestRetainedEvidenceRefusesModifiedReplacedAndOtherUser(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	os.WriteFile(exe, []byte("original"), 0o755)
	r, a := capture(t, exe, "/sandbox/app", 1000, exe)
	ev := r.Evidence()
	if err := VerifyRetainedEvidence(a, 1001, ev); code(err) != CodeExecutableChanged {
		t.Fatal("different UID accepted:", err)
	}
	// Modified in place (same inode): size/mtime/ctime differ.
	f, _ := os.OpenFile(exe, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("x"))
	f.Close()
	if err := VerifyRetainedEvidence(a, 1000, ev); code(err) != CodeExecutableChanged || !strings.Contains(err.Error(), "modified") {
		t.Fatal("modified executable accepted:", err)
	}
	// Replaced at the same path (new inode, identical-looking name).
	tmp := exe + ".new"
	os.WriteFile(tmp, []byte("original"), 0o755)
	os.Rename(tmp, exe)
	if err := VerifyRetainedEvidence(a, 1000, ev); code(err) != CodeExecutableChanged || !strings.Contains(err.Error(), "different file") {
		t.Fatal("replaced executable accepted:", err)
	}
	os.Remove(exe)
	if err := VerifyRetainedEvidence(a, 1000, ev); code(err) != CodeExecutableChanged || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal("deleted executable accepted:", err)
	}
	// Forged digest with an unchanged file still fails.
	exe2 := filepath.Join(dir, "app2")
	os.WriteFile(exe2, []byte("two"), 0o755)
	r2, a2 := capture(t, exe2, exe2, 1000, exe2)
	ev2 := r2.Evidence()
	ev2.SHA256 = strings.Repeat("0", 64)
	if err := VerifyRetainedEvidence(a2, 1000, ev2); code(err) != CodeExecutableChanged {
		t.Fatal("digest mismatch accepted:", err)
	}
}

func TestSandboxOnlyAndUndigestedEvidenceIsUnverifiable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	os.WriteFile(exe, []byte("tmpfs only"), 0o755)
	r, a := capture(t, exe, "/tmp/pv-tmpfs/app", 1000, "")
	ev := r.Evidence()
	if ev.Visibility != VisibilitySandboxOnly || ev.HostPath != "" {
		t.Fatalf("%+v", ev)
	}
	err := VerifyRetainedEvidence(a, 1000, ev)
	if code(err) != CodeIdentityUnverifiable || !strings.Contains(err.Error(), "mountns") || !strings.Contains(err.Error(), "/tmp/pv-tmpfs/app") {
		t.Fatal("sandbox-only executable not refused precisely:", err)
	}
	// Larger than the digest cap (sparse): no digest, so no persistent identity.
	big := filepath.Join(dir, "big")
	f, _ := os.Create(big)
	f.Truncate(MaxExecutableDigestBytes + 1)
	f.Close()
	rb, ab := capture(t, big, big, 1000, big)
	if rb.Evidence().DigestState != "too-large" || rb.HeldReference() {
		t.Fatal(rb.Evidence())
	}
	if err := VerifyRetainedEvidence(ab, 1000, rb.Evidence()); code(err) != CodeIdentityUnverifiable {
		t.Fatal("undigested evidence accepted:", err)
	}
	// Legacy path: another mount namespace without evidence.
	if err := VerifyRetainedExecutable(a, 1000, "mnt:[1]"); code(err) != CodeIdentityUnverifiable {
		t.Fatal(err)
	}
}

func TestMountinfoMapsNamespaceInstancesToOneHostPath(t *testing.T) {
	self := `22 1 0:31 /@ / rw shared:1 - btrfs /dev/nvme0n1p2 rw
23 22 0:31 /@home /home rw shared:2 - btrfs /dev/nvme0n1p2 rw
30 22 0:5 / /dev rw - devtmpfs devtmpfs rw
`
	inst := func(dir string) string {
		return `400 300 0:31 /@ / rw - btrfs /dev/nvme0n1p2 rw
401 400 0:77 / /tmp/pv rw - tmpfs tmpfs rw
402 401 0:31 /@home/u/.local/share/Steam/ubuntu12_32 /tmp/pv/` + dir + ` rw - btrfs /dev/nvme0n1p2 rw
403 400 0:31 /@home/u/My\040Games /games rw - btrfs /dev/nvme0n1p2 rw
`
	}
	a := mountCandidates("/tmp/pv/inst-1/steamerrorreporter", inst("inst-1"), self)
	b := mountCandidates("/tmp/pv/inst-2/steamerrorreporter", inst("inst-2"), self)
	want := "/home/u/.local/share/Steam/ubuntu12_32/steamerrorreporter"
	if len(a) != 1 || a[0] != want || len(b) != 1 || b[0] != want {
		t.Fatal(a, b)
	}
	if c := mountCandidates("/games/x.exe", inst("i"), self); len(c) != 1 || c[0] != "/home/u/My Games/x.exe" {
		t.Fatal("escaped mount path", c)
	}
	// A file on the sandbox tmpfs has no host mount of its device.
	if c := mountCandidates("/tmp/pv/app", inst("i"), self); len(c) != 0 {
		t.Fatal("tmpfs-only file mapped to the host", c)
	}
	// Key derivation follows the proven host path, not the per-instance path.
	k1 := ApplicationKey(1000, Application{Kind: "native", Executable: "/tmp/pv/inst-1/steamerrorreporter", HostExecutable: want})
	k2 := ApplicationKey(1000, Application{Kind: "native", Executable: "/tmp/pv/inst-2/steamerrorreporter", HostExecutable: want})
	k3 := ApplicationKey(1001, Application{Kind: "native", Executable: "/tmp/pv/inst-2/steamerrorreporter", HostExecutable: want})
	if k1 != k2 || k1 == k3 {
		t.Fatal("key derivation")
	}
}

func TestHostBackingPathSameFileAndRealCapture(t *testing.T) {
	// The test binary itself: a real /proc/self/exe capture in our namespace.
	p, err := Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if p.Application.HostExecutable != "" {
		t.Fatal("same-namespace process got a host key path", p.Application)
	}
	r, err := CaptureExecutable(p, p.Application)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Release()
	if !r.Wait(30 * time.Second) {
		t.Fatal("digest timeout")
	}
	ev := r.Evidence()
	if ev.Visibility != VisibilityHost || ev.HostSource != "same-path" || ev.HostPath != p.Executable || ev.SHA256 == "" {
		t.Fatalf("%+v", ev)
	}
	if err := VerifyRetainedEvidence(p.Application, p.UID, ev); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstanceExecutable(p.PID, p.Start, p.Application); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstanceExecutable(p.PID, "0", p.Application); code(err) != CodeIdentityUnverifiable {
		t.Fatal("other instance accepted", err)
	}
}
