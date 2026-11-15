package identity

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
)

func TestAppImageMountBinding(t *testing.T) {
	info := "1 0 0:1 / / rw - tmpfs tmp rw\n2 1 0:42 / /temporary ro,nosuid,nodev - fuse.any display-only ro,user_id=1000,group_id=1000\n"
	r := ownerExeRequest{Exe: "/temporary/bin/program", UID: 1000, GID: 1000, Dev: unix.Mkdev(0, 42)}
	m, e := appImageMountFor(info, r)
	if e != nil || m.Relative != "bin/program" || m.Connection != 42 {
		t.Fatal(m, e)
	}
	for _, bad := range []string{strings.Replace(info, "ro,nosuid", "rw,nosuid", 1), strings.Replace(info, "0:42 / /temporary", "0:42 /subdir /temporary", 1), strings.Replace(info, "0:42", "0:43", 1), strings.Replace(info, "ro,user_id", "ro,allow_other,user_id", 1), strings.Replace(info, "user_id=1000", "user_id=1001", 1), info + "3 2 0:43 / /temporary/bin ro - tmpfs other ro\n", info + strings.Split(info, "\n")[1] + "\n"} {
		if _, e = appImageMountFor(bad, r); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, path := range []string{"/temporary", "/temporary-other/bin/program"} {
		r.Exe = path
		if _, e = appImageMountFor(info, r); e == nil {
			t.Fatal(path)
		}
	}
}
func TestAppImageConnectionStrict(t *testing.T) {
	n, e := fuseConnection("pos:\t0\nfuse_connection:\t42\n")
	if e != nil || n != 42 {
		t.Fatal(n, e)
	}
	for _, s := range []string{"", "fuse_connection: 0", "fuse_connection: -1", "fuse_connection: x", "fuse_connection: 1 2", "fuse_connection: 1\nfuse_connection: 1"} {
		if _, e = fuseConnection(s); e == nil {
			t.Fatal(s)
		}
	}
}
func TestAppImageIdentityRemountSeparationAndNoJSONAuthority(t *testing.T) {
	mk := func(mount, archive, inner string) Application {
		return Application{Kind: "native", Executable: mount + "/" + inner, Revision: "inode-specific", AppImage: &AppImageIdentity{Container: archive, RelativeExecutable: inner, ContainerRevision: "stamp", verified: true}}
	}
	a := mk("/mount-one", "/apps/one", "bin/app")
	b := mk("/mount-two", "/apps/one", "bin/app")
	key := ApplicationKey(1000, a)
	if key != ApplicationKey(1000, b) {
		t.Fatal("remount changes key")
	}
	for _, q := range []Application{mk("/mount-two", "/apps/two", "bin/app"), mk("/mount-two", "/apps/one", "bin/helper"), {Kind: "native", Executable: a.KeyPath(), Revision: "stamp"}} {
		if ApplicationKey(1000, q) == key {
			t.Fatal("cross executable/archive transfer")
		}
	}
	if ApplicationKey(1001, a) == key {
		t.Fatal("cross user transfer")
	}
	raw, _ := json.Marshal(a)
	var forged Application
	json.Unmarshal(raw, &forged)
	if verifiedAppImage(forged) || ApplicationKey(1000, forged) == key {
		t.Fatal("serialized claim gained authority")
	}
}

// Run only in a disconnected guest containing two real AppImage fixtures.
func TestAppImageGuestBindingNegatives(t *testing.T) {
	raw := os.Getenv("FLOWGATE_APPIMAGE_TEST_PID")
	if raw == "" {
		t.Skip("guest only")
	}
	var pid int
	fmt.Sscan(raw, &pid)
	if !strings.Contains(string(readBound("/proc/cmdline", 4096)), "rdinit=/init") {
		t.Fatal("not guest")
	}
	p, e := Inspect(pid)
	if e != nil || !verifiedAppImage(p.Application) {
		st, err := executableStat(fmt.Sprintf("/proc/%d/exe", pid))
		_, reason := observeAppImage(pid, st)
		t.Fatal(p, e, err, reason)
	}
	r, e := ownerExeAnchor(pid, pid)
	if e != nil {
		t.Fatal(e)
	}
	m, e := appImageMountFor(string(readBound(fmt.Sprintf("/proc/%d/mountinfo", pid), 1<<20)), r)
	if e != nil {
		t.Fatal(e)
	}
	provider, e := discoverAppImageProvider(r, m)
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*appImageLocator, *ownerExeRequest, *appImageMount){
		"generation":   func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { l.Start = "different" },
		"archive-path": func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { l.Path = "/wrong" },
		"namespace":    func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { r.MountNS = "wrong" },
		"uid":          func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { r.UID++ },
		"connection":   func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { m.Connection++ },
		"archive-fd":   func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { l.ArchiveFD = l.FuseFD },
		"fuse-fd":      func(l *appImageLocator, r *ownerExeRequest, m *appImageMount) { l.FuseFD = l.ArchiveFD },
	} {
		t.Run(name, func(t *testing.T) {
			l, q, n := provider.Locator, r, m
			mutate(&l, &q, &n)
			if _, e := inspectAppImageProvider(l, q, n); e == nil {
				t.Fatal("accepted changed witness")
			}
		})
	}
	if e = VerifyInstanceExecutable(pid, p.Start, p.Application); e != nil {
		t.Fatal(e)
	}
	retained, e := CaptureExecutable(p, p.Application)
	if e != nil {
		t.Fatal(e)
	}
	if retained != nil {
		retained.Release()
	}
}

func TestAppImageMarkerDoesNotAuthorizeRuntime(t *testing.T) {
	p := t.TempDir() + "/unknown"
	b := make([]byte, appImageRuntimeSize+4)
	copy(b, "\x7fELF")
	copy(b[8:], "AI\x02")
	copy(b[appImageRuntimeSize:], "hsqs")
	if e := os.WriteFile(p, b, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := appImageHeader(p); e == nil {
		t.Fatal("format marker accepted as runtime authority")
	}
}
