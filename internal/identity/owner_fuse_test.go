package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestOwnerFuseGateUsesLongestMountAndExactCredentials(t *testing.T) {
	info := "1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:42 / /mount rw - fuse.synthetic display-only ro,user_id=1000,group_id=1000\n"
	for _, q := range []struct {
		path     string
		uid, gid uint32
		want     bool
	}{{"/mount/app", 1000, 1000, true}, {"/mount/app", 1001, 1000, false}, {"/mount/app", 1000, 1001, false}, {"/mount-prefix/app", 1000, 1000, false}} {
		_, ok := ownerFuseMount(info, q.path, q.uid, q.gid)
		if ok != q.want {
			t.Fatal(q, ok)
		}
	}
	if _, ok := ownerFuseMount(info+"3 2 0:43 / /mount/inner rw - tmpfs tmp rw\n", "/mount/inner/app", 1000, 1000); ok {
		t.Fatal("ignored nested non-FUSE mount")
	}
	if _, ok := ownerFuseMount(strings.ReplaceAll(info, "ro,user_id", "ro,allow_other,user_id"), "/mount/app", 1000, 1000); ok {
		t.Fatal("not exceptional owner-only mount")
	}
}
func TestOwnerFuseCredentialsRejectMixedOrMissing(t *testing.T) {
	good := "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t3 1000\n"
	u, g, groups, e := ownerCredentials(good)
	if e != nil || u != 1000 || g != 1000 || len(groups) != 2 {
		t.Fatal(u, g, groups, e)
	}
	for _, s := range []string{strings.Replace(good, "1000 1000 1000 1000", "1000 0 1000 1000", 1), strings.ReplaceAll(good, "1000", "0"), "Uid: 1000 1000 1000 1000\n", good + "Uid: 1000 1000 1000 1000\n"} {
		if _, _, _, e := ownerCredentials(s); e == nil {
			t.Fatal("accepted invalid credentials", s)
		}
	}
}
func TestOwnerFuseMapsTwoApplicationsDoNotTransfer(t *testing.T) {
	a := "100-200 r-xp 0 00:2a 41 /mount/app-a\n"
	b := "200-300 r-xp 0 00:2b 42 /mount/app-b\n"
	da, ia, e := mappedExecutable(a+b, "/mount/app-a")
	if e != nil || da != unix.Mkdev(0, 42) || ia != 41 {
		t.Fatal(da, ia, e)
	}
	db, ib, e := mappedExecutable(a+b, "/mount/app-b")
	if e != nil || db == da || ib == ia {
		t.Fatal(db, ib, e)
	}
	if _, _, e := mappedExecutable(a, "/mount/app-b"); e == nil {
		t.Fatal("cross application mapping accepted")
	}
	if _, _, e := mappedExecutable(a+strings.Replace(a, " 41 ", " 42 ", 1), "/mount/app-a"); e == nil {
		t.Fatal("ambiguous mapping")
	}
}
func TestOwnerFuseGenerationAndMappingBookends(t *testing.T) {
	r := ownerExeRequest{PID: 1, TID: 2, Start: "3", GroupStart: "4", Exe: "/mapped/app", MountNS: "mnt", UID: 1000, GID: 1000, Dev: 1, Ino: 2, Groups: []uint32{3, 1000}}
	for _, change := range []func(*ownerExeRequest){func(q *ownerExeRequest) { q.Start = "new" }, func(q *ownerExeRequest) { q.GroupStart = "new" }, func(q *ownerExeRequest) { q.Ino++ }, func(q *ownerExeRequest) { q.Dev++ }, func(q *ownerExeRequest) { q.UID++ }, func(q *ownerExeRequest) { q.Exe = "/other" }, func(q *ownerExeRequest) { q.MountNS = "other" }} {
		q := r
		change(&q)
		if sameOwnerExe(r, q) {
			t.Fatal("changed identity accepted")
		}
	}
	q := r
	q.Hash = true
	if !sameOwnerExe(r, q) {
		t.Fatal("operation changes identity")
	}
}
func TestOwnerFuseTargetStrictProcOnly(t *testing.T) {
	for _, s := range []string{"/tmp/app", "/proc/self/exe", "/proc/01/exe", "/proc/1/task/../exe", "/proc/1/root/app", "/proc/0/exe"} {
		if _, _, ok := procExeTarget(s); ok {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"/proc/1/exe", "/proc/1/task/2/exe"} {
		if _, _, ok := procExeTarget(s); !ok {
			t.Fatal(s)
		}
	}
}
func TestOwnerFuseFileInfoKeepsNormalRevision(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "exe")
	if e != nil {
		t.Fatal(e)
	}
	f.WriteString("synthetic native application")
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	other := ownerExeInfo{*st.Sys().(*syscall.Stat_t)}
	if statStamp(st) != statStamp(other) || other.Size() != st.Size() || other.Mode() != st.Mode() || !other.ModTime().Equal(st.ModTime()) {
		t.Fatal("revision changed")
	}
}
func TestOwnerFuseHelperRejectsCredentialsBeforeAnyOpen(t *testing.T) {
	if err := RunOwnerExecutableHelper([]string{`{"PID":1,"TID":1,"UID":0,"GID":0}`}); err == nil {
		t.Fatal("accepted root helper")
	}
	if err := RunOwnerExecutableHelper([]string{`{"PID":1,"TID":1,"UID":4294967294,"GID":4294967294}`}); err == nil {
		t.Fatal("accepted wrong helper uid")
	}
}

func TestOwnerFuseRealGuestRetention(t *testing.T) {
	raw := os.Getenv("FLOWGATE_FUSE_TEST_PID")
	if raw == "" {
		t.Skip("disposable guest fixture only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root guest required")
	}
	cmdline, e := os.ReadFile("/proc/cmdline")
	if e != nil || !strings.Contains(string(cmdline), "rdinit=/init") {
		t.Fatal("disposable guest kernel required")
	}
	parent := os.Getenv("FLOWGATE_PARENT_BOOT_ID")
	if parent == "" || parent == BootID() {
		t.Fatal("parent boot identity guard")
	}
	pid, e := strconv.Atoi(raw)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Inspect(pid)
	if e != nil || p.Application.Key == "" {
		t.Fatal(p, e)
	}
	evidence, e := CaptureExecutable(p, p.Application)
	if e != nil {
		t.Fatal(e)
	}
	defer evidence.Release()
	ev := evidence.Evidence()
	expected, e := os.ReadFile(os.Getenv("FLOWGATE_FUSE_TEST_RAW"))
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(expected)
	if ev.Stamp != p.Application.Revision || ev.SHA256 != hex.EncodeToString(h[:]) || ev.DigestState != "done" || ev.Visibility != VisibilitySandboxOnly {
		t.Fatal(ev)
	}
	if _, e = os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); !os.IsPermission(e) {
		t.Fatal("baseline root EACCES not reproduced", e)
	}
	t.Logf("retained exact stamp=%s hash=%s uid=%d inode=%d; no stable backing claimed", ev.Stamp, ev.SHA256, ev.UID, ev.Inode)
}
