package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObsoleteNativeRevision(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	if err := os.MkdirAll(proc+"/self/ns", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[1]", proc+"/self/ns/mnt"); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "runtime3.13")
	newer := filepath.Join(dir, "runtime3.14")
	for _, p := range []string{old, newer} {
		if err := os.WriteFile(p, []byte(p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	key := ApplicationKey(1000, Application{Kind: "native", Executable: old})
	original := stamp(old)
	check := func(rev string) bool { return obsoleteNativeRevision(proc, old, key, rev, 1000) }
	if check(original) {
		t.Fatal("side-by-side newer runtime removed still-installed older runtime")
	}
	retired := filepath.Join(dir, "retired")
	if err := os.Rename(old, retired); err != nil {
		t.Fatal(err)
	}
	original = stamp(retired)
	if check(original) {
		t.Fatal("missing executable treated as obsolete")
	}
	if err := os.WriteFile(old, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	if !check(original) {
		t.Fatal("replaced executable not detected")
	}
	if obsoleteNativeRevision(proc, old, ApplicationKey(1000, Application{Kind: "wine", Executable: old, Prefix: "/prefix"}), original, 1000) {
		t.Fatal("Wine identity removed")
	}
	if obsoleteNativeRevision(proc, old, key, original, 970) {
		t.Fatal("other user identity removed")
	}
	if err := os.MkdirAll(proc+"/123/ns", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc+"/123/stat", []byte("123 (test) S 1 1 1 1 1 0"), 0600); err != nil {
		t.Fatal(err)
	}
	if check(original) {
		t.Fatal("incomplete process visibility removed rule")
	}
	if err := os.Symlink(retired, proc+"/123/exe"); err != nil {
		t.Fatal(err)
	}
	if check(original) {
		t.Fatal("running old executable removed")
	}
	if err := os.Chmod(retired, 0600); err != nil {
		t.Fatal(err)
	}
	if check(original) {
		t.Fatal("changed ctime hid running old inode")
	}
	if err := os.Remove(proc + "/123/exe"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, proc+"/123/exe"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[2]", proc+"/123/ns/mnt"); err != nil {
		t.Fatal(err)
	}
	if check(original) {
		t.Fatal("unknown namespace view removed rule")
	}
	if err := os.Remove(proc + "/123/ns/mnt"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[1]", proc+"/123/ns/mnt"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", proc+"/123/root"); err != nil {
		t.Fatal(err)
	}
	if !check(original) {
		t.Fatal("current running executable prevented obsolete cleanup")
	}
}
