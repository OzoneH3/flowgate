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

func TestSharedObsoleteCensusKeepsRunningVersionAcrossCandidates(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	if err := os.MkdirAll(proc+"/self/ns", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[1]", proc+"/self/ns/mnt"); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "alpha"), filepath.Join(dir, "beta")}
	revisions := make([]string, 2)
	for i, p := range paths {
		if err := os.WriteFile(p, []byte("old"), 0700); err != nil {
			t.Fatal(err)
		}
		revisions[i] = stamp(p)
		if err := os.Rename(p, p+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("replacement"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(proc+"/123/ns", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc+"/123/stat", []byte("123 (test) S 1 1 1 1 1 0"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{paths[0] + ".old", proc + "/123/exe"}, {"mnt:[1]", proc + "/123/ns/mnt"}, {"/", proc + "/123/root"}} {
		if err := os.Symlink(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	check := newObsoleteNativeChecker(proc)
	for i, p := range paths {
		got := check(p, ApplicationKey(1000, Application{Kind: "native", Executable: p}), revisions[i], 1000)
		if got != (i == 1) {
			t.Fatalf("candidate %d obsolete=%v", i, got)
		}
	}
	// A later cleanup gets a new census; an unknown live owner retains the rule.
	if err := os.Mkdir(proc+"/124", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc+"/124/stat", []byte("124 (test) S 1 1 1 1 1 0"), 0600); err != nil {
		t.Fatal(err)
	}
	if newObsoleteNativeChecker(proc)(paths[1], ApplicationKey(1000, Application{Kind: "native", Executable: paths[1]}), revisions[1], 1000) {
		t.Fatal("census reused across cleanups")
	}
}
