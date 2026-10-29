package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNodeUtilityScopeAndArchiveBoundary(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	entry := filepath.Join(root, "entry.cjs")
	os.WriteFile(entry, []byte("fixture"), 0600)
	archive := filepath.Join(root, "modules.asar")
	os.WriteFile(archive, []byte("fixture archive"), 0600)
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !sharedPackageArchive(os.Getpid(), os.Getpid(), entry) {
		t.Fatal("shared package archive missed")
	}
	if sharedPackageArchive(os.Getpid(), os.Getpid(), outside) {
		t.Fatal("foreign package archive accepted")
	}
	a := Application{Kind: "electron", Runtime: "/runtime", Executable: entry, Hosted: &Hosted{State: "best-effort"}}
	main := ApplicationKey(1000, a)
	a.Hosted.Scope = "node-utilities"
	utility := ApplicationKey(1000, a)
	if utility == main || utility == ApplicationKey(1001, a) {
		t.Fatal("utility/main/user identities merged")
	}
	a.Executable = filepath.Join(outside, "entry.cjs")
	if utility == ApplicationKey(1000, a) {
		t.Fatal("independent package merged")
	}
	f.Close()
	foreign := filepath.Join(outside, "foreign.asar")
	os.WriteFile(foreign, []byte("foreign"), 0600)
	if err := os.Symlink(foreign, filepath.Join(root, "linked.asar")); err != nil {
		t.Fatal(err)
	}
	escaped, err := os.Open(filepath.Join(root, "linked.asar"))
	if err != nil {
		t.Fatal(err)
	}
	defer escaped.Close()
	if sharedPackageArchive(os.Getpid(), os.Getpid(), entry) {
		t.Fatal("closed archive accepted")
	}
}
