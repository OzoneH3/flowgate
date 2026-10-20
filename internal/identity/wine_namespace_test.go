package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamespaceFileRequiresSameLiveFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "observer.exe")
	if err := os.WriteFile(f, []byte("MZ"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := namespaceFile(os.Getpid(), f); err != nil || got != f {
		t.Fatal(got, err)
	}
	if _, err := namespaceFile(1<<28, f); err == nil {
		t.Fatal("dead target accepted")
	}
}
func TestNamespaceEntryPinsDescriptorsAndDropsBothCredentials(t *testing.T) {
	n := &wineNamespace{runner: "/runtime/wine", helper: "/verified/observer.exe", uid: 1000, gid: 1001}
	c := n.command()
	s := strings.Join(c.Args, " ")
	for _, need := range []string{"--mount=/proc/self/fd/3", "--root=/proc/self/fd/4", "--setgid=1001", "--setuid=1000", "-- /runtime/wine /verified/observer.exe"} {
		if !strings.Contains(s, need) {
			t.Fatal(s)
		}
	}
	for _, bad := range []string{"--all", "--net", "--user", "--env", "--target"} {
		if strings.Contains(s, bad) {
			t.Fatal("unbounded namespace entry", s)
		}
	}
	if len(c.ExtraFiles) != 2 {
		t.Fatal("missing pinned namespace/root descriptors")
	}
}
