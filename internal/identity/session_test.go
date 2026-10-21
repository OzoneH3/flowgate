package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceAttachmentBoundary(t *testing.T) {
	// Tests run with TMPDIR inside the workspace, as required by go-env.sh.
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(root)
	if err = os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	if _, err = workspacePath("/usr/bin"); err == nil {
		t.Fatal("outside workspace accepted")
	}
	if _, err = AttachRuntimes(nil, []string{"/usr/bin"}, "missing"); err == nil {
		t.Fatal("empty selection accepted")
	}
	if _, err = DiscoverRuntimes(make([]string, 5), ""); err == nil {
		t.Fatal("unbounded runtime directories")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "outside")
	if err = os.Symlink("/usr/bin", target); err != nil {
		t.Fatal(err)
	}
	if _, err = workspacePath(target); err == nil {
		t.Fatal("symlink escape accepted")
	}
	if supportedCensusVersion("unknown") {
		t.Fatal("unknown runtime contract supported")
	}
}
