package diagnostics

import (
	"flowgate/internal/readiness"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeInspectionCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")
	if c := RuntimePath(absent, 0700); c.Status != readiness.Unchecked || c.Code != "runtime_absent" {
		t.Fatal(c)
	}
	if _, e := os.Stat(absent); !os.IsNotExist(e) {
		t.Fatal("doctor created directory")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	if c := RuntimePath(link, 0700); c.Status != readiness.Blocked || c.Code != "runtime_path_invalid" {
		t.Fatal(c)
	}
}

func TestHumanExplainsPerCheckReadiness(t *testing.T) {
	var b strings.Builder
	Human(&b, Report{Kernel: "fixture", Architecture: "amd64", Checks: []readiness.Check{{ID: "fixture", Status: readiness.Unchecked, Code: "permission_required", Detail: "Not inspected"}}})
	if !strings.Contains(b.String(), "not_checked") || !strings.Contains(b.String(), "never overall activation") {
		t.Fatal(b.String())
	}
}
