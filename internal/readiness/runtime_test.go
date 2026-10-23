package readiness

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestRuntimeCapabilityIndependentOfModuleTree(t *testing.T) {
	missing := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	checks := runtimeChecks("kernel-test", nil, missing, func() error { return nil })
	if checks[0].Code != "module_tree_unavailable" || checks[1].Status != Ready {
		t.Fatal(checks)
	}
	checks = runtimeChecks("kernel-test", nil, missing, func() error { return syscall.ENOENT })
	if checks[1].Status != Optional || checks[1].Next != checks[0].Next {
		t.Fatal(checks)
	}
	checks = runtimeChecks("", errors.New("read failed"), missing, func() error { return syscall.EPERM })
	if checks[0].Code == "module_tree_present" || checks[1].Status != Optional {
		t.Fatal(checks)
	}
}
func TestRuntimeSnapshotCannotChangePublishedHealth(t *testing.T) {
	m := &RuntimeMonitor{checks: []Check{{ID: "original"}}}
	snapshot := m.Snapshot()
	snapshot[0].ID = "changed"
	if m.Snapshot()[0].ID != "original" {
		t.Fatal("mutable snapshot")
	}
}
