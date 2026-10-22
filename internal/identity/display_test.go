package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestDeletedExecutableDisplayRetainsRunningIdentity(t *testing.T) {
	data, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "native-display")
	if err = os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "30")
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	before, err := Inspect(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Replacement at the same name is not the running image.
	if err = os.WriteFile(path, append(data, 0), 0700); err != nil {
		t.Fatal(err)
	}
	p, err := Inspect(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	a := p.Application
	if a.Executable != path+" (deleted)" || a.DisplayExecutable != path || a.DisplayName != "native-display" || a.ExecutableStatus != "deleted" {
		t.Fatalf("bad metadata: %+v", a)
	}
	if a.Revision == stamp(path) || a.Revision != stamp("/proc/"+strconv.Itoa(child.Process.Pid)+"/exe") {
		t.Fatal("replacement revision substituted")
	}
	expected := digest(fmt.Sprintf("%d|%s|%s|%s", p.UID, a.Kind, a.Prefix, path))
	if a.Key != expected || a.Key != before.Application.Key {
		t.Fatal("unlinked image changed stable program identity")
	}
}

func TestLinkedLiteralDeletionSuffixIsNotAnotherProgram(t *testing.T) {
	data, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "native (deleted)")
	if err = os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(path, "30")
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	p, err := Inspect(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	a := p.Application
	if a.ExecutableStatus != "linked" || a.KeyPath() != path {
		t.Fatal("literal filename confused with unlinked image", a)
	}
	other := a
	other.Executable = filepath.Join(filepath.Dir(path), "native")
	if ApplicationKey(p.UID, other) == a.Key {
		t.Fatal("different executable inherited identity")
	}
}
