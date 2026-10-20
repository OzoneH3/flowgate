package identity

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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
	// Start may return while /proc still exposes the pre-exec child image.
	// Establish the fixture exec boundary before deleting its executable.
	until := time.Now().Add(time.Second)
	for {
		actual, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", child.Process.Pid))
		if actual == path {
			break
		}
		if time.Now().After(until) {
			t.Fatal("fixture did not exec selected image")
		}
		time.Sleep(time.Millisecond)
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
	expected := digest(fmt.Sprintf("%d|%s|%s|%s", p.UID, a.Kind, a.Prefix, a.Executable))
	if a.Key != expected {
		t.Fatal("display changed exact legacy identity")
	}
}
