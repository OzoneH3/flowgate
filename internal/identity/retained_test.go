package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyRetainedExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(path, []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := Application{Kind: "native", Executable: path, Revision: stamp(path)}
	app.Key = digest(fmt.Sprintf("%d|%s|%s|%s", 1000, app.Kind, app.Prefix, app.Executable))
	ns := link("/proc/self/ns/mnt")
	if err := VerifyRetainedExecutable(app, 1000, ns); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"other uid":     func() error { return VerifyRetainedExecutable(app, 1001, ns) },
		"mount ns":      func() error { return VerifyRetainedExecutable(app, 1000, "mnt:[1]") },
		"not available": func() error { return VerifyRetainedExecutable(Application{Kind: "wine-unresolved"}, 1000, ns) },
	} {
		if check() == nil {
			t.Error(name, "accepted")
		}
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte("one+"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRetainedExecutable(app, 1000, ns); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatal("in-place change accepted", err)
	}
	// Same path, different file: must not be substituted for the original.
	os.Remove(path)
	if err := os.WriteFile(path+".new", []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	keep := path + ".hold"
	os.WriteFile(keep, nil, 0o600) // keep the old inode number from being reused immediately
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRetainedExecutable(app, 1000, ns); err == nil || !(strings.Contains(err.Error(), "different file") || strings.Contains(err.Error(), "modified")) {
		t.Fatal("replacement accepted", err)
	}
	os.Remove(path)
	if err := VerifyRetainedExecutable(app, 1000, ns); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatal(err)
	}
	if InstanceRunning(os.Getpid(), "") || !InstanceRunning(os.Getpid(), func() string { s, _, _ := processStat("/proc/self"); return s }()) {
		t.Fatal("instance liveness")
	}
}
