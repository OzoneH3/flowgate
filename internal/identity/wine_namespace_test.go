package identity

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// Run in an isolated subordinate-ID user namespace; no host privilege required.
// The child tmpfs maps UID1000 but not its parent's UID0, like pressure-vessel.
func TestNamespaceScratchUnmappedRoot(t *testing.T) {
	if os.Getenv("FLOWGATE_USERNS_SCRATCH") != "1" {
		t.Skip("requires subordinate-ID namespace fixture")
	}
	base := t.TempDir()
	if err := os.Chmod(filepath.Dir(base), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "runtime")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(target, 1000, 0); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/setpriv", "--reuid=1000", "--regid=0", "--clear-groups", "/usr/bin/unshare", "--user", "--map-root-user", "--keep-caps", "--mount", "sh", "-c", `set -e; mount -t tmpfs -o mode=0700 tmpfs "$1"; echo ready; exec sleep 60`, "sh", "runtime")
	cmd.Dir = base
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	reader := bufio.NewReader(output)
	if line, e := reader.ReadString('\n'); e != nil || line != "ready\n" {
		t.Fatal(line, e)
	}
	dir, e := os.Open(fmt.Sprintf("/proc/%d/root%s", cmd.Process.Pid, target))
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	// This is the exact previous production operation and must fail here.
	old, e := os.MkdirTemp(fmt.Sprintf("/proc/self/fd/%d", dir.Fd()), "old-")
	if e == nil {
		os.Remove(old)
		t.Fatal("fixture did not reproduce unmapped-root failure")
	}
	if !errors.Is(e, syscall.EOVERFLOW) {
		t.Fatal("wrong failure", e)
	}
	n := &wineNamespace{scratchDir: dir, uid: 1000, gid: 0, cleanupPath: "flowgate-wine-test"}
	if e = n.scratchCommand("/usr/bin/mkdir", "-m", "0700", "--", "/proc/self/fd/3/"+n.cleanupPath); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), n.cleanupPath))
	if e != nil {
		t.Fatal(e)
	}
	if st.Sys().(*syscall.Stat_t).Uid != 1000 || st.Mode().Perm() != 0700 {
		t.Fatal("wrong scratch owner/mode", st)
	}
	n.removePrivateScratch()
	if _, e = os.Stat(fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), n.cleanupPath)); !os.IsNotExist(e) {
		t.Fatal("cleanup failed", e)
	}
}
