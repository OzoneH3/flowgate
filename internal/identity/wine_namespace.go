package identity

// Namespace entry is confined to an already verified broker's pinned mount
// namespace/root. Network and user namespaces are never entered. nsenter drops
// supplementary groups and changes GID/UID before it executes the Wine loader.
import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type wineNamespace struct {
	mount, root             *os.File
	runner, helper, scratch string
	removeScratch           bool
	scratchDir              *os.File
	cleanupPath             string
	uid, gid                uint32
}

func (n *wineNamespace) close() {
	if n != nil {
		if n.mount != nil {
			n.mount.Close()
		}
		if n.root != nil {
			n.root.Close()
		}
	}
}
func (n *wineNamespace) command() *exec.Cmd {
	c := exec.Command("/usr/bin/nsenter", "--mount=/proc/self/fd/3", "--root=/proc/self/fd/4", "--wdns=/", "--setgid="+strconv.FormatUint(uint64(n.gid), 10), "--setuid="+strconv.FormatUint(uint64(n.uid), 10), "--", n.runner, n.helper)
	c.ExtraFiles = []*os.File{n.mount, n.root}
	return c
}

// Reuse the executable-evidence mount mapping in reverse to locate the host
// file inside the broker namespace. Mount metadata proposes candidates only:
// device/inode must equal the selected file. This never selects a game target.
func namespaceFile(pid int, host string) (string, error) {
	expected, err := os.Stat(host)
	if err != nil {
		return "", err
	}
	candidates := append([]string{host}, mountCandidates(host, string(readBound("/proc/self/mountinfo", 1<<20)), string(readBound(fmt.Sprintf("/proc/%d/mountinfo", pid), 1<<20)))...)
	for _, candidate := range candidates {
		actual, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, candidate))
		if err == nil && os.SameFile(expected, actual) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("selected file has no verified path in broker mount namespace: %s", host)
}
func prepareWineNamespace(b Process, runner, helper, scratch, runtimeDir string) (n *wineNamespace, err error) {
	if os.Geteuid() != 0 && uint32(os.Geteuid()) != b.UID {
		return nil, fmt.Errorf("broker mount namespace requires privileged entry before dropping to its user")
	}
	n = &wineNamespace{uid: b.UID}
	ok := false
	allocated := n
	defer func() {
		if !ok {
			allocated.close()
			if allocated.removeScratch {
				allocated.removePrivateScratch()
				allocated.scratchDir.Close()
			}
		}
	}()
	base := fmt.Sprintf("/proc/%d", b.PID)
	n.mount, err = os.Open(base + "/ns/mnt")
	if err != nil {
		return nil, err
	}
	if link(fmt.Sprintf("/proc/self/fd/%d", n.mount.Fd())) != b.MountNS {
		return nil, fmt.Errorf("broker mount namespace changed")
	}
	n.root, err = os.Open(base + "/root")
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(base)
	if err != nil {
		return nil, err
	}
	n.gid = st.Sys().(*syscall.Stat_t).Gid
	n.runner, err = namespaceFile(b.PID, runner)
	if err != nil {
		return nil, err
	}
	n.helper, err = namespaceFile(b.PID, helper)
	if err != nil {
		return nil, err
	}
	n.scratch, err = namespaceFile(b.PID, scratch)
	if err != nil {
		// Proton may provide a private XDG runtime directory. Open it within
		// the pinned root, verify its ownership/mode, and retain its directory
		// descriptor for cleanup even after the broker exits or paths change.
		if runtimeDir == "" || !filepath.IsAbs(runtimeDir) {
			return nil, fmt.Errorf("no private observer scratch or XDG runtime directory")
		}
		root, e := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", n.root.Fd()))
		if e != nil {
			return nil, e
		}
		dir, e := root.Open(strings.TrimPrefix(filepath.Clean(runtimeDir), "/"))
		root.Close()
		if e != nil {
			return nil, e
		}
		rs, e := dir.Stat()
		if e != nil || !rs.IsDir() || rs.Sys().(*syscall.Stat_t).Uid != b.UID || rs.Mode().Perm()&0077 != 0 {
			dir.Close()
			return nil, fmt.Errorf("unverified container user runtime directory")
		}
		n.scratchDir = dir
		name := fmt.Sprintf("flowgate-wine-%x", randomScratchID())
		if e = n.scratchCommand("/usr/bin/mkdir", "-m", "0700", "--", "/proc/self/fd/3/"+name); e != nil {
			dir.Close()
			return nil, e
		}
		n.cleanupPath, n.removeScratch = name, true
		n.scratch = filepath.Join(runtimeDir, name)

	}
	if s, e := Inspect(b.PID); e != nil || s.Start != b.Start || s.MountNS != b.MountNS || s.ExecutableRevision != b.ExecutableRevision {
		return nil, fmt.Errorf("broker changed before namespace entry")
	}
	ok = true
	return n, nil
}

// A tmpfs created in a child user namespace cannot create an inode for an
// unmapped host-root UID (EOVERFLOW). Create and remove scratch as the broker's
// mapped desktop UID, without changing the daemon's credentials or entering a
// user namespace. The only inherited descriptor pins the verified directory.
func randomScratchID() [16]byte {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}
func (n *wineNamespace) scratchCommand(binary string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binary, args...)
	c.ExtraFiles = []*os.File{n.scratchDir}
	c.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if os.Geteuid() != int(n.uid) {
		c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: n.uid, Gid: n.gid, Groups: []uint32{}}}
	}
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("private observer scratch: %w: %.512s", err, out)
	}
	return nil
}
func (n *wineNamespace) removePrivateScratch() {
	if n.cleanupPath != "" {
		_ = n.scratchCommand("/usr/bin/rm", "-rf", "--", "/proc/self/fd/3/"+n.cleanupPath)
	}
}

// A namespace may expose the observer through /run/host, where Inspect cannot
// canonicalize argv[0] using the daemon's filesystem. Verify its mapped file
// directly through the live process root and the configured host-file inode.
func (w *WineTable) mappedObserver(p Process) bool {
	if !strings.HasPrefix(p.Application.Kind, "wine") {
		return false
	}
	expected, err := os.Stat(w.helper)
	if err != nil {
		return false
	}
	base := fmt.Sprintf("/proc/%d", p.PID)
	for _, line := range strings.Split(string(readBound(base+"/maps", 2<<20)), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		path := strings.Join(f[5:], " ")
		if !filepath.IsAbs(path) || strings.HasSuffix(path, " (deleted)") {
			continue
		}
		st, e := os.Stat(base + "/root" + path)
		if e == nil && os.SameFile(expected, st) && f[4] == strconv.FormatUint(st.Sys().(*syscall.Stat_t).Ino, 10) {
			return true
		}
	}
	return false
}
