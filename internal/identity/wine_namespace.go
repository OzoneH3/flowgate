package identity

// Namespace entry is confined to an already verified broker's pinned mount
// namespace/root. Network and user namespaces are never entered. nsenter drops
// supplementary groups and changes GID/UID before it executes the Wine loader.
import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type wineNamespace struct {
	mount, root             *os.File
	runner, helper, scratch string
	removeScratch           bool
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
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("broker mount namespace requires privileged entry before dropping to its user")
	}
	n = &wineNamespace{uid: b.UID}
	ok := false
	allocated := n
	defer func() {
		if !ok {
			allocated.close()
			if allocated.removeScratch {
				os.RemoveAll(allocated.scratch)
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
		// Container-private /run may hide the daemon's scratch directory. Use a
		// private child of the user's shared, verified XDG runtime directory only.
		if runtimeDir == "" || !filepath.IsAbs(runtimeDir) {
			return nil, fmt.Errorf("no shared private observer scratch or XDG runtime directory")
		}
		rs, e := os.Stat(runtimeDir)
		if e != nil || !rs.IsDir() || rs.Sys().(*syscall.Stat_t).Uid != b.UID || rs.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("unverified user runtime directory")
		}
		if shared, e := namespaceFile(b.PID, runtimeDir); e != nil || shared != runtimeDir {
			return nil, fmt.Errorf("user runtime directory is not shared at the verified absolute path")
		}
		n.scratch, e = os.MkdirTemp(runtimeDir, "flowgate-wine-")
		if e != nil {
			return nil, e
		}
		n.removeScratch = true
		if e = os.Chown(n.scratch, int(n.uid), int(n.gid)); e != nil {
			return nil, e
		}
	}
	if s, e := Inspect(b.PID); e != nil || s.Start != b.Start || s.MountNS != b.MountNS || s.ExecutableRevision != b.ExecutableRevision {
		return nil, fmt.Errorf("broker changed before namespace entry")
	}
	ok = true
	return n, nil
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
