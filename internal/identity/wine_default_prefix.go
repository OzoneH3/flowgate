package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Only a process that omitted both prefix settings can use Wine's HOME/.wine
// default. This is a discovery hint; it does not identify a socket or an app.
func defaultWinePath(raw string) string {
	var home string
	for _, entry := range strings.Split(raw, "\x00") {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "WINEPREFIX", "STEAM_COMPAT_DATA_PATH":
			return ""
		case "HOME":
			home = value
		}
	}
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".wine")
}

// Classic Wine servers lock byte zero of this per-UID, per-prefix lock.
// Verify the lock holder, its cwd, generation, UID and namespaces. A client
// must also have a live bidirectional Unix socket to that same server.
func verifiedDefaultWinePrefix(client Process, raw string) string {
	candidate := defaultWinePath(raw)
	if candidate == "" || client.MountNS == "" || client.NetNS == "" {
		return ""
	}
	prefix, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return ""
	}
	info, err := os.Stat(prefix)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != client.UID {
		return ""
	}
	root := fmt.Sprintf("/proc/%d/root", client.PID)
	inGuest, err := os.Stat(root + candidate)
	if err != nil || !os.SameFile(info, inGuest) {
		return ""
	}
	dev, ino := devIno(info)
	dir := fmt.Sprintf("%s/tmp/.wine-%d/server-%x-%x", root, client.UID, dev, ino)
	lockPath := dir + "/lock"
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Sys().(*syscall.Stat_t).Uid != client.UID {
		return ""
	}
	lock, err := os.OpenFile(lockPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer lock.Close()
	opened, err := lock.Stat()
	if err != nil || !os.SameFile(lockInfo, opened) {
		return ""
	}
	owner := func() int {
		q := syscall.Flock_t{Type: syscall.F_RDLCK, Whence: 0, Len: 1}
		if syscall.FcntlFlock(lock.Fd(), syscall.F_GETLK, &q) != nil || q.Type != syscall.F_WRLCK {
			return 0
		}
		return int(q.Pid)
	}
	pid := owner()
	if pid <= 0 {
		return ""
	}
	base := fmt.Sprintf("/proc/%d", pid)
	start, _, err := processStat(base)
	if err != nil || filepath.Base(link(base+"/exe")) != "wineserver" {
		return ""
	}
	st, err := os.Stat(base)
	if err != nil || st.Sys().(*syscall.Stat_t).Uid != client.UID ||
		link(base+"/ns/mnt") != client.MountNS || link(base+"/ns/net") != client.NetNS {
		return ""
	}
	cwd, err := os.Stat(base + "/cwd")
	serverDir, dirErr := os.Stat(dir)
	if err != nil || dirErr != nil || !os.SameFile(cwd, serverDir) {
		return ""
	}
	if client.PID != pid && !wineSocketPeer(client.PID, pid) {
		return ""
	}
	current, err := os.Stat(candidate)
	if err != nil || !os.SameFile(info, current) || owner() != pid || !InstanceRunning(pid, start) {
		return ""
	}
	return prefix
}
