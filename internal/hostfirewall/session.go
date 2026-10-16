package hostfirewall

import (
	"flowgate/internal/daemon"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// PrepareSession creates only specifically named private runtime/data directories.
// Existing directories must already have safe ownership/modes; never chmod or
// chown a symlink or another user's object to make it pass validation.
func PrepareSession(state, api, database string) (string, error) {
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{state, 0700}, {api, 0711}, {filepath.Dir(database), 0700}} {
		if err := daemon.SecureDirectory(filepath.Dir(d.path)); err != nil {
			return "", err
		}
		if err := os.Mkdir(d.path, d.mode); err != nil && !os.IsExist(err) {
			return "", err
		}
		st, err := os.Lstat(d.path)
		if err != nil || !st.IsDir() || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Mode().Perm() != d.mode {
			return "", fmt.Errorf("unsafe existing session directory %s (expected daemon-owned mode %04o)", d.path, d.mode)
		}
	}
	l, err := lock(state)
	if err != nil {
		return "", err
	}
	defer l.Close()
	if old, err := Read(state); err == nil && old.State != "stopped" {
		return "", fmt.Errorf("previous controller requires Stop/recovery before starting again")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	// /proc/self/exe pins the executing inode rather than reopening an editable
	// build pathname after authentication. The snapshot and watchdog stay owned by root.
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer source.Close()
	f, err := os.CreateTemp(state, "controller-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(source, 100<<20))
	if err != nil {
		return "", err
	}
	if n == 100<<20 {
		return "", fmt.Errorf("controller executable exceeds bound")
	}
	if err = f.Chmod(0700); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	target := filepath.Join(state, "controller")
	if err = os.Rename(f.Name(), target); err != nil {
		return "", err
	}
	return target, nil
}
