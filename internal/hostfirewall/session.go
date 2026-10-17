package hostfirewall

import (
	"flowgate/internal/daemon"
	"flowgate/internal/readiness"
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
			return "", readiness.Fail("runtime_path_invalid", err.Error(), "Inspect host-control runtime paths with doctor; no automatic permission repair")
		}
		if err := os.Mkdir(d.path, d.mode); err == nil {
			// Set the exact mode only on a directory this invocation created;
			// a restrictive inherited umask must not prevent GUI traversal.
			if err = os.Chmod(d.path, d.mode); err != nil {
				return "", err
			}
		} else if !os.IsExist(err) {
			return "", err
		}
		st, err := os.Lstat(d.path)
		if err != nil || !st.IsDir() || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Mode().Perm() != d.mode {
			return "", readiness.Fail("runtime_path_invalid", fmt.Sprintf("unsafe existing session directory %s (expected daemon-owned mode %04o)", d.path, d.mode), "Inspect paths with doctor; do not overwrite another instance")
		}
	}
	l, err := lock(state)
	if err != nil {
		return "", err
	}
	defer l.Close()
	if old, err := Read(state); err == nil && old.State != "stopped" {
		return "", readiness.Fail("instance_active", "previous controller requires Stop/recovery before starting again", "Inspect host-status and use scoped recovery only for confirmed owned resources")
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
