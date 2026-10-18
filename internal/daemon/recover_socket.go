package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// RecoverSocket is only called after exclusive database acquisition. A root-owned
// nonwritable parent and inode recheck prevent a user from substituting a file.
func RecoverSocket(path string, uid uint32) error {
	if err := SecureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uid {
		return fmt.Errorf("refusing unexpected existing API object %s", path)
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		c.Close()
		return fmt.Errorf("API consumer still running at %s", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot prove stale API socket: %w", err)
	}
	next, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(st, next) {
		return fmt.Errorf("API socket changed during recovery")
	}
	return os.Remove(path)
}
