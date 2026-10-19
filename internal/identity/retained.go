package identity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// VerifyRetainedExecutable re-validates an application identity that was
// captured from a verified owner at request time, after that process may have
// exited. It needs no PID, socket or live instance: the captured path is
// inspected directly and must still be the same file (device, inode, size,
// mtime, ctime) recorded as the application revision. A different file now at
// the same path, a modified file or a missing file is refused with its reason.
func VerifyRetainedExecutable(a Application, uid uint32, mountNS string) error {
	if (a.Kind != "native" && a.Kind != "wine") || a.Key == "" || a.Revision == "" || a.Executable == "" {
		return fmt.Errorf("captured identity is not a verifiable executable (kind %q)", a.Kind)
	}
	if mountNS == "" || mountNS != SelfMountNS() {
		return UnverifiableEvidence(mountNS, nil, "no reusable executable identity was retained while it ran")
	}
	if a.Key != ApplicationKey(uid, a) {
		return fmt.Errorf("captured application key does not match its executable, prefix and user")
	}
	st, err := os.Stat(a.Executable)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("executable %s no longer exists (deleted, moved or replaced)", a.Executable)
	}
	if err != nil {
		return fmt.Errorf("executable %s cannot be inspected: %v", a.Executable, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is no longer a regular file", a.Executable)
	}
	want := strings.SplitN(a.Revision, ":", 3)
	s := st.Sys().(*syscall.Stat_t)
	if len(want) < 2 || want[0] != strconv.FormatUint(s.Dev, 10) || want[1] != strconv.FormatUint(s.Ino, 10) {
		return fmt.Errorf("a different file now occupies %s (device/inode changed); the requesting executable is gone", a.Executable)
	}
	if stamp(a.Executable) != a.Revision {
		return fmt.Errorf("%s was modified since the request (size, modification or change time differs)", a.Executable)
	}
	return nil
}

// InstanceRunning reports whether the exact process instance (PID plus start
// time) still exists. Presentation only; it grants no authority.
func InstanceRunning(pid int, start string) bool {
	if pid <= 0 || start == "" {
		return false
	}
	current, _, err := processStat(fmt.Sprintf("/proc/%d", pid))
	return err == nil && current == start
}
