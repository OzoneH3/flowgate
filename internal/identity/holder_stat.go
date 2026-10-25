package identity

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// readHolderTaskStat makes a new procfs observation on every call. It avoids
// os.ReadFile's size probe/pollable-file setup and parsing fields beyond start
// ticks. No FD, bytes or generation evidence survives this call. Existing
// census topology/descriptor/identity bookends and deadlines are unchanged.
// Linux task stat is much smaller than one page; an oversized future/malformed
// record refuses explicitly instead of authorizing from a truncated record.
func readHolderTaskStat(path string) (string, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	for err == unix.EINTR {
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return "", false, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	var buf [4097]byte
	n := 0
	for n < len(buf) {
		k, e := unix.Read(fd, buf[n:])
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return "", false, &os.PathError{Op: "read", Path: path, Err: e}
		}
		n += k
		if k == 0 {
			return parseHolderTaskStat(buf[:n])
		}
	}
	return "", false, fmt.Errorf("task stat exceeds 4096-byte limit")
}
func parseHolderTaskStat(b []byte) (string, bool, error) {
	i := bytes.LastIndex(b, []byte(") "))
	if i < 0 {
		return "", false, fmt.Errorf("task stat unavailable")
	}
	zombie := false
	field := 0
	for f := range bytes.FieldsSeq(b[i+2:]) {
		if field == 0 {
			zombie = bytes.Equal(f, []byte("Z"))
		}
		if field == 19 {
			return string(f), zombie, nil
		}
		field++
	}
	return "", false, fmt.Errorf("short task stat")
}
