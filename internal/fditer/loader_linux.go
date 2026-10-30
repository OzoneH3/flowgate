package fditer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Load executes one explicitly configured, root-owned, non-writable helper
// through its already-open file descriptor. It receives an unattached program
// FD; the helper exits immediately. No executable path is reopened after check.
func Load(path, expectedSHA256 string) (*Reader, error) {
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, fmt.Errorf("iterator requires the matched loader SHA256")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("iterator helper must be absolute")
	}
	image, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer image.Close()
	st, err := image.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 {
		return nil, fmt.Errorf("iterator helper must be root-owned and not group/world writable")
	}
	if st.Size() <= 0 || st.Size() > 32<<20 {
		return nil, fmt.Errorf("iterator helper size outside bound")
	}
	hash := sha256.New()
	nread, err := io.Copy(hash, io.LimitReader(image, (32<<20)+1))
	if err != nil || nread != st.Size() || !bytes.Equal(hash.Sum(nil), expected) {
		return nil, fmt.Errorf("iterator helper differs from matched bundle digest")
	}
	if _, err = image.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(pair[0]), "iterator-parent")
	defer parent.Close()
	child := os.NewFile(uintptr(pair[1]), "iterator-child")
	defer child.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/4", "--send-program-fd")
	cmd.ExtraFiles = []*os.File{child, image}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	child.Close()
	// Receiving is bounded independently of helper exit/exec failures.
	unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3})
	data := make([]byte, 16)
	control := make([]byte, unix.CmsgSpace(4*4))
	n, oob, flags, _, recvErr := unix.Recvmsg(pair[0], data, control, unix.MSG_CMSG_CLOEXEC)
	if recvErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	var fds []int
	messages, parseErr := unix.ParseSocketControlMessage(control[:max(0, oob)])
	for _, m := range messages {
		rights, e := unix.ParseUnixRights(&m)
		if e != nil {
			parseErr = e
		} else {
			fds = append(fds, rights...)
		}
	}
	if recvErr != nil || waitErr != nil || parseErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != 13 || string(data[:5]) != "FGFI2" || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("iterator loader handoff failed: receive=%v exit=%v control=%v", recvErr, waitErr, parseErr)
	}
	if err = verifyProgram(fds[0], data[5:13]); err != nil {
		unix.Close(fds[0])
		return nil, err
	}
	return New(os.NewFile(uintptr(fds[0]), "holder-iterator-program")), nil
}

func verifyProgram(fd int, tag []byte) error {
	// Stable prefix of linux bpf_prog_info through name[16]. Other optional
	// fields are not requested. Program type/name/tag are kernel-returned values.
	info := new(struct {
		Type, ID                uint32
		Tag                     [8]byte
		JitedLen, XlatedLen     uint32
		Jited, Xlated, LoadTime uint64
		UID, MapCount           uint32
		Maps                    uint64
		Name                    [16]byte
	})
	var pin runtime.Pinner
	pin.Pin(info)
	defer pin.Unpin()
	attr := struct {
		FD, Length uint32
		Info       uint64
	}{uint32(fd), uint32(unsafe.Sizeof(*info)), uint64(uintptr(unsafe.Pointer(info)))}
	_, err := bpf(unix.BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return fmt.Errorf("iterator program info: %w", err)
	}
	if info.Type != unix.BPF_PROG_TYPE_TRACING || string(bytes.TrimRight(info.Name[:], "\x00")) != "fds" || !bytes.Equal(tag, info.Tag[:]) {
		return fmt.Errorf("iterator received program does not match embedded loader object")
	}
	// The startup self-TID probe also proves TRACE_ITER/task_file attachment.
	return nil
}
