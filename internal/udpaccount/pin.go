package udpaccount

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flowgate/internal/readiness"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxHelperSize = 32 * 1024 * 1024

func descriptorPath(file *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", file.Fd())
}

func openPin(directories []string) (*os.File, error) {
	var failures []error
	for _, directory := range directories {
		// O_EXCL prevents linking this anonymous file into the filesystem.
		fd, err := unix.Open(directory, unix.O_TMPFILE|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0700)
		if err == nil {
			var fs unix.Statfs_t
			err = unix.Fstatfs(fd, &fs)
			if err == nil && fs.Flags&unix.ST_NOEXEC == 0 {
				return os.NewFile(uintptr(fd), directory), nil
			}
			unix.Close(fd)
			if err == nil {
				err = errors.New("mount is noexec")
			}
		}
		failures = append(failures, fmt.Errorf("%s: %w", directory, err))
	}
	return nil, fmt.Errorf("no anonymous executable UDP pin location: %w", errors.Join(failures...))
}

func pinHelper(source *os.File, expected string, directories []string) (*os.File, error) {
	if expected != "" {
		st, err := source.Stat()
		if err != nil {
			return nil, err
		}
		if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 {
			return nil, errors.New("packaged UDP helper must be daemon-owned and non-writable by other users")
		}
	}
	writer, err := openPin(directories)
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	if err = writer.Chmod(0700); err != nil {
		return nil, err
	}
	n, err := io.Copy(writer, io.LimitReader(source, maxHelperSize+1))
	if err != nil {
		return nil, err
	}
	if n > maxHelperSize {
		return nil, errors.New("UDP helper exceeds the pin size limit")
	}

	// Linux refuses execution while a writable descriptor for the inode is open.
	// Keep a separate read-only descriptor to the same anonymous inode.
	pinned, err := os.Open(descriptorPath(writer))
	if err != nil {
		return nil, err
	}
	err = writer.Close()
	if err == nil {
		err = verifyPin(pinned, expected)
	}
	if err != nil {
		pinned.Close()
		return nil, err
	}
	return pinned, nil
}

func verifyPin(pinned *os.File, expected string) error {
	if check := readiness.MachineHelper(descriptorPath(pinned)); check.Status != readiness.Ready {
		return fmt.Errorf("pinned helper incompatible: %s", check.Detail)
	}
	if expected == "" {
		return nil
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(pinned, 0, maxHelperSize)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("pinned UDP helper SHA-256 differs from the packaged helper")
	}
	return nil
}
