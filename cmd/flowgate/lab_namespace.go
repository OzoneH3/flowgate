package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Initial-user-namespace capabilities are needed for the isolated iterator
// test. This opt-in is confined to serve-lab and requires real inherited
// namespace FDs, not caller-supplied namespace names, proving separate PID and
// mount namespaces. The existing separate network namespace check also applies.
func isolatedRootLab(pidFD, mountFD int) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root lab requires root")
	}
	for _, v := range []struct {
		fd, kind int
		name     string
	}{{pidFD, unix.CLONE_NEWPID, "pid"}, {mountFD, unix.CLONE_NEWNS, "mnt"}} {
		if v.fd < 3 {
			return fmt.Errorf("root lab requires inherited parent namespace descriptors")
		}
		kind, err := unix.IoctlRetInt(v.fd, unix.NS_GET_NSTYPE)
		if err != nil || kind != v.kind {
			return fmt.Errorf("invalid parent %s namespace descriptor", v.name)
		}
		var parent, current unix.Stat_t
		if unix.Fstat(v.fd, &parent) != nil || unix.Stat("/proc/self/ns/"+v.name, &current) != nil || parent.Ino == current.Ino && parent.Dev == current.Dev {
			return fmt.Errorf("root lab requires separate %s namespace", v.name)
		}
	}
	self, err := os.Readlink("/proc/self/ns/pid")
	init, e := os.Readlink("/proc/1/ns/pid")
	if err != nil || e != nil || self != init {
		return fmt.Errorf("root lab requires its own /proc mount")
	}
	return nil
}
