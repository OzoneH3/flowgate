package main

// This rollout-only read operation saves the exact executable behind the fixed
// non-enforcing monitor. No caller-supplied PID/source/destination or root write.
import (
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func monitorBackupCommand(args []string) error {
	fs := flag.NewFlagSet("monitor-backup", flag.ContinueOnError)
	generation := fs.String("generation", "", "exact non-enforcing monitor generation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("monitor-backup requires root read permission")
	}
	if *generation == "" || fs.NArg() != 0 {
		return fmt.Errorf("--generation required; no PID or path arguments")
	}
	if err := daemon.SecureDirectory(filepath.Dir(monitorSocket)); err != nil {
		return err
	}
	c, err := net.DialTimeout("unix", monitorSocket, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credentialError error
	if err = raw.Control(func(fd uintptr) {
		cred, credentialError = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credentialError != nil || cred == nil || cred.Uid != 0 || cred.Pid <= 1 {
		return fmt.Errorf("fixed monitor peer is not a root daemon")
	}
	if err = json.NewEncoder(c).Encode(daemon.Request{Version: 1, Operation: "list"}); err != nil {
		return err
	}
	var r daemon.Response
	if err = json.NewDecoder(io.LimitReader(c, 8<<20)).Decode(&r); err != nil {
		return err
	}
	if r.Error != "" || r.Generation != *generation || r.Mode != "daemon-monitor" || r.Enforcement == nil || r.Enforcement.State != "stopped" {
		return fmt.Errorf("monitor identity/generation/state mismatch; no executable exported")
	}
	f, err := os.Open("/proc/" + strconv.Itoa(int(cred.Pid)) + "/exe")
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 64<<20 {
		return fmt.Errorf("unexpected monitor executable type/size")
	}
	// The open descriptor pins that executable inode even if the process exits.
	n, err := io.Copy(os.Stdout, io.LimitReader(f, st.Size()+1))
	if err != nil {
		return err
	}
	if n != st.Size() {
		return fmt.Errorf("monitor executable changed while copying")
	}
	return nil
}
