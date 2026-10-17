package main

import (
	"flag"
	"flowgate/internal/daemon"
	"fmt"
	"os"
	"path/filepath"
)

const monitorSocket = "/run/flowgate-api/daemon.sock"

// Fixed paths only: no recursive repair, chown, replacement or deletion.
func prepareMonitorDirectory(path string, mode os.FileMode) (bool, error) {
	if err := daemon.SecureDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	created := false
	if err := os.Mkdir(path, mode); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return false, err
	}
	if created {
		// Set required traversal bits even under a restrictive root umask.
		// Existing directories are never chmodded. Parent was validated above.
		if err := os.Chmod(path, mode); err != nil {
			return created, err
		}
	}
	if err := daemon.SecureDirectory(path); err != nil {
		return created, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return created, err
	}
	if st.Mode().Perm() != mode {
		return created, fmt.Errorf("%s must have mode %04o; existing permissions preserved (no automatic repair)", path, mode)
	}
	return created, nil
}
func monitorSetupCommand(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("monitor-setup accepts no path arguments")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("monitor-setup requires root")
	}
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{"/run/flowgate-api", 0711}, {"/var/lib/flowgate", 0700}} {
		created, err := prepareMonitorDirectory(d.path, d.mode)
		if err != nil {
			return err
		}
		state := "validated; preserved existing contents"
		if created {
			state = "created"
		}
		fmt.Printf("%s: %s (root, %04o)\n", d.path, state, d.mode)
	}
	return nil
}
func monitorStopCommand(args []string) error {
	fs := flag.NewFlagSet("monitor-stop", flag.ContinueOnError)
	generation := fs.String("generation", "", "required exact generation from the intended daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("monitor-stop requires root; delegated rule administration does not grant daemon shutdown")
	}
	if *generation == "" || fs.NArg() != 0 {
		return fmt.Errorf("--generation required; no unconditional stop")
	}
	if err := daemon.SecureDirectory(filepath.Dir(monitorSocket)); err != nil {
		return err
	}
	r, err := daemon.Call(monitorSocket, daemon.Request{Version: 1, Operation: "monitor-stop", Generation: *generation})
	if err != nil {
		return err
	}
	if r.Generation != *generation || !r.Stopping {
		return fmt.Errorf("stop not acknowledged; inspect authoritative status, do not retry blindly")
	}
	fmt.Println("Monitor shutdown acknowledged for generation", r.Generation, "; no firewall resources were installed by this mode")
	return nil
}
