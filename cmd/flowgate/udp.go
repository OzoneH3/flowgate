package main

import (
	"context"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/readiness"
	"flowgate/internal/udpaccount"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func udpCommand() error {
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	uid := fs.Uint("uid", uint(os.Getuid()), "desktop UID permitted to monitor/stop its collector")
	socket := fs.String("socket", "", "collection-only socket (default /run/flowgate-traffic/UID/api.sock)")
	helper := fs.String("helper", "", "optional built udp-collector executable")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if uint64(*uid) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid UID")
	}
	if *socket == "" {
		*socket = fmt.Sprintf("/run/flowgate-traffic/%d/api.sock", *uid)
	}
	if os.Args[1] == "udp-stop" {
		u, e := udpaccount.Request(*socket, "stop")
		if e == nil {
			output(u)
		}
		return e
	}
	explicitUID := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "uid" {
			explicitUID = true
		}
	})
	if !explicitUID {
		return fmt.Errorf("explicit --uid required for privileged collection")
	}
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "explicit authentication required to load UDP BPF collector", "Run doctor; then use explicit Enable extended monitoring only when authorized")
	}
	dir := filepath.Dir(*socket)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := daemon.SecureDirectory(dir); err != nil {
		return err
	}
	if *helper == "" {
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		*helper = filepath.Join(filepath.Dir(exe), "udp-collector")
	}
	if check := readiness.Helper(*helper); check.Status != readiness.Ready {
		return &readiness.Failure{Check: check}
	}
	if check := readiness.BTFNames("/sys/kernel/btf/vmlinux"); check.Status != readiness.Ready {
		return &readiness.Failure{Check: check}
	}
	// Explicit sudo initially trusts the reviewed built binary and helper. Pin a
	// private executable copy so a later workspace rebuild cannot replace it.
	source, e := os.Open(*helper)
	if e != nil {
		return readiness.Fail("helper_missing", "UDP helper could not be opened", "Build scripts/build.sh udp, then run doctor")
	}
	defer source.Close()
	pinned, e := os.CreateTemp(dir, "collector-")
	if e != nil {
		return e
	}
	defer os.Remove(pinned.Name())
	n, e := io.Copy(pinned, io.LimitReader(source, 32*1024*1024+1))
	if e != nil || n > 32*1024*1024 {
		pinned.Close()
		return fmt.Errorf("invalid helper size/copy")
	}
	if e = pinned.Chmod(0700); e != nil {
		pinned.Close()
		return e
	}
	if e = pinned.Close(); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return udpaccount.Run(ctx, *socket, pinned.Name(), uint32(*uid))
}
