package main

import (
	"context"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/monitor"
	"flowgate/internal/readiness"
	"flowgate/internal/store"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Foreground root daemon foundation: observe and manage stored policy without
// interception. There is intentionally no automatic/implicit firewall path here.
func serveCommand(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	socket := fs.String("socket", "", "existing root-owned API directory + new private socket")
	database := fs.String("database", "", "SQLite file in an existing secure root-owned directory")
	uid := fs.Int("uid", -1, "explicit desktop peer UID")
	administrator := fs.Bool("administrator", false, "root grants that selected UID machine-wide visibility and rule authority")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "serve requires a root Go daemon; Electron remains unprivileged", "Use read-only ordinary launch; privileged manual start is a separate explicit action")
	}
	if *uid < 0 || uint64(*uid) > uint64(^uint32(0)) || !filepath.IsAbs(*socket) || !filepath.IsAbs(*database) {
		return fmt.Errorf("explicit --uid, absolute --socket and --database required")
	}
	if err := daemon.SecureDirectory(filepath.Dir(*database)); err != nil {
		return err
	}
	db, err := store.OpenExclusive(*database)
	if err != nil {
		return err
	}
	defer db.Close()
	rules, err := db.Load()
	if err != nil {
		return err
	}
	e := daemon.New(30 * time.Second)
	peer := uint32(*uid)
	e.APIUID = &peer
	if *administrator {
		e.AdministratorUID = &peer
	}
	e.Mode = "daemon-monitor"
	e.SaveRules = db.Replace
	e.Enforcement = func() daemon.EnforcementStatus {
		return daemon.EnforcementStatus{State: "stopped", Detail: "Non-enforcing root daemon: observation and stored policy only; no queue, rules or collector attachments"}
	}
	if err = e.SetRules(rules); err != nil {
		return err
	}
	observer := monitor.New(time.Second)
	e.Activity = observer.Snapshot
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	e.StopMonitoring = cancel
	api, err := daemon.Serve(*socket, e, false)
	if err != nil {
		return err
	}
	defer api.Close()
	ro, err := daemon.Serve(*socket+".monitor", e, true)
	if err != nil {
		return err
	}
	defer ro.Close()
	go observer.Run(ctx)
	fmt.Fprintln(os.Stderr, "READY: root daemon — non-enforcing; administrative grant:", *administrator)
	<-ctx.Done()
	return nil
}
