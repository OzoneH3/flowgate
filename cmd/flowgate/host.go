package main

import (
	"context"
	"flag"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/readiness"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func hostCommand() error {
	op := os.Args[1]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	state := fs.String("state", "", "existing private daemon-owned state directory")
	database := fs.String("database", "", "durable SQLite path; default STATE/rules.db")
	socket := fs.String("socket", "", "GUI user's private API socket path")
	administrator := fs.Bool("administrator", false, "explicitly grant selected GUI UID machine-wide observation and application rule authority")
	uid := fs.Int("uid", -1, "explicit GUI user UID; grants control only over that user's applications")
	duration := fs.Duration("duration", 5*time.Minute, "automatic deliberate stop (10s–30m)")
	timeout := fs.Duration("timeout", 30*time.Second, "pending decision timeout (1s–60s)")
	profile := fs.String("profile", "incoming", "incoming or both; fixed for this evaluation")
	action := fs.String("action", "", "session start/status/stop/recover")
	token := fs.String("token", "", "internal watchdog generation")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if op == "host-session" {
		if os.Geteuid() != 0 {
			return readiness.Fail("permission_required", "session commands require terminal sudo; never elevate the frontend", "Run doctor; use the explicit evaluation workflow only after authorization")
		}
		if *state == "" {
			*state = "/run/flowgate"
		}
		if *socket == "" {
			*socket = "/run/flowgate-api/control.sock"
		}
		if *database == "" {
			*database = "/var/lib/flowgate/rules.db"
		}
		switch *action {
		case "start":
			if *profile != "incoming" && *profile != "both" {
				return fmt.Errorf("profile must be incoming or both")
			}
			if *uid < 0 || uint64(*uid) > uint64(^uint32(0)) {
				return fmt.Errorf("explicit GUI UID required")
			}
			target, err := hostfirewall.PrepareSession(*state, filepath.Dir(*socket), *database)
			if err != nil {
				return err
			}
			args := []string{target, "host-start", "--state", *state, "--socket", *socket, "--database", *database, "--uid", strconv.Itoa(*uid), "--duration", duration.String(), "--timeout", timeout.String(), "--profile", *profile}
			if *administrator {
				args = append(args, "--administrator")
			}
			return syscall.Exec(target, args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"})
		case "status":
			v, err := hostfirewall.Status(*state)
			if err == nil {
				output(v)
			}
			return err
		case "stop":
			return hostfirewall.StopGeneration(*state, *token)
		case "recover":
			return hostfirewall.Recover(*state, *token)
		default:
			return fmt.Errorf("session action must be start, status, stop or recover")
		}
	}
	if *state == "" {
		return fmt.Errorf("--state is required")
	}
	switch op {
	case "host-start":
		if *uid < 0 || uint64(*uid) > uint64(^uint32(0)) || *socket == "" {
			return fmt.Errorf("--uid and --socket required")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return hostfirewall.RunProfileAuthorized(ctx, *state, *socket, *database, uint32(*uid), *duration, *timeout, *profile, *administrator)
	case "host-stop":
		return hostfirewall.StopGeneration(*state, *token)
	case "host-recover":
		return hostfirewall.Recover(*state, "")
	case "host-watch":
		return hostfirewall.Watch(*state, *token)
	case "host-status":
		v, e := hostfirewall.Status(*state)
		if e == nil {
			output(v)
		}
		return e
	}
	return fmt.Errorf("unknown host command")
}
