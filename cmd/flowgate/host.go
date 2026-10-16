package main

import (
	"context"
	"flag"
	"flowgate/internal/hostfirewall"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func hostCommand() error {
	op := os.Args[1]
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	state := fs.String("state", "", "existing private daemon-owned state directory")
	database := fs.String("database", "", "durable SQLite path; default STATE/rules.db")
	socket := fs.String("socket", "", "GUI user's private API socket path")
	uid := fs.Int("uid", -1, "explicit GUI user UID; grants control only over that user's applications")
	duration := fs.Duration("duration", 5*time.Minute, "automatic deliberate stop (10s–30m)")
	timeout := fs.Duration("timeout", 30*time.Second, "pending decision timeout (1s–60s)")
	token := fs.String("token", "", "internal watchdog generation")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
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
		return hostfirewall.Run(ctx, *state, *socket, *database, uint32(*uid), *duration, *timeout)
	case "host-stop":
		return hostfirewall.Stop(*state)
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
