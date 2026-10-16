package main

import (
	"context"
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/diagnostics"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/queue"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var productName = "FlowGate"

func output(v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		fatal(e)
	}
	fmt.Println(string(b))
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func main() {
	// Explicit opt-in to the documented Wine 11.19 non-sharing handle model.
	identity.WineBrokerExecutable = os.Getenv("FLOWGATE_WINE_BROKER")

	if len(os.Args) < 2 {
		fmt.Printf("%s: doctor | sockets | process PID | attribute | pending | decide | serve-lab\n", productName)
		return
	}
	switch os.Args[1] {
	case "doctor":
		output(diagnostics.Report())
	case "sockets":
		s, e := identity.Sockets()
		if e != nil {
			fatal(e)
		}
		output(s)
	case "process":
		if len(os.Args) != 3 {
			fatal(fmt.Errorf("process PID"))
		}
		pid, e := strconv.Atoi(os.Args[2])
		if e != nil {
			fatal(e)
		}
		p, e := identity.Inspect(pid)
		if e != nil {
			fatal(e)
		}
		output(p)
	case "attribute":
		fs := flag.NewFlagSet("attribute", flag.ExitOnError)
		p := fs.String("protocol", "tcp", "tcp/udp")
		d := fs.String("direction", "incoming", "incoming/outgoing")
		l := fs.String("local", "", "local IP:port")
		r := fs.String("remote", "", "remote IP:port")
		fs.Parse(os.Args[2:])
		f, e := identity.ParseFlow(*p, *d, *l, *r)
		if e != nil {
			fatal(e)
		}
		output(identity.Resolve(f))
	case "pending", "decide":
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		s := fs.String("socket", ".workspace/run/control.sock", "v1 API socket")
		id := fs.String("id", "", "request ID")
		a := fs.String("action", "", "allow/block")
		scope := fs.String("scope", "once", "once/application (one hour; incoming remote address + local port; outgoing destination)")
		fs.Parse(os.Args[2:])
		op := "list"
		if os.Args[1] == "decide" {
			op = "decide"
		}
		r, e := daemon.Call(*s, daemon.Request{Version: 1, Operation: op, ID: *id, Action: *a, Scope: *scope})
		output(r)
		if e != nil {
			fatal(e)
		}
	case "serve-lab":
		if e := serve(); e != nil {
			fatal(e)
		}
	default:
		fatal(fmt.Errorf("unknown command"))
	}
}
func serve() error {
	fs := flag.NewFlagSet("serve-lab", flag.ExitOnError)
	socket := fs.String("socket", ".workspace/run/control.sock", "private socket path")
	parent := fs.String("parent-netns", "", "original namespace identity (required)")
	direction := fs.String("direction", "incoming", "incoming/outgoing")
	timeout := fs.Duration("timeout", 15*time.Second, "pending timeout")
	rulepath := fs.String("rules", "", "JSON rule array")
	fs.Parse(os.Args[2:])
	if *parent == "" || *parent == identity.NetNS() {
		return fmt.Errorf("refusing enforcement without a different parent network namespace; use scripts/lab.sh")
	}
	uidmap, _ := os.ReadFile("/proc/self/uid_map")
	if !strings.HasSuffix(strings.TrimSpace(string(uidmap)), "1") {
		return fmt.Errorf("lab requires a single-user unprivileged user namespace")
	}
	if *direction != "incoming" && *direction != "outgoing" {
		return fmt.Errorf("invalid direction")
	}
	if *timeout < time.Second || *timeout > time.Minute {
		return fmt.Errorf("timeout must be 1s..1m")
	}
	p, err := filepath.Abs(*socket)
	if err != nil {
		return err
	}
	e := daemon.New(*timeout)
	if *rulepath != "" {
		b, err := os.ReadFile(*rulepath)
		if err != nil {
			return err
		}
		var rules []policy.Rule
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&rules); err != nil {
			return err
		}
		if err = e.SetRules(rules); err != nil {
			return err
		}
	}
	l, err := daemon.Serve(p, e, false)
	if err != nil {
		return err
	}
	defer l.Close()
	ro, err := daemon.Serve(p+".monitor", e, true)
	if err != nil {
		return err
	}
	defer ro.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	// Exclusive fixed table creation fails if present; cleanup is namespace-owned and table-specific.
	hook := "input"
	if *direction == "outgoing" {
		hook = "output"
	}
	rules := fmt.Sprintf(`create table inet flowgate_lab
add chain inet flowgate_lab gate { type filter hook %s priority 10; policy accept; }
add rule inet flowgate_lab gate meta l4proto tcp tcp flags & (syn | ack) == syn queue num 100
add rule inet flowgate_lab gate meta l4proto tcp ct mark %d ct state established,related accept
add rule inet flowgate_lab gate meta l4proto tcp drop
add rule inet flowgate_lab gate meta l4proto udp ct direction reply ct mark %d accept
add rule inet flowgate_lab gate meta l4proto udp queue num 100
`, hook, queue.Mark, queue.Mark)
	installed := false
	defer func() {
		if installed && ctx.Err() != nil {
			exec.Command("nft", "delete", "table", "inet", "flowgate_lab").Run()
		}
	}()
	return queue.Run(ctx, e, *direction, func() error {
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		b, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft: %w: %s", err, b)
		}
		installed = true
		fmt.Fprintln(os.Stderr, "READY: disposable namespace enforcement; v1 API", p)
		return nil
	})
}
