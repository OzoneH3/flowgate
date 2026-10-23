package main

import (
	"context"
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/monitor"
	"flowgate/internal/policy"
	"flowgate/internal/queue"
	"flowgate/internal/store"
	"flowgate/internal/udpaccount"
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
		fmt.Printf("%s: doctor | tailscale-inspect | runtime-discover | sockets | process PID | attribute | pending | decide | rule-delete | monitor-setup | monitor-backup | monitor-stop | serve | observe | serve-lab | host-start | host-status | host-stop | host-recover\n", productName)
		return
	}
	switch os.Args[1] {
	case "system-networking-inspect":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s := essential.Discover(ctx, essential.Default())
		rules, issues, err := s.Rules(essential.Options{}, time.Now())
		if err != nil {
			fatal(err)
		}
		output(struct {
			Discovery  essential.Snapshot `json:"discovery"`
			Rules      []policy.Rule      `json:"rules"`
			Issues     []string           `json:"issues"`
			ReviewOnly bool               `json:"review_only"`
		}{s, rules, issues, true})
	case "version":
		output(buildIdentity())
	case "protection-guard", "protection-recover":
		if err := protectionLocalCommand(os.Args[1], os.Args[2:]); err != nil {
			fatal(err)
		}
	case "host-test-peer", "host-test-peer-child":
		if err := hostTestPeerCommand(os.Args[1], os.Args[2:]); err != nil {
			fatal(err)
		}
	case "host-session", "host-start", "host-stop", "host-status", "host-recover", "host-watch", "host-embedded-watch":
		if err := hostCommand(); err != nil {
			fatal(err)
		}
	case "runtime-discover":
		fs := flag.NewFlagSet("runtime-discover", flag.ExitOnError)
		bins := fs.String("runtime-bins", "/usr/bin", "comma-separated explicitly trusted runtime bin directories")
		helper := fs.String("helper", ".workspace/windows/table-probe.exe", "observer image to detect")
		fs.Parse(os.Args[2:])
		sessions, err := identity.DiscoverRuntimes(strings.Split(*bins, ","), *helper)
		if err != nil {
			fatal(err)
		}
		output(sessions)
	case "tailscale-inspect":
		if err := tailscaleInspectCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "doctor":
		if err := doctorCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
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
		p.Provenance = identity.CaptureProvenance(p)
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
	case "rule-delete":
		if err := deleteRuleCLI(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fatal(err)
		}
	case "pending", "decide":
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		s := fs.String("socket", ".workspace/run/control.sock", "v1 API socket")
		id := fs.String("id", "", "request ID")
		a := fs.String("action", "", "allow/block")
		scope := fs.String("scope", "once", "once/for-a-while/application (for-a-while: this process and direction for 15 seconds, memory only; application: one hour; incoming remote address + local port; outgoing destination)")
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
	case "udp-start", "udp-stop":
		if err := udpCommand(); err != nil {
			fatal(err)
		}
	case "monitor-setup":
		if err := monitorSetupCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "monitor-backup":
		if err := monitorBackupCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "monitor-stop":
		if err := monitorStopCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "serve":
		if err := serveCommand(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "observe":
		if err := observe(); err != nil {
			fatal(err)
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
	var localZones zonePrefixes
	fs.Var(&localZones, "zone-local", "repeatable local policy prefix for isolated acceptance")
	socket := fs.String("socket", ".workspace/run/control.sock", "private socket path")
	parent := fs.String("parent-netns", "", "original namespace identity (required)")
	direction := fs.String("direction", "incoming", "incoming/outgoing")
	timeout := fs.Duration("timeout", 15*time.Second, "pending timeout")
	discoverWine := fs.Bool("discover-wine", false, "discover same-user brokers and validate their live owner census in this isolated namespace")
	observe := fs.String("observe-prefixes", "", "comma-separated workspace prefixes for on-demand Wine census")
	scratch := fs.String("observer-scratch", "", "private workspace observer scratch directory")
	prefixes := fs.String("attach-prefixes", "", "comma-separated already-running workspace prefixes")
	bins := fs.String("runtime-bins", "/usr/bin", "comma-separated trusted runtime bin directories")
	helper := fs.String("wine-helper", ".workspace/windows/table-probe.exe", "workspace PE census helper")
	policyDB := fs.String("policy-store", "", "optional private workspace SQLite rule store for isolated acceptance")
	rulepath := fs.String("rules", "", "JSON rule array")
	decisionPath := fs.String("decision-log", "", "optional absolute decision log path in a private 0700 directory")
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
	defer e.CloseProcessTargets()
	e.Mode = "isolated-lab"
	e.Zones, err = configuredZones(localZones, nil)
	if err != nil {
		return err
	}
	if *policyDB != "" {
		if _, err := identity.WorkspaceObserverScratch(filepath.Dir(*policyDB)); err != nil {
			return err
		}
		st, err := os.Stat(filepath.Dir(*policyDB))
		if err != nil || st.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("private workspace store directory required")
		}
		db, err := store.OpenExclusive(*policyDB)
		if err != nil {
			return err
		}
		defer db.Close()
		rules, err := db.LoadCurrent(time.Now())
		if err != nil {
			return err
		}
		if err = e.SetRules(rules); err != nil {
			return err
		}
		e.SaveRules = db.Replace
	}
	observer := monitor.New(250 * time.Millisecond)
	activityCtx, activityCancel := context.WithCancel(context.Background())
	defer activityCancel()
	e.Activity = observer.Snapshot
	if *decisionPath != "" {
		if !filepath.IsAbs(*decisionPath) {
			return fmt.Errorf("--decision-log must be absolute")
		}
		if st, err := os.Lstat(filepath.Dir(*decisionPath)); err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("--decision-log directory must be a private 0700 directory")
		}
		e.Decisions = openDecisionLog(*decisionPath, e.Generation, e.Mode, true)
		defer func() { e.FinalizePending(); e.Decisions.Close() }()
	}
	if *observe != "" || *discoverWine {
		if *prefixes != "" || os.Getenv("FLOWGATE_WINE_TABLE_RUNNER") != "" {
			return fmt.Errorf("choose one Wine observation mode")
		}
		paths := []string{*scratch, *helper}
		if *observe != "" {
			paths = append(paths, strings.Split(*observe, ",")...)
		}
		for _, path := range paths {
			if _, err := identity.WorkspaceObserverScratch(path); err != nil {
				return err
			}
		}
		options := identity.WineObserverOptions{Helper: *helper, UID: uint32(os.Getuid()), Scratch: *scratch, Discover: *discoverWine}
		if !*discoverWine {
			options.RuntimeBins = strings.Split(*bins, ",")
			options.Prefixes = strings.Split(*observe, ",")
		} else if *observe != "" {
			return fmt.Errorf("choose discovery or explicit prefixes")
		}
		observers, err := identity.NewWineObservers(options)
		if err != nil {
			return err
		}
		defer observers.Close()
		resolver := identity.NewUDPAttributionReuse(observers.Resolve)
		resolver.Try = observers.TryResolve
		e.Resolve, e.TryResolve = resolver.Resolve, resolver.TryResolve
		observer.Annotate = observers.AnnotateActivity
	} else if *prefixes != "" {
		if os.Getenv("FLOWGATE_WINE_TABLE_RUNNER") != "" {
			return fmt.Errorf("choose explicit attachment or legacy environment, not both")
		}
		observers, err := identity.AttachRuntimes(strings.Split(*prefixes, ","), strings.Split(*bins, ","), *helper)
		if err != nil {
			return err
		}
		defer observers.Close()
		e.Resolve = identity.NewUDPAttributionReuse(observers.Resolve).Resolve
		b, _ := json.Marshal(observers.Sessions())
		fmt.Fprintln(os.Stderr, "ATTACHED", string(b))
	} else if runner := os.Getenv("FLOWGATE_WINE_TABLE_RUNNER"); runner != "" {
		observer, err := identity.NewWineTable(runner, os.Getenv("FLOWGATE_WINE_TABLE_HELPER"), os.Getenv("FLOWGATE_WINE_BROKER"), os.Getenv("WINEPREFIX"), os.Getenv("FLOWGATE_WINE_TABLE_VERSION"))
		if err != nil {
			return err
		}
		defer observer.Close()
		e.Resolve = identity.NewUDPAttributionReuse(observer.Resolve).Resolve
	}
	go observer.Run(activityCtx)
	if *rulepath != "" {
		b, err := os.ReadFile(*rulepath)
		if err != nil {
			return err
		}
		rules, err := decodeImportedRules(b)
		if err != nil {
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

// Host observation has no queue, nftables, helper or namespace launch path.
func observe() error {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	socket := fs.String("socket", "", "private API socket path (required)")
	udpSocket := fs.String("udp-socket", fmt.Sprintf("/run/flowgate-traffic/%d/api.sock", os.Getuid()), "optional collection-only UDP socket (empty disables)")
	interval := fs.Duration("interval", time.Second, "collection delay after each snapshot (500ms..30s)")
	fs.Parse(os.Args[2:])
	if *socket == "" || *interval < 500*time.Millisecond || *interval > 30*time.Second {
		return fmt.Errorf("socket required; interval must be 500ms..30s")
	}
	path, err := filepath.Abs(*socket)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	observer := monitor.New(*interval)
	if *udpSocket != "" {
		client := &udpaccount.Client{Path: *udpSocket}
		observer.UDP = client.Snapshot
	}
	e := daemon.New(15 * time.Second)
	defer e.CloseProcessTargets()
	e.Mode = "host-monitor"
	zoneManager := identity.NewZoneManager(identity.DefaultNetworkZones())
	e.Zones = zoneManager.Snapshot()
	e.ZoneSource = zoneManager.Snapshot
	observer.ZoneSource = zoneManager.Snapshot
	go zoneManager.Run(ctx)
	e.Activity = observer.Snapshot
	listener, err := daemon.Serve(path, e, true)
	if err != nil {
		return err
	}
	defer listener.Close()
	go observer.Run(ctx)
	fmt.Fprintln(os.Stderr, "READY: host monitor — read-only", path)
	<-ctx.Done()
	return nil
}
