package main

import (
	"context"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/essential"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/identity"
	"flowgate/internal/monitor"
	"flowgate/internal/readiness"
	"flowgate/internal/store"
	"flowgate/internal/tcpinit"
	"flowgate/internal/udpaccount"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Foreground root daemon foundation: observe and manage stored policy without
// interception. There is intentionally no automatic/implicit firewall path here.
// openDecisionLog never prevents startup: an unavailable log is reported
// through health while policy and enforcement continue unchanged.
func openDecisionLog(path, generation, mode string, recording bool) *decisionlog.Log {
	l, err := decisionlog.Open(path, generation, mode, recording)
	if err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: decision log unavailable:", err)
		return decisionlog.Unavailable(err)
	}
	return l
}

func serveCommand(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var localZones, internetZones, wineBins, winePrefixes zonePrefixes
	fs.Var(&wineBins, "wine-runtime-bin", "repeatable trusted supported Wine/Proton bin directory")
	fs.Var(&winePrefixes, "wine-prefix", "repeatable explicitly authorized existing Wine prefix")
	wineHelper := fs.String("wine-helper", "", "reviewed PE owner observer; opt-in, runs as desktop UID")
	fs.Var(&localZones, "zone-local", "repeatable administrator-defined Local Network prefix")
	fs.Var(&internetZones, "zone-internet", "repeatable administrator-defined Internet policy prefix, not connectivity proof")
	socket := fs.String("socket", "", "existing root-owned API directory + new private socket")
	database := fs.String("database", "", "SQLite file in an existing secure root-owned directory")
	uid := fs.Int("uid", -1, "explicit desktop peer UID")
	administrator := fs.Bool("administrator", false, "root grants that selected UID machine-wide visibility and rule authority")
	tcpHelper := fs.String("tcp-initiation-helper", "", "optional reviewed sockops initiation helper; no host attach without this explicit root startup option")
	tcpShared := fs.Bool("tcp-initiation-observe-shared", false, "explicit shared sockops observation; never changes callback/tuning fields; requires foreign close callbacks")
	tcpCgroup := fs.String("tcp-initiation-cgroup", "/sys/fs/cgroup", "cgroup-v2 observation coverage; current network namespace only")
	helper := fs.String("udp-helper", "", "reviewed UDP native helper; pinned at startup but never implicitly attached")
	allowProtection := fs.Bool("allow-protection", false, "explicit selected administrator authority for continuous Start/Stop")
	protectionState := fs.String("protection-state", "/var/lib/flowgate/protection.json", "durable desired protection mode")
	restoreUDP := fs.Bool("restore-udp", false, "restore previously authorized machine UDP monitoring independently of firewall")
	notify := fs.Bool("systemd-notify", false, "send readiness only after policy and desired enforcement initialized")
	decisionTimeout := fs.Duration("decision-timeout", 30*time.Second, "bounded pending retention (1s-60s)")
	allowEvaluation := fs.Bool("allow-evaluation", false, "explicit selected administrator authority to start/stop incoming five-minute evaluation")
	evaluationState := fs.String("evaluation-state", "/run/flowgate-evaluation", "root-owned evaluation state; prepared only on explicit Start")
	allowTraffic := fs.Bool("allow-traffic-control", false, "explicitly allow the selected administrator to start/stop machine UDP collection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "serve requires a root Go daemon; Electron remains unprivileged", "Use read-only ordinary launch; privileged manual start is a separate explicit action")
	}
	if (*allowEvaluation || *allowProtection) && !*administrator {
		return fmt.Errorf("--allow-evaluation requires --administrator")
	}
	if !filepath.IsAbs(*evaluationState) {
		return fmt.Errorf("--evaluation-state must be absolute")
	}
	if *allowTraffic && !*administrator {
		return fmt.Errorf("--allow-traffic-control requires --administrator")
	}
	if *helper != "" && !filepath.IsAbs(*helper) {
		return fmt.Errorf("--udp-helper must be absolute")
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
	zones, err := configuredZones(localZones, internetZones)
	if err != nil {
		return err
	}
	if *decisionTimeout < time.Second || *decisionTimeout > 60*time.Second {
		return fmt.Errorf("decision-timeout must be 1s–60s")
	}
	e := daemon.New(*decisionTimeout)
	build := buildIdentity()
	e.Build = &build
	e.Zones = zones
	defer e.CloseProcessTargets()
	peer := uint32(*uid)
	e.APIUID = &peer
	if *administrator {
		e.AdministratorUID = &peer
	}
	e.Mode = "daemon-monitor"
	e.SaveRules = db.Replace
	e.Enforcement = func() daemon.EnforcementStatus {
		return daemon.EnforcementStatus{State: "stopped", Detail: "Non-enforcing root daemon: observation and stored policy only; no queue or firewall rules; optional UDP accounting is separately controlled"}
	}
	if err = e.SetRules(rules); err != nil {
		return err
	}
	// History only: this non-enforcing daemon makes no connection decisions.
	e.Decisions = openDecisionLog(filepath.Join(filepath.Dir(*database), "decisions.db"), e.Generation, e.Mode, false)
	defer e.Decisions.Close()
	if err = daemon.SecureDirectory(filepath.Dir(*socket)); err != nil {
		return err
	}
	if *helper == "" {
		exe, er := os.Executable()
		if er != nil {
			return er
		}
		*helper = filepath.Join(filepath.Dir(exe), "udp-collector")
	}
	traffic := udpaccount.NewManager(*helper, filepath.Dir(*socket))
	defer traffic.Close()
	e.Traffic = traffic
	if *allowTraffic {
		e.TrafficControlUID = &peer
	}
	observer := monitor.New(time.Second)
	observer.Zones = zones
	observer.UDP = traffic.Snapshot
	e.Activity = observer.Snapshot
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if *wineHelper != "" {
		scratch := filepath.Join(filepath.Dir(*socket), "wine-observer")
		if err = os.MkdirAll(scratch, 0700); err != nil {
			return err
		}
		if err = os.Chown(scratch, int(peer), -1); err != nil {
			return err
		}
		wines, er := identity.NewWineObservers(identity.WineObserverOptions{Discover: len(wineBins) == 0 && len(winePrefixes) == 0, Helper: *wineHelper, RuntimeBins: wineBins, Prefixes: winePrefixes, UID: peer, Scratch: scratch})
		if er != nil {
			return er
		}
		defer wines.Close()
		e.Resolve = wines.Resolve
		observer.Annotate = wines.AnnotateActivity
	} else if len(wineBins) > 0 || len(winePrefixes) > 0 {
		return fmt.Errorf("Wine runtime/prefix selection requires --wine-helper")
	}
	zoneManager := identity.NewZoneManager(zones.Legacy())
	e.ZoneSource = zoneManager.Snapshot
	observer.ZoneSource = zoneManager.Snapshot
	go zoneManager.Run(ctx)
	initiation := tcpinit.NewWithOptions(ctx, *tcpHelper, *tcpCgroup, filepath.Dir(*socket), tcpinit.Options{ObserveShared: *tcpShared})
	defer initiation.Close()
	observer.InitiationEvents = initiation.Sample
	evaluation := hostfirewall.NewEvaluation(ctx, e, *evaluationState, *socket, *database)
	e.Evaluation = evaluation
	if *allowProtection {
		e.ConfigureEssential(ctx, essential.Default())
		if err = evaluation.ConfigureProtection(*protectionState); err != nil {
			return err
		}
		e.Protection = evaluation
		e.ProtectionControlUID = &peer
	}
	if *allowEvaluation {
		e.EvaluationControlUID = &peer
	}
	e.Enforcement = func() daemon.EnforcementStatus {
		s := evaluation.Status()
		return daemon.EnforcementStatus{State: s.State, Profile: s.Profile, StopsAt: s.StopsAt, Detail: s.Reason}
	}
	defer evaluation.Close()
	e.StopMonitoring = cancel
	if err = daemon.RecoverSocket(*socket, peer); err != nil {
		return err
	}
	if err = daemon.RecoverSocket(*socket+".monitor", peer); err != nil {
		return err
	}
	if *allowProtection {
		if err = evaluation.Restore(); err != nil {
			return err
		}
	}
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
	if *restoreUDP {
		if _, er := traffic.Start(); er != nil {
			fmt.Fprintln(os.Stderr, "WARNING: UDP restoration failed independently:", er)
		}
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	lastStatus := ""
	for {
		if !ready {
			s := evaluation.ProtectionStatus()
			if !*allowProtection || s.DesiredMode == "monitoring" || s.State == "active" {
				if *notify {
					if err = notifyService("READY=1\nSTATUS=Policy loaded; " + s.State + " " + s.Profile); err != nil {
						return err
					}
				}
				fmt.Fprintln(os.Stderr, "READY: root daemon; desired:", s.DesiredMode, "actual:", s.State)
				ready = true
			}
		}
		if ready && *notify {
			p, s := evaluation.ProtectionStatus(), evaluation.Status()
			summary := "desired " + p.DesiredMode + "; actual " + s.State + " " + s.Profile + "; " + s.ReasonCode
			if summary != lastStatus {
				if er := notifyService("STATUS=" + summary); er != nil {
					fmt.Fprintln(os.Stderr, "WARNING: status notification:", er)
				}
				lastStatus = summary
			}
		}
		if *allowProtection {
			s := evaluation.ProtectionStatus()
			if s.DesiredMode != "monitoring" && (s.State == "failed" || s.State == "degraded") {
				if *notify {
					notifyService("STATUS=Protection failure: " + s.Reason)
				}
				return fmt.Errorf("continuous protection failed: %s", s.Reason)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func notifyService(message string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return fmt.Errorf("systemd notification requested without NOTIFY_SOCKET")
	}
	if strings.HasPrefix(path, "@") {
		path = "\x00" + path[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(message))
	return err
}
