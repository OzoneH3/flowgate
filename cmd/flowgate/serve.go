package main

import (
	"context"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/monitor"
	"flowgate/internal/readiness"
	"flowgate/internal/store"
	"flowgate/internal/udpaccount"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	socket := fs.String("socket", "", "existing root-owned API directory + new private socket")
	database := fs.String("database", "", "SQLite file in an existing secure root-owned directory")
	uid := fs.Int("uid", -1, "explicit desktop peer UID")
	administrator := fs.Bool("administrator", false, "root grants that selected UID machine-wide visibility and rule authority")
	helper := fs.String("udp-helper", "", "reviewed UDP native helper; pinned at startup but never implicitly attached")
	allowEvaluation := fs.Bool("allow-evaluation", false, "explicit selected administrator authority to start/stop incoming five-minute evaluation")
	evaluationState := fs.String("evaluation-state", "/run/flowgate-evaluation", "root-owned evaluation state; prepared only on explicit Start")
	allowTraffic := fs.Bool("allow-traffic-control", false, "explicitly allow the selected administrator to start/stop machine UDP collection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "serve requires a root Go daemon; Electron remains unprivileged", "Use read-only ordinary launch; privileged manual start is a separate explicit action")
	}
	if *allowEvaluation && !*administrator {
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
	e := daemon.New(30 * time.Second)
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
	observer.UDP = traffic.Snapshot
	e.Activity = observer.Snapshot
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	evaluation := hostfirewall.NewEvaluation(ctx, e, *evaluationState, *socket, *database)
	e.Evaluation = evaluation
	if *allowEvaluation {
		e.EvaluationControlUID = &peer
	}
	e.Enforcement = func() daemon.EnforcementStatus {
		s := evaluation.Status()
		return daemon.EnforcementStatus{State: s.State, Profile: s.Profile, StopsAt: s.StopsAt, Detail: s.Reason}
	}
	defer evaluation.Close()
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
