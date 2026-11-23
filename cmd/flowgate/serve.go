package main

import (
	"context"
	"flag"
	"flowgate/internal/accounting"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/essential"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/identity"
	"flowgate/internal/monitor"
	"flowgate/internal/readiness"
	diagnostics "flowgate/internal/serveprofile"
	"flowgate/internal/socketgrant"
	"flowgate/internal/store"
	"flowgate/internal/tcpinit"
	"flowgate/internal/udpaccount"
	"flowgate/internal/uploadshape"
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
	iteratorHelper := fs.String("holder-iterator-helper", "", "explicit reviewed task_file iterator loader; capability failure retains /proc")
	socketAuthorization := fs.Bool("socket-authorization", false, "opt-in connection-lifetime socket-bound IPv4 UDP output authorization; requires supported build and continuous protection")
	allowProtection := fs.Bool("allow-protection", false, "explicit selected administrator authority for continuous Start/Stop")
	protectionState := fs.String("protection-state", "/var/lib/flowgate/protection.json", "durable desired protection mode")
	restoreUDP := fs.Bool("restore-udp", false, "restore previously authorized machine UDP monitoring independently of firewall")
	notify := fs.Bool("systemd-notify", false, "send readiness only after policy and desired enforcement initialized")
	decisionTimeout := fs.Duration("decision-timeout", 30*time.Second, "bounded pending retention (1s-60s)")
	allowEvaluation := fs.Bool("allow-evaluation", false, "explicit selected administrator authority to start/stop incoming five-minute evaluation")
	evaluationState := fs.String("evaluation-state", "/run/flowgate-evaluation", "root-owned evaluation state; prepared only on explicit Start")
	allowTraffic := fs.Bool("allow-traffic-control", false, "explicitly allow the selected administrator to start/stop machine UDP collection")
	shapeInterface := fs.String("experimental-upload-interface", "", "opt-in experimental native upload API on one supported interface; disabled by default")
	shapeHelpers := fs.String("experimental-upload-helpers", "", "root-owned M1 helper directory")
	shapeState := fs.String("experimental-upload-state", "", "private isolated controller journal directory")
	shapeHost := fs.Bool("experimental-upload-host-trial", false, "explicit experimental physical-interface trial opt-in; mutually exclusive with parent-netns; no automatic activation")
	shapeParent := fs.String("experimental-upload-parent-netns", "", "explicit parent namespace; child namespace required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return readiness.Fail("permission_required", "serve requires a root Go daemon; Electron remains unprivileged", "Use read-only ordinary launch; privileged manual start is a separate explicit action")
	}
	if (*allowEvaluation || *allowProtection) && !*administrator {
		return fmt.Errorf("--allow-evaluation requires --administrator")
	}
	if *socketAuthorization && !*allowProtection {
		return fmt.Errorf("--socket-authorization requires --allow-protection")
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
	if *iteratorHelper != "" {
		close, err := identity.EnableHolderIterator(*iteratorHelper, holderIteratorSHA256)
		if err != nil {
			fmt.Fprintln(os.Stderr, "holder iterator unavailable; using /proc:", err)
		} else {
			defer close()
		}
	}
	db, err := store.OpenExclusive(*database)
	if err != nil {
		return err
	}
	defer db.Close()
	rules, err := db.LoadCurrent(time.Now())
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
	timeoutSeconds, timeoutRevision, err := db.DecisionTimeout()
	if err != nil {
		return err
	}
	e.InitDecisionTimeout(timeoutSeconds, timeoutRevision, db.SaveDecisionTimeout)
	disabledChecks, checksRevision, err := db.ConnectionChecks()
	if err != nil {
		return err
	}
	e.InitConnectionChecks(disabledChecks, checksRevision, db.SaveConnectionChecks)
	build := buildIdentity()
	e.Build = &build
	e.Zones = zones
	defer e.CloseProcessTargets()
	peer := uint32(*uid)
	e.APIUID = &peer
	if *administrator {
		e.AdministratorUID = &peer
	}
	if *shapeInterface != "" && !*administrator {
		return fmt.Errorf("experimental upload requires explicit administrator")
	}
	if *shapeInterface == "" && (*shapeHelpers != "" || *shapeState != "" || *shapeParent != "" || *shapeHost) {
		return fmt.Errorf("experimental upload options require an explicit interface")
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
	// Both directories were verified above. The collector chooses an
	// executable mount without changing either mount's policy.
	traffic := udpaccount.NewManager(*helper, udpCollectorSHA256, filepath.Dir(*socket), filepath.Dir(*database))
	defer traffic.Close()
	e.Traffic = traffic
	if *allowTraffic {
		e.TrafficControlUID = &peer
	}
	observer := monitor.New(time.Second)
	e.ObservedUsage = accounting.New()
	history, historyErr := accounting.OpenHistory(filepath.Join(filepath.Dir(*database), "usage-history.db"), e.ObservedUsage, e.Generation)
	if historyErr != nil {
		fmt.Fprintln(os.Stderr, "WARNING: usage history unavailable:", historyErr)
		history = accounting.UnavailableHistory(historyErr)
	}
	e.UsageHistory = history
	defer history.Close()
	observer.Observed = e.ObservedUsage.Observe
	observer.Zones = zones
	observer.UDP = traffic.AccountingSnapshot
	e.Activity = observer.Snapshot
	e.ConnectionSample = observer.ConnectionSample
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	socketResolvers := daemon.SocketSessionResolvers{
		Fresh: identity.Resolve,
		Observed: func(f identity.Flow) (identity.Attribution, uint64) {
			start := socketgrant.BootNow()
			return identity.Resolve(f), start
		},
	}
	var wineResolve func(identity.Flow) identity.Attribution
	if *wineHelper != "" {
		health := readiness.NewRuntimeMonitor()
		e.RuntimeChecks = health.Snapshot
		for _, check := range health.Snapshot() {
			if check.Status != readiness.Ready {
				fmt.Fprintln(os.Stderr, "WARNING:", check.Detail, check.Next)
			}
		}
		go health.Run(ctx)
		scratch := filepath.Join(filepath.Dir(*socket), "wine-observer")
		if err = os.MkdirAll(scratch, 0700); err != nil {
			return err
		}
		if err = os.Chown(scratch, int(peer), -1); err != nil {
			return err
		}
		wines, er := identity.NewWineObservers(identity.WineObserverOptions{ReserveRenewalCapacity: false, Discover: len(wineBins) == 0 && len(winePrefixes) == 0, Helper: *wineHelper, RuntimeBins: wineBins, Prefixes: winePrefixes, UID: peer, Scratch: scratch})
		if er != nil {
			return er
		}
		defer wines.Close()
		wineResolve = wines.ResolveFresh
		socketResolvers = daemon.SocketSessionResolvers{Fresh: wines.ResolveFresh, Observed: wines.ResolveObserved, Group: wines.ResolveFrozenRuntime, Diagnostics: wines.RenewalStatus}
		resolver := identity.NewUDPAttributionReuse(wines.Resolve)
		resolver.Try = wines.TryResolve
		e.Resolve, e.TryResolve = resolver.Resolve, resolver.TryResolve
		observer.Annotate = wines.AnnotateActivity
		observer.AnalyzeRuntime = wines.AnnotateConnectionAnalysis
	} else if len(wineBins) > 0 || len(winePrefixes) > 0 {
		return fmt.Errorf("Wine runtime/prefix selection requires --wine-helper")
	}
	if *shapeInterface != "" {
		preferences, er := db.ShapingPreferences()
		if er != nil {
			return fmt.Errorf("load shaping preferences: %w", er)
		}
		manager, er := uploadshape.New(uploadshape.Options{Zones: e.CurrentZones, Interface: *shapeInterface,
			Helpers: *shapeHelpers, State: *shapeState, ParentNetNS: *shapeParent, HostTrial: *shapeHost,
			WineResolve: wineResolve}, preferences, db.SaveShapingPreferences)
		if er != nil {
			return er
		}
		e.UploadShaping = manager
		defer manager.Close()
	}
	hostfirewall.ConfigureEstablishedTCP(e, socketResolvers.Fresh)
	// Construct outside Engine.mu: the initial refresh publishes through Engine.
	zoneManager := identity.NewZoneManagerWithPublisher(zones.Legacy(), e.NetworkZonePublisher())
	previousRuntimeChecks := e.RuntimeChecks
	e.RuntimeChecks = func() []readiness.Check {
		var checks []readiness.Check
		if previousRuntimeChecks != nil {
			checks = append(checks, previousRuntimeChecks()...)
		}
		err := zoneManager.PublicationError()
		if retained := e.PublishedSocketAuthorizationFailure(); retained != nil {
			err = retained
		}
		return append(checks, zonePublicationChecks(err)...)
	}
	e.ZoneSource = zoneManager.Snapshot
	observer.ZoneSource = zoneManager.Snapshot
	go zoneManager.Run(ctx)
	initiation := tcpinit.NewWithOptions(ctx, *tcpHelper, *tcpCgroup, filepath.Dir(*socket), tcpinit.Options{ObserveShared: *tcpShared})
	defer initiation.Close()
	observer.InitiationEvents = initiation.Sample
	evaluation := hostfirewall.NewEvaluation(ctx, e, *evaluationState, *socket, *database)
	e.Evaluation = evaluation
	if *socketAuthorization {
		if err = configureSocketAuthorization(evaluation, e, socketResolvers); err != nil {
			return err
		}
	}
	sessionRuntimeChecks := e.RuntimeChecks
	e.RuntimeChecks = func() []readiness.Check {
		var checks []readiness.Check
		if sessionRuntimeChecks != nil {
			checks = append(checks, sessionRuntimeChecks()...)
		}
		return append(checks, socketSessionChecks(evaluation.SocketSessionFailure())...)
	}
	if *allowProtection {
		e.ConfigureEssential(ctx, essential.Default())
		if err = e.RepairMigratedEssential(); err != nil {
			fmt.Fprintln(os.Stderr, "WARNING: essential migration metadata repair failed; affected permissions remain inactive:", err)
		}
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
		return daemon.EnforcementStatus{Session: s.ID, State: s.State, Profile: s.Profile, StopsAt: s.StopsAt, Detail: s.Reason}
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
	if e.UploadShaping != nil {
		e.UploadShaping.Resume()
	}
	// Bounded, explicit administrator captures are available without an opt-in
	// environment file or restart. Idle construction does not start profiling.
	// Close before engine/helper teardown so a capture cannot sample freed state.
	e.Profiler = diagnostics.NewRecorder(ctx, func() any { return e.ProfileSnapshot() })
	defer e.Profiler.Close()
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
	lastFailure := ""
	for {
		if !ready {
			s := evaluation.ProtectionStatus()
			if !*allowProtection || s.DesiredMode == "monitoring" || s.State == "active" || s.State == "failed" || s.State == "degraded" {
				if *notify {
					if err = notifyService("READY=1\nSTATUS=Policy loaded; " + s.State + " " + s.Profile); err != nil {
						return err
					}
				}
				fmt.Fprintln(os.Stderr, "READY: root daemon; desired:", s.DesiredMode, "actual:", s.State)
				ready = true
				stopProfile := diagnostics.StartFromEnvironment(ctx, func() any {
					collector := traffic.Status()
					return map[string]any{"queue_health": e.QueueHealth.Snapshot(true), "collector_state": collector.State, "collector_generation": collector.Generation, "collector_missed_operations": collector.Missed, "build": build}
				})
				defer stopProfile()
			}
		}
		if ready && *notify {
			p, s := evaluation.ProtectionStatus(), evaluation.Status()
			summary := "desired " + p.DesiredMode + "; actual " + s.State + " " + s.Profile + "; " + s.ReasonCode + "; " + s.Reason
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
				// Keep the control API available for an explicit Stop/Retry. The
				// protection manager retains fail-closed resources; readiness here
				// describes the API, never successful traffic enforcement.
				if s.Reason != lastFailure {
					fmt.Fprintln(os.Stderr, "WARNING: protection failed; fail-closed resources retained; use Stop protection to return to monitoring:", s.Reason)
					lastFailure = s.Reason
				}
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
