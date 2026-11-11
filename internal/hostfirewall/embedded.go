package hostfirewall

// Daemon-owned evaluation: no database, API, observer or UDP ownership here.
import (
	"bufio"
	"context"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/queue"
	"flowgate/internal/readiness"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"
)

type Evaluation struct {
	socketFailure         error
	socketFactory         SocketSessionFactory
	socketSession         SocketSessionResources
	continuous            bool
	desiredMode           string
	desiredPath           string
	mu                    sync.Mutex
	e                     *daemon.Engine
	ctx                   context.Context
	dir, socket, database string
	status                daemon.EvaluationStatus
	cancel                context.CancelFunc
	done                  chan struct{}
	probing               bool
	duration              time.Duration // fixed five minutes in production; shortened by in-package tests only
	probe                 func() []readiness.Check
	runner                func(context.Context, func() error) error
	prepare               func() (string, error)      // in-package fault fixture only
	establishedPreflight  func(context.Context) error // fresh read-only compatibility check
	afterInstall          func() error                // in-package partial activation failure fixture only
}

func NewEvaluation(ctx context.Context, e *daemon.Engine, dir, socket, database string) *Evaluation {
	m := &Evaluation{e: e, ctx: ctx, dir: dir, socket: socket, database: database, duration: 5 * time.Minute}
	m.status = daemon.EvaluationStatus{State: "stopped", Profile: "incoming", DurationSeconds: 300, Cleanup: "not_needed", ReasonCode: "monitoring", Reason: "Monitoring only; no evaluation resources", Readiness: daemon.EvaluationReadiness{State: "not_checked", Checks: []readiness.Check{}}}
	m.status.Review = "For five minutes, current stored rules decide new incoming TCP/UDP; supported unmatched applications prompt, unknown/ambiguous ownership blocks. Existing connections are preserved; outgoing remains allowed. Stop/expiry removes only FlowGate enforcement and does not disconnect already-approved TCP deliberately. Other firewalls can still block. Closing the GUI does not stop or extend the deadline."
	m.status.UnsupportedOutgoing = "Bounded evaluation supports incoming only. Use continuous-firewall-v1 for supported continuous incoming+outgoing protection."
	m.probe = func() []readiness.Check {
		ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
		defer cancel()
		return readiness.FirewallFor(ctx, readiness.Default(), m.Status().Profile, e.AdministratorUID != nil)
	}
	m.runner = func(ctx context.Context, ready func() error) error {
		return queue.RunConfigured(ctx, e, m.Status().Profile, Queue, false, ready)
	}
	m.establishedPreflight = checkEstablishedTCP
	m.prepare = func() (string, error) { return PrepareSession(m.dir, filepath.Dir(m.socket), m.database) }
	return m
}
func (m *Evaluation) Status() daemon.EvaluationStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Readiness.Checks = append([]readiness.Check{}, s.Readiness.Checks...)
	return s
}
func blocked(checks []readiness.Check) error {
	for _, c := range checks {
		if c.Status == readiness.Blocked || (c.Status == readiness.Unchecked && c.ID != "firewall.queue_census") {
			return &readiness.Failure{Check: c}
		}
	}
	return nil
}
func (m *Evaluation) setChecks(checks []readiness.Check) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := "ready"
	if blocked(checks) != nil {
		state = "blocked"
	}
	m.status.Readiness = daemon.EvaluationReadiness{State: state, CheckedAt: time.Now(), Checks: checks}
}
func (m *Evaluation) Readiness() daemon.EvaluationStatus {
	m.mu.Lock()
	if !m.probing && (m.status.State == "stopped" || m.status.State == "failed") {
		m.probing = true
		m.status.Readiness.State = "checking"
		go func() { checks := m.probe(); m.setChecks(checks); m.mu.Lock(); m.probing = false; m.mu.Unlock() }()
	}
	m.mu.Unlock()
	return m.Status()
}
func lifecycleError(code, message string) error {
	return &daemon.RuleMutationError{Code: code, Message: message}
}
func validNonce(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (m *Evaluation) Start(expected, request string) (daemon.EvaluationStatus, error) {
	return m.start(expected, request, "incoming", false)
}
func (m *Evaluation) start(expected, request, profile string, continuous bool) (daemon.EvaluationStatus, error) {
	m.mu.Lock()
	if !validNonce(request) {
		m.mu.Unlock()
		return m.Status(), lifecycleError("invalid_request", "fresh 32 lowercase hexadecimal request_id required")
	}
	if request == m.status.RequestID && (continuous != m.continuous || profile != m.status.Profile) {
		m.mu.Unlock()
		return m.Status(), lifecycleError("protection_conflict", "request_id already binds another lifecycle/profile")
	}
	if request == m.status.RequestID && continuous == m.continuous && profile == m.status.Profile {
		m.mu.Unlock()
		return m.Status(), nil
	}
	if expected != m.status.ID {
		m.mu.Unlock()
		return m.Status(), lifecycleError("evaluation_conflict", "Evaluation changed; refresh and confirm again")
	}
	if m.probing || m.cancel != nil {
		m.mu.Unlock()
		return m.Status(), lifecycleError("busy", "Readiness/evaluation operation still in flight")
	}
	if m.status.Cleanup == "unconfirmed" || m.socketSession != nil {
		m.mu.Unlock()
		return m.Status(), lifecycleError("unavailable", "Owned resources require scoped recovery before another Start")
	}
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return m.Status(), lifecycleError("unavailable", "Daemon shutting down")
	}
	fromMonitoring := continuous && m.desiredMode == "monitoring"
	if continuous {
		if err := m.saveDesired(profile); err != nil {
			m.mu.Unlock()
			return m.Status(), err
		}
	} else if m.desiredMode != "" && m.desiredMode != "monitoring" {
		m.mu.Unlock()
		return m.Status(), lifecycleError("busy", "Stop continuous protection before starting evaluation")
	}
	m.socketFailure = nil
	m.continuous = continuous
	m.status.Profile = profile
	m.status.DurationSeconds = 300
	m.status.ID = decisionlog.NewRecordID()
	m.status.RequestID = request
	m.status.State = "starting"
	m.status.Cleanup = "pending"
	m.status.StopsAt = time.Now().Add(m.duration)
	m.status.ReasonCode = "starting"
	m.status.Reason = "Rechecking preflight, watchdog, queue and owned interception"
	ctx, cancel := context.WithDeadline(m.ctx, m.status.StopsAt)
	if continuous {
		cancel()
		ctx, cancel = context.WithCancel(m.ctx)
		m.status.StopsAt = time.Time{}
		m.status.DurationSeconds = 0
	}
	m.cancel = cancel
	m.done = make(chan struct{})
	id := m.status.ID
	m.mu.Unlock()
	go m.run(ctx, id, fromMonitoring)
	return m.Status(), nil
}
func (m *Evaluation) Stop(expected string) (daemon.EvaluationStatus, error) {
	return m.stop(expected, false)
}
func (m *Evaluation) stop(expected string, continuous bool) (daemon.EvaluationStatus, error) {
	m.mu.Lock()
	if m.continuous != continuous {
		m.mu.Unlock()
		return m.Status(), lifecycleError("protection_conflict", "Wrong lifecycle; refresh continuous/evaluation status")
	}
	if continuous && expected == m.status.ID {
		if err := m.saveDesired("monitoring"); err != nil {
			m.mu.Unlock()
			return m.Status(), err
		}
	}
	if expected == "" || expected != m.status.ID {
		m.mu.Unlock()
		return m.Status(), lifecycleError("evaluation_conflict", "Current evaluation_id required")
	}
	if m.cancel == nil && (m.status.Cleanup == "unconfirmed" || continuous) {
		ctx, cancel := context.WithCancel(m.ctx)
		_ = ctx
		m.cancel = cancel
		m.done = make(chan struct{})
		id := m.status.ID
		m.status.State = "stopping"
		m.status.ReasonCode = "cleanup_retry"
		m.status.Reason = "Retrying cleanup of this exact owned evaluation"
		go func() {
			err := cleanupEmbedded(m.dir, id)
			if continuous && os.IsNotExist(err) {
				err = nil
			}
			if err == nil {
				err = m.releaseSocketSession()
			}
			if err == nil && continuous {
				err = RemoveGuard(m.dir)
			}
			m.finish(err, err == nil)
		}()
	} else if m.cancel != nil {
		m.status.State = "stopping"
		m.status.ReasonCode = "stop_requested"
		m.status.Reason = "Dropping held packets and removing only owned resources"
		cancel, session := m.cancel, m.socketSession
		m.mu.Unlock()
		var err error
		if session != nil {
			err = session.Disable()
		}
		cancel()
		return m.Status(), err
	}
	m.mu.Unlock()
	return m.Status(), nil
}
func (m *Evaluation) Close() {
	m.mu.Lock()
	cancel, done, session := m.cancel, m.done, m.socketSession
	m.mu.Unlock()
	if cancel != nil {
		if session != nil {
			_ = session.Disable()
		}
		cancel()
		<-done
	}
}
func (m *Evaluation) finish(err error, clean bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finishLocked(err, clean)
}

func (m *Evaluation) finishLocked(err error, clean bool) {
	if err != nil {
		m.status.State = "failed"
		m.status.ReasonCode = "activation_failed"
		m.status.Reason = err.Error()
		if _, unsupported := err.(*unsupportedEstablishedTCP); unsupported && clean && m.desiredMode == "monitoring" {
			m.status.State = "stopped"
			m.status.ReasonCode = "unsupported_established_tcp"
			m.status.Reason = "Activation refused; monitoring remains available: " + err.Error()
		}
		var failure *readiness.Failure
		if errors.As(err, &failure) {
			m.status.ReasonCode = failure.Check.Code
		}
	} else {
		m.status.State = "stopped"
		m.status.ReasonCode = "stopped"
		m.status.Reason = "Evaluation ended; FlowGate is not controlling traffic"
		if m.continuous {
			m.status.Reason = "Protection stopped intentionally; monitoring and independent collectors remain available"
		}
		if !m.continuous && !time.Now().Before(m.status.StopsAt) {
			m.status.ReasonCode = "expired"
			m.status.Reason = "Original five-minute deadline reached; FlowGate enforcement stopped"
		}
	}
	if m.continuous && m.desiredMode != "monitoring" && err != nil {
		clean = false
	}
	if clean {
		m.status.Cleanup = "confirmed"
	} else {
		m.status.State = "degraded"
		m.status.Cleanup = "unconfirmed"
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel = nil
	close(m.done)
}

// The caller has identified the sole, pre-claim compatibility refusal from an
// explicit monitoring activation. Persist monitoring before cleanup, as Stop
// does, so a crash resumes that exact owned cleanup instead of retrying Both.
func (m *Evaluation) finishUnsupported(id string, refusal error, validate, cleanup func() error) (bool, error) {
	m.mu.Lock()
	current := m.status.ID == id && (m.status.State == "starting" || m.status.State == "stopping")
	m.mu.Unlock()
	if !current {
		return true, nil
	}
	if validate != nil {
		if err := validate(); err != nil {
			return false, errors.Join(refusal, err)
		}
	}
	m.mu.Lock()
	if m.status.ID != id || (m.status.State != "starting" && m.status.State != "stopping") {
		m.mu.Unlock()
		return true, nil // Another lifecycle is never ours to finish or clean.
	}
	deliberateStop := m.desiredMode == "monitoring"
	var err error
	if !deliberateStop {
		err = m.saveDesired("monitoring")
	}
	m.mu.Unlock()
	if err != nil {
		return false, errors.Join(refusal, err)
	}
	if cleanup != nil {
		if err := cleanup(); err != nil {
			return false, errors.Join(refusal, err)
		}
	}
	if deliberateStop {
		refusal = nil
	}
	m.finish(refusal, true)
	return true, nil
}

func (m *Evaluation) run(ctx context.Context, id string, fromMonitoring bool) {
	m.mu.Lock()
	continuous, profile := m.continuous, m.status.Profile
	m.mu.Unlock()
	if continuous {
		if err := RecoverContinuous(m.dir); err != nil {
			m.finish(err, false)
			return
		}
	}
	checks := m.probe()
	m.setChecks(checks)
	if ctx.Err() != nil {
		m.finish(nil, true)
		return
	}
	if err := blocked(checks); err != nil {
		m.finish(err, true)
		return
	}
	// Only a deliberate attempt from clean monitoring can return to monitoring
	// on this specific compatibility refusal. Persisted protection restoration and
	// every other failure retain their existing fail-closed behaviour.
	refuseCleanly := false
	if continuous && fromMonitoring {
		present, err := guardOwned(m.dir)
		if err != nil {
			m.finish(err, false)
			return
		}
		refuseCleanly = !present
		if refuseCleanly {
			err := m.establishedPreflight(ctx)
			if _, unsupported := err.(*unsupportedEstablishedTCP); unsupported {
				handled, refusalErr := m.finishUnsupported(id, err, func() error {
					present, er := guardOwned(m.dir)
					if er != nil {
						return er
					}
					if present {
						return fmt.Errorf("guard appeared after activation preflight")
					}
					return nil
				}, nil)
				if handled {
					return
				}
				err = refusalErr // Integrity/I/O failure uses the ordinary failure guard.
			}
			if err != nil {
				m.mu.Lock()
				if m.desiredMode == "monitoring" {
					m.mu.Unlock()
					cleanupErr := RemoveGuard(m.dir)
					m.finish(cleanupErr, cleanupErr == nil)
					return
				}
				m.mu.Unlock()
				if guardErr := InstallGuard(m.dir, m.e.ApprovedBootstrap()...); guardErr != nil {
					err = errors.Join(err, guardErr)
				}
				// Stop may have raced guard installation; commit under the same lock as
				// saveDesired, or finish its exact-owned cleanup instead of losing Stop.
				m.mu.Lock()
				if m.desiredMode != "monitoring" {
					m.finishLocked(err, false)
					m.mu.Unlock()
					return
				}
				m.mu.Unlock()
				cleanupErr := RemoveGuard(m.dir)
				m.finish(cleanupErr, cleanupErr == nil)
				return
			}
		}
	}
	bootstrap := m.e.ApprovedBootstrap()
	if ctx.Err() != nil {
		m.finish(nil, true)
		return
	}
	var activationGuard guardRecord
	if continuous {
		if err := InstallGuard(m.dir, bootstrap...); err != nil {
			m.finish(err, false)
			return
		}
		var err error
		activationGuard, err = guardMetadata(m.dir)
		if err != nil {
			m.finish(err, false)
			return
		}
	}
	exe, err := m.prepare()
	if err != nil {
		m.finish(err, true)
		return
	}
	owner, err := lock(m.dir)
	if err != nil {
		m.finish(err, true)
		return
	}
	var releaseOnce sync.Once
	releaseOwner := func() { releaseOnce.Do(func() { owner.Close() }) }
	defer releaseOwner()
	finish := func(err error, clean bool) { releaseOwner(); m.finish(err, clean) }
	if previous, er := Read(m.dir); er == nil && previous.State != "stopped" {
		finish(fmt.Errorf("previous evaluation requires recovery"), false)
		return
	} else if er != nil && !os.IsNotExist(er) {
		finish(er, false)
		return
	}
	s := m.Status()
	r := Record{Bootstrap: bootstrap, Continuous: continuous, Embedded: true, Profile: profile, Token: id, PID: os.Getpid(), Start: startID(os.Getpid()), NetNS: identity.NetNS(), State: "starting", StopsAt: s.StopsAt}
	if err = save(m.dir, r); err != nil {
		finish(err, true)
		return
	}
	if !continuous {
		if err = startEmbeddedWatch(exe, m.dir, id); err != nil {
			r.State = "stopped"
			save(m.dir, r)
			finish(err, true)
			return
		}
	}
	m.e.ResetAdmission()
	m.e.Decisions.SetRecording(true)
	activated := false
	runctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	auditError := make(chan error, 1)
	var auditDone chan struct{}
	err = m.runner(runctx, func() error {
		return evaluationLock(m.dir, func() error {
			if er := ctx.Err(); er != nil {
				return er
			}
			m.mu.Lock()
			socketEnabled := continuous && profile == "both" && m.socketFactory != nil
			m.mu.Unlock()
			if er := activateProfileWithSocketGate(ctx, id, profile, func() error { r.MarksOwned = true; return save(m.dir, r) }, socketEnabled, bootstrap...); er != nil {
				return er
			}
			if socketEnabled {
				if er := m.prepareSocketSession(runctx); er != nil {
					return er
				}
			}
			if m.afterInstall != nil {
				if er := m.afterInstall(); er != nil {
					return er
				}
			}
			if socketEnabled {
				r.DigestFormat = numericDigestFormat
			}
			digest, er := tableDigestForFormat(Table, r.DigestFormat)
			if er != nil {
				return er
			}
			r.TableDigest = digest
			r.State = "active"
			if er = save(m.dir, r); er != nil {
				return er
			}
			if continuous {
				if yes, er := guardOwned(m.dir); er != nil {
					return er
				} else if yes {
					if _, er = nft("delete", "table", "inet", GuardTable); er != nil {
						return er
					}
				}
			}
			activated = true
			m.mu.Lock()
			if m.status.State == "starting" {
				m.status.State = "active"
				m.status.ReasonCode = "active"
				m.status.Reason = "Incoming interception verified; independent deadline armed"
				if continuous {
					m.status.Reason = "Continuous " + profile + " interception verified; GUI not required"
				}
			}
			m.mu.Unlock()
			expectedDigest := r.TableDigest
			lastSafety := time.Now()
			lastBootstrap := time.Now()
			type bootstrapResult struct {
				scopes []policy.BootstrapInterface
				err    error
			}
			bootstrapResults := make(chan bootstrapResult, 1)
			bootstrapPending := false
			auditDone = make(chan struct{})
			go func(record Record) {
				inconclusiveAudits := 0
				defer close(auditDone)
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-runctx.Done():
						return
					case <-ticker.C:
						present, er := owns(record)
						if er == nil && !present {
							er = fmt.Errorf("owned interception table disappeared")
						}
						if er == nil {
							var d string
							d, er = tableDigestForFormat(Table, record.DigestFormat)
							if er == nil && d != expectedDigest && record.DigestFormat == numericDigestFormat {
								// Re-read a name-resolved snapshot once before treating a
								// possible concurrent interface-name swap as rule mutation.
								d, er = tableDigestForFormat(Table, record.DigestFormat)
							}
							if er == nil && d != expectedDigest {
								er = fmt.Errorf("owned interception table changed")
							}
						}
						if errors.Is(er, errAuditInconclusive) {
							inconclusiveAudits++
							_ = m.e.DisableSocketAuthorization(er)
							if inconclusiveAudits < 3 {
								continue
							}
						} else {
							inconclusiveAudits = 0
						}
						if er == nil && continuous && time.Since(lastSafety) >= 10*time.Second {
							er = m.auditEnvironment(runctx, profile)
							lastSafety = time.Now()
						}
						if er == nil && continuous {
							select {
							case result := <-bootstrapResults:
								bootstrapPending = false
								if result.err != nil {
									log.Printf("WARNING: DHCP refresh discovery failed; retaining active scopes: %v", result.err)
								} else if !slices.Equal(result.scopes, bootstrap) {
									er = refreshBootstrap(runctx, m.dir, &record, result.scopes)
									if er == nil {
										bootstrap = record.Bootstrap
										expectedDigest = record.TableDigest
									}
								}
							default:
							}
							if !bootstrapPending && time.Since(lastBootstrap) >= 30*time.Second {
								bootstrapPending = true
								lastBootstrap = time.Now()
								go func() { scopes, err := m.e.DiscoverBootstrap(runctx); bootstrapResults <- bootstrapResult{scopes, err} }()
							}
						}
						if er != nil {
							if runctx.Err() != nil {
								return
							}
							if continuous {
								m.mu.Lock()
								m.status.State = "degraded"
								m.status.ReasonCode = "runtime_compatibility_failed"
								m.status.Reason = er.Error()
								m.status.Cleanup = "unconfirmed"
								m.mu.Unlock()
								if guardErr := InstallGuard(m.dir, bootstrap...); guardErr != nil {
									er = fmt.Errorf("%v; guard installation failed: %w", er, guardErr)
								}
							}
							select {
							case auditError <- er:
							default:
							}
							cancelRun()
							return
						}
					}
				}
			}(r)
			return nil
		})
	})
	cancelRun()
	// No accelerator rule mutation: failed sessions retain their audited owner
	// until exact table cleanup succeeds, including deliberate cleanup retries.
	stopErr := m.stopSocketSession()
	if stopErr != nil {
		err = errors.Join(err, stopErr)
	}
	if auditDone != nil {
		<-auditDone
	}
	// Queue has drained held packets before returning. On unexpected failure keep
	// owned interception fail-closed until deliberate Stop or original deadline.
	m.e.ResetAdmission()
	m.e.Decisions.SetRecording(false)
	auditFailed := false
	select {
	case er := <-auditError:
		err = er
		auditFailed = true
	default:
	}
	if err != nil && activated && !auditFailed && ctx.Err() == nil {
		m.mu.Lock()
		m.status.State = "degraded"
		m.status.ReasonCode = "queue_failed"
		m.status.Reason = err.Error()
		m.status.Cleanup = "unconfirmed"
		m.mu.Unlock()
		<-ctx.Done()
	}
	// A post-preflight compatibility race is still returned before claim or
	// installation. Never classify joined teardown/integrity errors as refusals.
	if _, unsupported := err.(*unsupportedEstablishedTCP); unsupported && refuseCleanly && !activated && !auditFailed && stopErr == nil && ctx.Err() == nil {
		validateGuard := func() error {
			yes, er := guardOwned(m.dir)
			if er != nil {
				return er
			}
			if !yes {
				return fmt.Errorf("activation guard disappeared")
			}
			actual, er := guardMetadata(m.dir)
			if er != nil {
				return er
			}
			if actual != activationGuard {
				return fmt.Errorf("activation guard generation changed")
			}
			return nil
		}
		handled, refusalErr := m.finishUnsupported(id, err, validateGuard, func() error {
			if er := cleanupEmbedded(m.dir, id); er != nil {
				return er
			}
			if er := m.releaseSocketSession(); er != nil {
				return er
			}
			if er := validateGuard(); er != nil {
				return er
			}
			return RemoveGuard(m.dir)
		})
		if !handled {
			finish(refusalErr, false)
		}
		return
	}
	if continuous {
		m.mu.Lock()
		deliberate := m.desiredMode == "monitoring"
		m.mu.Unlock()
		if !deliberate {
			guardErr := InstallGuard(m.dir, bootstrap...)
			if err == nil {
				err = fmt.Errorf("continuous consumer ended; new admissions fail closed until restart or explicit recovery")
			}
			if guardErr != nil {
				err = fmt.Errorf("%v; guard: %w", err, guardErr)
			}
			// Stop may arrive while the failure guard is being installed. Commit
			// the degraded outcome under the same lock as desired-mode updates;
			// otherwise an acknowledged Stop can be lost between these steps.
			m.mu.Lock()
			if m.desiredMode != "monitoring" {
				m.finishLocked(err, false)
				m.mu.Unlock()
				return
			}
			m.mu.Unlock()
		}
	}
	cleanupErr := cleanupEmbedded(m.dir, id)
	if cleanupErr == nil {
		cleanupErr = m.releaseSocketSession()
	}
	if cleanupErr == nil && continuous {
		cleanupErr = RemoveGuard(m.dir)
	}
	m.e.Decisions.SetRecording(false)
	if cleanupErr != nil {
		finish(cleanupErr, false)
		return
	}
	if ctx.Err() != nil {
		err = nil
	}
	finish(err, true)
}

// Separate cleanup lock serializes activation and the independent watchdog.
func evaluationLock(dir string, fn func() error) error {
	fd, err := unix.Open(filepath.Join(dir, "cleanup.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(20 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			return fmt.Errorf("evaluation cleanup lock: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fn()
}
func cleanupEmbedded(dir, token string) error {
	return evaluationLock(dir, func() error {
		r, err := Read(dir)
		if err != nil {
			return err
		}
		if !r.Embedded || r.Token != token {
			return fmt.Errorf("evaluation changed; refusing cleanup")
		}
		if r.State == "stopped" {
			return nil
		}
		if err = remove(r); err != nil {
			r.State = "degraded"
			save(dir, r)
			return err
		}
		r.State = "stopped"
		return save(dir, r)
	})
}
func startEmbeddedWatch(exe, dir, token string) error {
	cmd := exec.Command(exe, "host-embedded-watch", "--state", dir, "--token", token)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(dir, "watchdog.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		ready <- scanner.Scan() && scanner.Text() == "READY "+token
		out.Close()
	}()
	select {
	case ok := <-ready:
		if !ok {
			return fmt.Errorf("independent watchdog did not acknowledge")
		}
		return nil
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		return fmt.Errorf("watchdog readiness timeout")
	}
}
func WatchEmbedded(dir, token string) error {
	r, err := Read(dir)
	if err != nil {
		return err
	}
	if !r.Embedded || r.Token != token {
		return fmt.Errorf("wrong embedded evaluation")
	}
	fmt.Println("READY", token)
	for {
		r, err = Read(dir)
		if err != nil {
			return err
		}
		if r.Token != token || r.State == "stopped" {
			return nil
		}
		if !time.Now().Before(r.StopsAt) {
			return cleanupEmbedded(dir, token)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
