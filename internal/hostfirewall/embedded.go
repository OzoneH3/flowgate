package hostfirewall

// Daemon-owned evaluation: no database, API, observer or UDP ownership here.
import (
	"bufio"
	"context"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/queue"
	"flowgate/internal/readiness"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Evaluation struct {
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
	prepare               func() (string, error) // in-package fault fixture only
	afterInstall          func() error           // in-package partial activation failure fixture only
}

func NewEvaluation(ctx context.Context, e *daemon.Engine, dir, socket, database string) *Evaluation {
	m := &Evaluation{e: e, ctx: ctx, dir: dir, socket: socket, database: database, duration: 5 * time.Minute}
	m.status = daemon.EvaluationStatus{State: "stopped", Profile: "incoming", DurationSeconds: 300, Cleanup: "not_needed", ReasonCode: "monitoring", Reason: "Monitoring only; no evaluation resources", Readiness: daemon.EvaluationReadiness{State: "not_checked", Checks: []readiness.Check{}}}
	m.status.Review = "For five minutes, current stored rules decide new incoming TCP/UDP; supported unmatched applications prompt, unknown/ambiguous ownership blocks. Existing connections are preserved; outgoing remains allowed. Stop/expiry removes only FlowGate enforcement and does not disconnect already-approved TCP deliberately. Other firewalls can still block. Closing the GUI does not stop or extend the deadline."
	m.status.UnsupportedOutgoing = "Only incoming is supported by this daemon lifecycle, including the bounded Tailscale client profile; combined outgoing evaluation is unavailable."
	m.probe = func() []readiness.Check {
		ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
		defer cancel()
		return readiness.FirewallFor(ctx, readiness.Default(), "incoming", e.AdministratorUID != nil)
	}
	m.runner = func(ctx context.Context, ready func() error) error {
		return queue.RunConfigured(ctx, e, "incoming", Queue, false, ready)
	}
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
	m.mu.Lock()
	if !validNonce(request) {
		m.mu.Unlock()
		return m.Status(), lifecycleError("invalid_request", "fresh 32 lowercase hexadecimal request_id required")
	}
	if request == m.status.RequestID {
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
	if m.status.Cleanup == "unconfirmed" {
		m.mu.Unlock()
		return m.Status(), lifecycleError("unavailable", "Owned resources require scoped recovery before another Start")
	}
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return m.Status(), lifecycleError("unavailable", "Daemon shutting down")
	}
	m.status.ID = decisionlog.NewRecordID()
	m.status.RequestID = request
	m.status.State = "starting"
	m.status.Cleanup = "pending"
	m.status.StopsAt = time.Now().Add(m.duration)
	m.status.ReasonCode = "starting"
	m.status.Reason = "Rechecking preflight, watchdog, queue and owned interception"
	ctx, cancel := context.WithDeadline(m.ctx, m.status.StopsAt)
	m.cancel = cancel
	m.done = make(chan struct{})
	id := m.status.ID
	m.mu.Unlock()
	go m.run(ctx, id)
	return m.Status(), nil
}
func (m *Evaluation) Stop(expected string) (daemon.EvaluationStatus, error) {
	m.mu.Lock()
	if expected == "" || expected != m.status.ID {
		m.mu.Unlock()
		return m.Status(), lifecycleError("evaluation_conflict", "Current evaluation_id required")
	}
	if m.cancel == nil && m.status.Cleanup == "unconfirmed" {
		ctx, cancel := context.WithCancel(m.ctx)
		_ = ctx
		m.cancel = cancel
		m.done = make(chan struct{})
		id := m.status.ID
		m.status.State = "stopping"
		m.status.ReasonCode = "cleanup_retry"
		m.status.Reason = "Retrying cleanup of this exact owned evaluation"
		go func() { err := cleanupEmbedded(m.dir, id); m.finish(err, err == nil) }()
	} else if m.cancel != nil {
		m.status.State = "stopping"
		m.status.ReasonCode = "stop_requested"
		m.status.Reason = "Dropping held packets and removing only owned resources"
		m.cancel()
	}
	m.mu.Unlock()
	return m.Status(), nil
}
func (m *Evaluation) Close() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
func (m *Evaluation) finish(err error, clean bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.status.State = "failed"
		m.status.ReasonCode = "activation_failed"
		m.status.Reason = err.Error()
		var failure *readiness.Failure
		if errors.As(err, &failure) {
			m.status.ReasonCode = failure.Check.Code
		}
	} else {
		m.status.State = "stopped"
		m.status.ReasonCode = "stopped"
		m.status.Reason = "Evaluation ended; FlowGate is not controlling traffic"
		if !time.Now().Before(m.status.StopsAt) {
			m.status.ReasonCode = "expired"
			m.status.Reason = "Original five-minute deadline reached; FlowGate enforcement stopped"
		}
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
func (m *Evaluation) run(ctx context.Context, id string) {
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
	r := Record{Embedded: true, Profile: "incoming", Token: id, PID: os.Getpid(), Start: startID(os.Getpid()), NetNS: identity.NetNS(), State: "starting", StopsAt: s.StopsAt}
	if err = save(m.dir, r); err != nil {
		finish(err, true)
		return
	}
	if err = startEmbeddedWatch(exe, m.dir, id); err != nil {
		r.State = "stopped"
		save(m.dir, r)
		finish(err, true)
		return
	}
	m.e.ResetAdmission()
	m.e.Decisions.SetRecording(true)
	activated := false
	runctx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	auditError := make(chan error, 1)
	err = m.runner(runctx, func() error {
		return evaluationLock(m.dir, func() error {
			if er := ctx.Err(); er != nil {
				return er
			}
			if er := bootstrapContext(ctx, func() error { r.MarksOwned = true; return save(m.dir, r) }); er != nil {
				return er
			}
			if er := ctx.Err(); er != nil {
				return er
			}
			if er := batch(profileRules(id, "incoming")); er != nil {
				return er
			}
			if m.afterInstall != nil {
				if er := m.afterInstall(); er != nil {
					return er
				}
			}
			digest, er := tableDigest()
			if er != nil {
				return er
			}
			r.TableDigest = digest
			r.State = "active"
			if er = save(m.dir, r); er != nil {
				return er
			}
			activated = true
			m.mu.Lock()
			if m.status.State == "starting" {
				m.status.State = "active"
				m.status.ReasonCode = "active"
				m.status.Reason = "Incoming interception verified; independent deadline armed"
			}
			m.mu.Unlock()
			expectedDigest := r.TableDigest
			go func(record Record) {
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
							d, er = tableDigest()
							if er == nil && d != expectedDigest {
								er = fmt.Errorf("owned interception table changed")
							}
						}
						if er != nil {
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
	cleanupErr := cleanupEmbedded(m.dir, id)
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
