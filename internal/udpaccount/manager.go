package udpaccount

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Manager belongs to the existing Go daemon. It owns one optional native helper,
// no second Unix server/Go process, no queue/firewall and no automatic Start.
type Status struct {
	TracingSkipped *uint64   `json:"tracing_skipped_runs,omitempty"`
	State          string    `json:"state"`
	Available      bool      `json:"available"` // static prerequisite checks only, not load success
	ReasonCode     string    `json:"reason_code"`
	Reason         string    `json:"reason"`
	Generation     string    `json:"generation,omitempty"`
	NetNS          string    `json:"netns"`
	Scope          string    `json:"scope"`
	Partial        bool      `json:"partial"`
	FinalsLost     uint64    `json:"final_snapshots_lost,omitempty"`
	Missed         uint64    `json:"missed_operations"`
	Collected      time.Time `json:"collected,omitempty"`
}
type Manager struct {
	mu       sync.Mutex
	status   Status
	pinned   string
	run      *session
	cancel   context.CancelFunc
	done     chan struct{}
	closed   bool
	attempts []time.Time
	launch   func(context.Context, string, uint32, bool) (*session, error)
}

func NewManager(helper, pinDir string) *Manager {
	m := &Manager{launch: startSession, status: Status{State: "disabled", NetNS: identity.NetNS(), Scope: "machine", ReasonCode: "disabled", Reason: "Explicit Start required; no collector attached"}}
	check := readiness.MachineHelper(helper)
	if check.Status == readiness.Ready {
		check = readiness.BTFNames("/sys/kernel/btf/vmlinux")
	}
	if check.Status != readiness.Ready {
		m.status.ReasonCode = check.Code
		m.status.Reason = check.Detail
		return m
	}
	source, err := os.Open(helper)
	if err != nil {
		m.status.ReasonCode = "helper_missing"
		m.status.Reason = err.Error()
		return m
	}
	defer source.Close()
	pinned, err := os.CreateTemp(pinDir, ".flowgate-udp-")
	if err != nil {
		m.status.ReasonCode = "helper_pin_failed"
		m.status.Reason = err.Error()
		return m
	}
	cleanup := func(err error) {
		pinned.Close()
		os.Remove(pinned.Name())
		m.status.ReasonCode = "helper_pin_failed"
		m.status.Reason = err.Error()
	}
	n, err := io.Copy(pinned, io.LimitReader(source, 32*1024*1024+1))
	if err != nil || n > 32*1024*1024 {
		cleanup(fmt.Errorf("helper copy failed/oversized"))
		return m
	}
	if err = pinned.Chmod(0700); err != nil {
		cleanup(err)
		return m
	}
	if err = pinned.Close(); err != nil {
		cleanup(err)
		return m
	}
	if check = readiness.MachineHelper(pinned.Name()); check.Status != readiness.Ready {
		cleanup(fmt.Errorf("pinned helper incompatible: %s", check.Detail))
		return m
	}
	m.pinned = pinned.Name()
	m.status.Available = true
	return m
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.status
	if m.run != nil && out.State == "active" {
		s := m.run.snapshot()
		out.Collected = s.Collected
		out.Missed = s.Missed
		out.TracingSkipped = s.TracingSkipped
		out.Partial = s.Missed > 0 || s.FinalsLost > 0 || s.TracingGapReason() != ""
		out.FinalsLost = s.FinalsLost
		out.Reason = s.Reason
		if time.Since(s.Collected) > 4*time.Second {
			out.Partial = true
			out.Reason = "UDP sample overdue; measurements unavailable"
		}
	}
	return out
}

var ErrCollectorGeneration = errors.New("collector generation changed; refresh before lifecycle operation")

func (m *Manager) Start(expected ...string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(expected) > 0 && expected[0] != m.status.Generation {
		return m.status, ErrCollectorGeneration
	}
	if m.closed {
		return m.status, fmt.Errorf("collector owner is shutting down")
	}
	if m.status.State == "starting" || m.status.State == "active" {
		return m.status, nil
	}
	if m.status.State == "stopping" {
		return m.status, fmt.Errorf("collector is stopping; wait for disabled")
	}
	if !m.status.Available {
		return m.status, fmt.Errorf("%s: %s", m.status.ReasonCode, m.status.Reason)
	}
	now := time.Now()
	kept := m.attempts[:0]
	for _, at := range m.attempts {
		if now.Sub(at) < time.Minute {
			kept = append(kept, at)
		}
	}
	m.attempts = kept
	if len(m.attempts) >= 3 {
		return m.status, fmt.Errorf("collector retry limit: at most three starts per minute")
	}
	m.attempts = append(m.attempts, now)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	m.status.State = "starting"
	m.status.ReasonCode = "starting"
	m.status.Reason = "Awaiting actual BPF load/attach and first sample"
	m.status.Generation = generation()
	go func() {
		run, err := m.launch(ctx, m.pinned, 0, true)
		if err == nil {
			m.mu.Lock()
			m.run = run
			// Expose active only after an actual sample, never on process creation alone.
			m.mu.Unlock()
			for ctx.Err() == nil {
				snapshot := run.snapshot()
				if snapshot.State == "active" {
					m.mu.Lock()
					if m.status.State != "stopping" {
						m.status.State = "active"
						m.status.ReasonCode = "active"
						m.status.Reason = snapshot.Reason
					}
					m.mu.Unlock()
					break
				}
				select {
				case <-ctx.Done():
				case <-run.done:
					err = run.failure()
					if err == nil {
						err = fmt.Errorf("helper exited before first sample")
					}
				case <-time.After(20 * time.Millisecond):
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				select {
				case <-ctx.Done():
				case <-run.done:
					err = run.failure()
					if err == nil {
						err = fmt.Errorf("helper exited")
					}
				}
			}
			run.close()
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.run = nil
		m.cancel = nil
		if ctx.Err() != nil {
			m.status.State = "disabled"
			m.status.ReasonCode = "disabled"
			m.status.Reason = "Explicit Stop/shutdown; TCP and policy unaffected"
		} else {
			m.status.State = "failed"
			m.status.ReasonCode = "bpf_load_failed"
			if err != nil {
				m.status.Reason = err.Error()
			}
			if errors.Is(err, os.ErrPermission) || (err != nil && strings.Contains(err.Error(), "collector_inspection_denied:")) {
				m.status.ReasonCode = "permission_required"
			} else if err != nil && strings.Contains(err.Error(), "collector_conflict:") {
				m.status.ReasonCode = "collector_conflict"
			}
		}
		close(done)
	}()
	return m.status, nil
}
func (m *Manager) Stop(expected ...string) (Status, error) {
	m.mu.Lock()
	if len(expected) > 0 && expected[0] != m.status.Generation {
		s := m.status
		m.mu.Unlock()
		return s, ErrCollectorGeneration
	}
	if m.cancel == nil {
		s := m.status
		if s.State != "disabled" {
			m.status.State = "disabled"
			m.status.ReasonCode = "disabled"
			m.status.Reason = "Stopped; no owned helper"
			s = m.status
		}
		m.mu.Unlock()
		return s, nil
	}
	m.status.State = "stopping"
	m.status.ReasonCode = "stopping"
	m.status.Reason = "Closing only owned helper links/maps"
	m.cancel()
	done := m.done
	m.mu.Unlock()
	select {
	case <-done:
		return m.Status(), nil
	case <-time.After(2 * time.Second):
		return m.Status(), fmt.Errorf("collector stop pending; no replacement started")
	}
}
func (m *Manager) Snapshot() identity.UDPSnapshot { return m.snapshot(false) }

// AccountingSnapshot is reserved for the single observer, not API reads.
func (m *Manager) AccountingSnapshot() identity.UDPSnapshot { return m.snapshot(true) }
func (m *Manager) snapshot(consume bool) identity.UDPSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.State == "active" && m.run != nil {
		var s identity.UDPSnapshot
		if consume {
			s = m.run.accountingSnapshot()
		} else {
			s = m.run.snapshot()
		}
		if time.Since(s.Collected) <= 4*time.Second {
			s.Generation = m.status.Generation
			return s
		}
	}
	state := "unavailable"
	if m.status.State == "starting" {
		state = "warming-up"
	}
	return identity.UDPSnapshot{Version: 1, Machine: true, NetNS: m.status.NetNS, Generation: m.status.Generation, State: state, Reason: m.status.State + ": " + m.status.Reason}
}
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	m.Stop()
	m.mu.Lock()
	done := m.done
	pinned := m.pinned
	m.mu.Unlock()
	if done != nil {
		<-done
	}
	if pinned != "" {
		os.Remove(pinned)
	}
}
