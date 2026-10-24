// Package queuehealth records bounded diagnostic facts, never policy authority.
package queuehealth

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const Capability = "queue-health-v1"
const RecentWindow = 30 * time.Second
const MaxSessions = 8

type Cause uint8

const (
	AttributionCapacity Cause = iota
	CensusCapacity
	FairnessDisplacement
	Deadline
	Shutdown
	RetentionCapacity
	RetainedDeadline
	RetainedShutdown
	ParseRejected
	PayloadMissing
	NetlinkOverflow
	ReceiveFailure
	VerdictFailure
	SelfTrackingFailure
	causeCount
)

var names = [...]string{"attribution_capacity_rejections", "census_capacity_rejections", "fairness_displacement_rejections", "deadline_rejections", "shutdown_rejections", "retention_capacity_rejections", "retained_deadline_rejections", "retained_shutdown_rejections", "parse_rejections", "missing_payload_rejections", "netlink_overflow_notifications", "receive_failures", "verdict_failures", "self_tracking_failures"}

type Gauges struct {
	AttributionPackets int `json:"attribution_packets"`
	AttributionBytes   int `json:"attribution_bytes"`
	CensusPackets      int `json:"census_packets"`
	CensusBytes        int `json:"census_bytes"`
	ActiveWorkers      int `json:"active_workers"`
	RetainedPackets    int `json:"retained_packets"`
	RetainedBytes      int `json:"retained_bytes"`
}
type View struct {
	Generation  string            `json:"generation"`
	Queue       uint16            `json:"queue"`
	Direction   string            `json:"direction"`
	StartedAt   time.Time         `json:"started_at"`
	StoppedAt   *time.Time        `json:"stopped_at,omitempty"`
	LastIssueAt *time.Time        `json:"last_issue_at,omitempty"`
	Counters    map[string]string `json:"counters"`
	Saturated   bool              `json:"saturated"`
	Gauges      Gauges            `json:"gauges"`
}
type Snapshot struct {
	CounterUnits map[string]string `json:"counter_units,omitempty"`
	State        string            `json:"state"` // inactive, ready, pressure; readiness is not delivery proof
	SampledAt    time.Time         `json:"sampled_at"`
	Sessions     []View            `json:"sessions,omitempty"` // machine detail: administrator only
}
type Session struct {
	generation string
	queue      uint16
	direction  string
	started    time.Time
	counters   [causeCount]atomic.Uint64
	saturated  atomic.Bool
	last       atomic.Int64
	mu         sync.Mutex
	stopped    *time.Time
	gauges     func() Gauges
}
type Registry struct {
	mu          sync.Mutex
	sessions    []*Session
	unavailable bool
}

// Start is per queue binding, including reactivations within one daemon generation.
// Active entries are never evicted; the oldest ended entry is discarded first.
// Refusing an extra diagnostic session must not alter enforcement behavior.
func (r *Registry) Start(queue uint16, direction string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sessions) >= MaxSessions {
		found := -1
		for i, s := range r.sessions {
			s.mu.Lock()
			ended := s.stopped != nil
			s.mu.Unlock()
			if ended {
				found = i
				break
			}
		}
		if found < 0 {
			r.unavailable = true
			return nil
		}
		r.sessions = append(r.sessions[:found], r.sessions[found+1:]...)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		r.unavailable = true
		return nil
	}
	s := &Session{generation: hex.EncodeToString(id[:]), queue: queue, direction: direction, started: time.Now().UTC()}
	r.sessions = append(r.sessions, s)
	return s
}
func (s *Session) GaugeSource(f func() Gauges) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.gauges = f
	s.mu.Unlock()
}
func (s *Session) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped == nil {
		now := time.Now().UTC()
		s.stopped = &now
	}
	s.gauges = nil
}

// Add counts one observed operation/notification or rejected packet attempt.
// Rejections are not proof that a kernel verdict was successfully delivered.
func (s *Session) Add(c Cause) {
	if s == nil || c >= causeCount {
		return
	}
	a := &s.counters[c]
	for {
		v := a.Load()
		if v == ^uint64(0) {
			s.saturated.Store(true)
			break
		}
		if a.CompareAndSwap(v, v+1) {
			if v+1 == ^uint64(0) {
				s.saturated.Store(true)
			}
			break
		}
	}
	if c != Shutdown && c != RetainedShutdown {
		s.last.Store(time.Now().UnixNano())
	}
}
func (r *Registry) Snapshot(admin bool) Snapshot { return r.snapshot(time.Now().UTC(), admin) }
func (r *Registry) snapshot(now time.Time, admin bool) Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Snapshot{State: "inactive", SampledAt: now}
	for _, s := range r.sessions {
		s.mu.Lock()
		stopped := s.stopped
		gauge := s.gauges
		s.mu.Unlock()
		last := s.last.Load()
		if stopped == nil {
			if out.State == "inactive" {
				out.State = "ready"
			}
			if last != 0 && now.Sub(time.Unix(0, last)) <= RecentWindow {
				out.State = "pressure"
			}
		}
		if !admin {
			continue
		}
		v := View{Generation: s.generation, Queue: s.queue, Direction: s.direction, StartedAt: s.started, StoppedAt: stopped, Counters: make(map[string]string), Saturated: s.saturated.Load()}
		if last != 0 {
			t := time.Unix(0, last).UTC()
			v.LastIssueAt = &t
		}
		for c := Cause(0); c < causeCount; c++ {
			v.Counters[names[c]] = strconv.FormatUint(s.counters[c].Load(), 10)
		}
		if gauge != nil {
			v.Gauges = gauge()
		}
		out.Sessions = append(out.Sessions, v)
	}
	if r.unavailable {
		out.State = "unavailable"
	}
	if admin {
		out.CounterUnits = make(map[string]string)
		for c := Cause(0); c < causeCount; c++ {
			unit := "packets"
			if c == NetlinkOverflow {
				unit = "notifications"
			} else if c >= ReceiveFailure {
				unit = "operations"
			}
			out.CounterUnits[names[c]] = unit
		}
	}
	return out
}
