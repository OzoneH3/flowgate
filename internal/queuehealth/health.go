// Package queuehealth records bounded diagnostic facts, never policy authority.
package queuehealth

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

const Capability = "queue-health-v1"
const RecentWindow = 30 * time.Second
const MaxSessions = 8
const recentBuckets = int(RecentWindow/time.Second) + 1

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
	// VerdictWriteRetry counts identical verdicts re-sent after a netlink
	// write deadline expired before delivery; the packet stayed queued.
	VerdictWriteRetry
	// VerdictTargetGone counts stale verdict error ACKs, not approved packets.
	VerdictTargetGone
	causeCount
)

var names = [...]string{"attribution_capacity_rejections", "census_capacity_rejections", "fairness_displacement_rejections", "deadline_rejections", "shutdown_rejections", "retention_capacity_rejections", "retained_deadline_rejections", "retained_shutdown_rejections", "parse_rejections", "missing_payload_rejections", "netlink_overflow_notifications", "receive_failures", "verdict_failures", "self_tracking_failures", "verdict_write_retries", "verdict_target_gone"}

type Gauges struct {
	FirstProofAdmissions       string `json:"first_proof_admissions,omitempty"`
	FirstProofDisplacements    string `json:"first_proof_denied_tails_reclaimed,omitempty"`
	FirstProofHistory          int    `json:"first_proof_history_rows,omitempty"`
	FirstProofHistoryEvictions string `json:"first_proof_history_evictions,omitempty"`
	FirstProofHistoryFull      string `json:"first_proof_history_full_observations,omitempty"`
	AttributionPackets         int    `json:"attribution_packets"`
	AttributionBytes           int    `json:"attribution_bytes"`
	CensusPackets              int    `json:"census_packets"`
	CensusBytes                int    `json:"census_bytes"`
	ActiveWorkers              int    `json:"active_workers"`
	RetainedPackets            int    `json:"retained_packets"`
	RetainedBytes              int    `json:"retained_bytes"`
}
type View struct {
	Generation        string            `json:"generation"`
	Queue             uint16            `json:"queue"`
	Direction         string            `json:"direction"`
	StartedAt         time.Time         `json:"started_at"`
	StoppedAt         *time.Time        `json:"stopped_at,omitempty"`
	LastIssueAt       *time.Time        `json:"last_issue_at,omitempty"`
	Counters          map[string]string `json:"counters"`
	RecentCounters    map[string]string `json:"recent_counters"`
	LastAdmissionMask *int              `json:"last_admission_mask,omitempty"`
	Saturated         bool              `json:"saturated"`
	Gauges            Gauges            `json:"gauges"`
}
type Snapshot struct {
	CounterUnits map[string]string `json:"counter_units,omitempty"`
	State        string            `json:"state"` // inactive, ready, pressure; readiness is not delivery proof
	SampledAt    time.Time         `json:"sampled_at"`
	Sessions     []View            `json:"sessions,omitempty"` // machine detail: administrator only
}
type recentBucket struct {
	second int64
	counts [causeCount]uint64
}

type Session struct {
	generation        string
	queue             uint16
	direction         string
	started           time.Time
	mu                sync.Mutex
	counters          [causeCount]uint64
	recent            [recentBuckets]recentBucket
	saturated         bool
	last              time.Time
	lastAdmissionMask int
	stopped           *time.Time
	gauges            func() Gauges
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
	s := &Session{generation: hex.EncodeToString(id[:]), queue: queue, direction: direction, started: time.Now()}
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
	s.add(c, -1, time.Time{})
}

// RejectAdmission records the limits observed by the scheduler on the last
// failed admission attempt. Several limit bits may be set for one rejection.
func (s *Session) RejectAdmission(mask uint8) {
	s.add(AttributionCapacity, int(mask), time.Time{})
}

func (s *Session) add(c Cause, mask int, now time.Time) {
	if s == nil || c >= causeCount {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counters[c] != ^uint64(0) {
		s.counters[c]++
	}
	s.saturated = s.saturated || s.counters[c] == ^uint64(0)
	if c == Shutdown || c == RetainedShutdown {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.last = now
	sec := int64(now.Sub(s.started) / time.Second)
	b := &s.recent[sec%int64(recentBuckets)]
	if b.second != sec {
		*b = recentBucket{second: sec}
	}
	if b.counts[c] != ^uint64(0) {
		b.counts[c]++
	}
	if c == AttributionCapacity {
		s.lastAdmissionMask = mask
	}
}
func (r *Registry) Snapshot(admin bool) Snapshot { return r.snapshot(time.Now(), admin) }
func (r *Registry) snapshot(now time.Time, admin bool) Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Snapshot{State: "inactive", SampledAt: now.UTC()}
	for _, s := range r.sessions {
		s.mu.Lock()
		stopped := s.stopped
		gauge := s.gauges
		last := s.last
		if stopped == nil {
			if out.State == "inactive" {
				out.State = "ready"
			}
			if !last.IsZero() && now.Sub(last) <= RecentWindow {
				out.State = "pressure"
			}
		}
		if !admin {
			s.mu.Unlock()
			continue
		}
		counters := s.counters
		var recent [causeCount]uint64
		sec := int64(now.Sub(s.started) / time.Second)
		for _, b := range s.recent {
			if b.second > sec || sec-b.second >= int64(recentBuckets) {
				continue
			}
			for c, n := range b.counts {
				recent[c] += min(n, ^uint64(0)-recent[c])
			}
		}
		saturated, mask := s.saturated, s.lastAdmissionMask
		s.mu.Unlock()
		v := View{Generation: s.generation, Queue: s.queue, Direction: s.direction, StartedAt: s.started.UTC(), StoppedAt: stopped,
			Counters: make(map[string]string), RecentCounters: make(map[string]string), Saturated: saturated}
		if !last.IsZero() {
			t := last.UTC()
			v.LastIssueAt = &t
		}
		for c := Cause(0); c < causeCount; c++ {
			v.Counters[names[c]] = strconv.FormatUint(counters[c], 10)
			if recent[c] != 0 {
				v.RecentCounters[names[c]] = strconv.FormatUint(recent[c], 10)
			}
		}
		if recent[AttributionCapacity] != 0 && mask >= 0 {
			v.LastAdmissionMask = &mask
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
