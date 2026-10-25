// Package diagnostics provides one-shot, opt-in, private serve profiling.
// Timings are elapsed (including blocking), not CPU; nested stages must not be summed.
package serveprofile

import (
	"math/bits"
	"sync/atomic"
	"time"
)

type Stage uint8

const (
	SocketCensus Stage = iota
	HolderCensus
	ProcessFacts
	FullInspect
	FullResolve
	LinkQuery
	PolicyLockWait
	PolicyLocked
	PolicyEvaluate
	Verdict
	AdmissionWait
	QueueResidence
	WorkerBatch
	stageCount
)

var stageNames = [...]string{"socket_census", "holder_census", "process_facts", "full_inspect", "full_resolve", "link_query", "policy_lock_wait", "policy_locked", "policy_evaluate", "verdict", "admission_wait", "callback_to_worker", "worker_batch"}

type Counter uint8

const (
	Offered Counter = iota
	Parsed
	ParsedUDP
	ParsedTCP
	Admitted
	AdmissionRejected
	WorkerVisits
	CompletedVisits
	VerdictAllow
	VerdictDrop
	VerdictError
	counterCount
)

var counterNames = [...]string{"callback_offered", "parsed", "parsed_udp", "parsed_tcp", "admitted", "admission_rejected", "worker_packet_visits", "completed_packet_visits", "allow_verdicts", "drop_verdicts", "verdict_errors"}

type bucket struct {
	count, nanos atomic.Uint64
	hist         [32]atomic.Uint64
}
type session struct {
	stages      [stageCount]bucket
	counters    [counterCount]atomic.Uint64
	batchSizes  [17]atomic.Uint64
	from, until time.Time
}

var active atomic.Pointer[session]

type Span struct {
	session *session
	stage   Stage
	at      time.Time
}

func Begin(stage Stage) Span {
	s := active.Load()
	if s == nil {
		return Span{}
	}
	return Span{s, stage, time.Now()}
}
func (s Span) End() {
	if s.session == nil || active.Load() != s.session {
		return
	}
	end := time.Now()
	if end.After(s.session.until) {
		return
	}
	record(s.session, s.stage, end.Sub(s.at))
}
func record(s *session, stage Stage, d time.Duration) {
	if stage >= stageCount || d < 0 {
		return
	}
	b := &s.stages[stage]
	n := uint64(d)
	b.count.Add(1)
	b.nanos.Add(n)
	k := bits.Len64(n / 1000)
	if k > 31 {
		k = 31
	}
	b.hist[k].Add(1)
}

// Since records callback-to-worker elapsed time, including admission/coalescing.
// Revisited census jobs appear again; this is not a packet latency denominator.
func Since(stage Stage, at time.Time) {
	s := active.Load()
	if s == nil {
		return
	}
	now := time.Now()
	if at.Before(s.from) || now.After(s.until) {
		return
	}
	record(s, stage, now.Sub(at))
}
func Count(c Counter, n uint64) {
	s := active.Load()
	if s != nil && c < counterCount {
		s.counters[c].Add(n)
	}
}
func Batch(n int) {
	s := active.Load()
	if s != nil && n > 0 && n < len(s.batchSizes) {
		s.batchSizes[n].Add(1)
	}
}
func snapshot(s *session) map[string]any {
	stages := map[string]any{}
	counters := map[string]uint64{}
	for i, n := range stageNames {
		b := &s.stages[i]
		h := [32]uint64{}
		for k := range h {
			h[k] = b.hist[k].Load()
		}
		stages[n] = map[string]any{"completed_calls": b.count.Load(), "elapsed_ns": b.nanos.Load(), "log2_us_histogram": h}
	}
	for i, n := range counterNames {
		counters[n] = s.counters[i].Load()
	}
	sizes := [17]uint64{}
	for i := range sizes {
		sizes[i] = s.batchSizes[i].Load()
	}
	return map[string]any{"elapsed_stages": stages, "counters": counters, "worker_batch_sizes": sizes}
}
