// Package diagnostics provides one-shot, opt-in, private serve profiling.
// Timings are elapsed (including blocking), not CPU; nested stages must not be summed.
package serveprofile

import (
	"bytes"
	"encoding/json"
	"math/bits"
	"sync"
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
	CensusService
	CensusWait
	CensusResidence
	WineSlotWait
	WineSessionWait
	WineLockWait
	WineRuntimeQuery
	WineHelperValidation
	WineImageValidation
	WineFinalValidation
	stageCount
)

var stageNames = [...]string{"socket_census", "holder_census", "process_facts", "full_inspect", "full_resolve", "link_query", "policy_lock_wait", "policy_locked", "policy_evaluate", "verdict", "admission_wait", "callback_to_worker", "worker_batch", "census_service", "census_lane_wait", "callback_to_census_worker", "wine_slot_wait", "wine_session_setup_wait", "wine_lock_wait", "wine_runtime_query", "wine_helper_validation", "wine_image_validation", "wine_final_validation"}

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
	WineHintHit
	WineHintFallback
	HolderRetry
	WineBusy
	counterCount
)

var counterNames = [...]string{"callback_offered", "parsed", "parsed_udp", "parsed_tcp", "admitted", "admission_rejected", "worker_packet_visits", "completed_packet_visits", "allow_verdicts", "drop_verdicts", "verdict_errors", "wine_hint_hit", "wine_hint_fresh_fallback", "holder_second_attempt", "wine_hint_busy"}

type bucket struct {
	count, nanos atomic.Uint64
	hist         [32]atomic.Uint64
}
type session struct {
	stages              [stageCount]bucket
	counters            [counterCount]atomic.Uint64
	batchSizes          [17]atomic.Uint64
	from, until         time.Time
	evidenceMu          sync.Mutex
	evidence            []json.RawMessage
	evidenceSkipped     uint64
	lastSuccess         time.Time
	failures, successes int
	queueEvents         int
	quotas              map[string]int
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
	s.evidenceMu.Lock()
	defer s.evidenceMu.Unlock()
	return map[string]any{"elapsed_stages": stages, "counters": counters, "worker_batch_sizes": sizes, "evidence": s.evidence, "evidence_skipped": s.evidenceSkipped}
}

// Evidence captures at most 32 refusals and 64 successes (at most one success
// per second), each at most 16KiB, only during explicit profiling. No hot-path
// file IO and no payloads; callers provide bounded projections, not full /proc.
func Evidence(failed bool, build func() any)                { EvidenceKey(failed, "", build) }
func EvidenceKey(failed bool, key string, build func() any) { evidenceKey(failed, key, build, false) }
func QueueEvidence(key string, build func() any)            { evidenceKey(true, key, build, true) }
func evidenceKey(failed bool, key string, build func() any, queue bool) {
	s := active.Load()
	if s == nil {
		return
	}
	now := time.Now()
	if now.After(s.until) {
		return
	}
	s.evidenceMu.Lock()
	defer s.evidenceMu.Unlock()
	if key != "" && (len(key) > 512 || s.quotas[key] >= 4) {
		s.evidenceSkipped++
		return
	}
	if key != "" {
		if s.quotas == nil {
			s.quotas = map[string]int{}
		}
		if _, ok := s.quotas[key]; !ok && len(s.quotas) >= 112 {
			s.evidenceSkipped++
			return
		}
	}
	if queue && s.queueEvents >= 16 || !queue && (failed && s.failures >= 32 || !failed && (s.successes >= 64 || now.Sub(s.lastSuccess) < time.Second)) {
		s.evidenceSkipped++
		return
	}
	if key != "" {
		s.quotas[key]++
	}
	if queue {
		s.queueEvents++
	} else if failed {
		s.failures++
	} else {
		s.successes++
		s.lastSuccess = now
	}
	var b bytes.Buffer
	w := &cappedWriter{dst: &b, left: 16 << 10}
	if json.NewEncoder(w).Encode(build()) != nil {
		s.evidenceSkipped++
		return
	}
	s.evidence = append(s.evidence, append(json.RawMessage(nil), b.Bytes()...))
}

func ObservationTime() time.Time {
	if active.Load() == nil {
		return time.Time{}
	}
	return time.Now()
}
