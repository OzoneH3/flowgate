package queue

import (
	"flowgate/internal/daemon"
	"time"
)

const MaxFirstProofPackets = 32
const MaxFirstProofBytes = 256 << 10
const MaxFirstProofFlows = 1024

type firstProofDecision struct {
	complete, everAllowed, denied bool
	until                         time.Time
}
type firstProofCounters struct{ Admitted, Displaced uint64 }

func (w *packetWorkers) enableFirstProofHolding(epoch func() uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.firstHolding = true
	w.policyEpoch = epoch
	w.firstSeen = map[string]firstProofDecision{}
	if epoch != nil {
		w.seenEpoch = epoch()
	}
}
func (w *packetWorkers) syncFirstEpochLocked() {
	if w.policyEpoch != nil {
		if epoch := w.policyEpoch(); epoch != w.seenEpoch {
			w.seenEpoch = epoch
			w.firstSeen = map[string]firstProofDecision{}
			w.nextFirstPrune = time.Time{}
		}
	}
}
func (w *packetWorkers) firstEligibleLocked(p packetJob) bool {
	if !w.firstHolding || p.flow.Protocol != "udp" || p.flow.Direction != "outgoing" || !p.flow.Local.Addr().Is4() || !p.flow.Remote.Addr().Is4() {
		return false
	}
	w.syncFirstEpochLocked()
	w.pruneFirstLocked(time.Now())
	seen, ok := w.firstSeen[p.flow.Key()]
	if ok {
		return !seen.complete
	}
	if len(w.firstSeen) < MaxFirstProofFlows || w.oldestCompletedLocked() != "" {
		return true
	}
	w.firstFull++
	return false
}
func (w *packetWorkers) endpointFullForLocked(p packetJob) bool {
	if !w.firstEligibleLocked(p) {
		return w.endpointFullLocked(p.key(), p.size)
	}
	count, bytes := 0, 0
	for _, j := range w.jobs[p.key()] {
		if j.flow == p.flow {
			count++
			bytes += j.size
		}
	}
	return count >= MaxFirstProofPackets || p.size > MaxFirstProofBytes-bytes
}

// Only the initial-proof subset can borrow from the general headroom. All
// packets remain charged to the unchanged global48/1MiB. Repeat census traffic
// cannot consume those16 extra slots; active heads are never reclaimed.
func (w *packetWorkers) censusRoomLocked(p packetJob) bool {
	if w.firstEligibleLocked(p) {
		return true
	}
	return w.queueCensusRoomLocked([]packetJob{p})
}
func (w *packetWorkers) queueCensusRoomLocked(incoming []packetJob) bool {
	count, bytes := 0, 0
	for k, q := range w.jobs {
		if !w.census[k] {
			continue
		}
		for _, j := range q {
			if !j.firstProof {
				count++
				bytes += j.size
			}
		}
	}
	for _, j := range incoming {
		if !j.firstProof {
			count++
			bytes += j.size
		}
	}
	return count <= MaxCensusPackets && bytes <= MaxCensusBytes
}
func (w *packetWorkers) noteInitialDecision(v daemon.Event, allowed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.firstHolding || v.Flow.Protocol != "udp" || v.Flow.Direction != "outgoing" || !v.Flow.Local.Addr().Is4() || !v.Flow.Remote.Addr().Is4() {
		return
	}
	w.syncFirstEpochLocked()
	epoch, until := v.QueueSchedulingHint()
	if epoch != w.seenEpoch {
		return
	}
	key := v.Flow.Key()
	s, ok := w.firstSeen[key]
	if !ok && !w.makeFirstRoomLocked() {
		return
	}
	s.complete = true
	s.everAllowed = s.everAllowed || allowed
	s.denied = v.State == "blocked" && !allowed
	s.until = time.Now().Add(30 * time.Second)
	if !until.IsZero() && until.Before(s.until) {
		s.until = until
	}
	w.firstSeen[key] = s
	// Already held initial packets drain normally. They cannot acquire additional
	// startup credit after the first decision. The prompt retainer is untouched.
}
func (w *packetWorkers) displaceDeniedTailLocked(p packetJob, incomingKey string) *packetJob {
	if w.reject == nil || w.displacing {
		return nil
	}
	w.syncFirstEpochLocked()
	needed := p.size - (MaxAttributionBytes - w.bytes)
	for key, q := range w.jobs {
		if key == incomingKey || len(q) == 0 || w.active[key] && len(q) <= max(1, w.activeBatch[key]) {
			continue
		}
		victim := q[len(q)-1]
		s, ok := w.firstSeen[victim.flow.Key()]
		if !ok || !s.complete || s.everAllowed || !s.denied || !time.Now().Before(s.until) || victim.size < needed {
			continue
		}
		if w.census[key] {
			w.censusCount--
			w.censusBytes -= victim.size
		}
		w.count--
		w.bytes -= victim.size
		if len(q) > 1 {
			w.jobs[key] = q[:len(q)-1]
		} else {
			delete(w.jobs, key)
			delete(w.census, key)
			for lane := range w.ready {
				for i, k := range w.ready[lane] {
					if k == key {
						w.ready[lane] = append(w.ready[lane][:i], w.ready[lane][i+1:]...)
						break
					}
				}
			}
		}
		w.firstDisplacements++
		return &victim
	}
	return nil
}
func (w *packetWorkers) firstProofStats() firstProofCounters {
	w.mu.Lock()
	defer w.mu.Unlock()
	return firstProofCounters{w.firstAdmissions, w.firstDisplacements}
}

// Completed metadata is not a permanent per-session flow registry. Active first
// attempts keep their slot until their unchanged packet deadline; completed
// records are LRU-evictable and expire within30s. An evicted/rebound flow can be
// treated as new for scheduling only, never for permission.
func (w *packetWorkers) pruneFirstLocked(now time.Time) {
	if now.Before(w.nextFirstPrune) {
		return
	}
	for key, s := range w.firstSeen {
		if !now.Before(s.until) {
			delete(w.firstSeen, key)
		}
	}
	w.nextFirstPrune = now.Add(time.Second)
}
func (w *packetWorkers) oldestCompletedLocked() string {
	key := ""
	var at time.Time
	for k, s := range w.firstSeen {
		if s.complete && (key == "" || s.until.Before(at)) {
			key = k
			at = s.until
		}
	}
	return key
}
func (w *packetWorkers) makeFirstRoomLocked() bool {
	w.pruneFirstLocked(time.Now())
	if len(w.firstSeen) < MaxFirstProofFlows {
		return true
	}
	if key := w.oldestCompletedLocked(); key != "" {
		delete(w.firstSeen, key)
		w.firstEvictions++
		return true
	}
	w.firstFull++
	return false
}
