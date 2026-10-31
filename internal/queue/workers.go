package queue

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/queuehealth"
	diagnostics "flowgate/internal/serveprofile"
	"fmt"
	"sync"
	"time"
)

// Together with MaxRetainedPackets these leave room in the 128-packet kernel
// queue for callback processing. Attribution owns no packet payload copies.
const MaxAttributionPackets = 48
const MaxAttributionBytes = 1 << 20
const MaxAttributionPerEndpoint = 16

// SharedAttributionReserve is the reclaimable part of MaxAttributionPackets.
// Idle slots may be borrowed by packets behind an in-flight batch; an endpoint
// within its base allowance can reclaim a borrowed tail before displacing base
// work, including from a recently progressing endpoint. Waiting packets,
// not the frozen active batch, count toward MaxAttributionPerEndpoint, so a busy
// endpoint can prepare its next batch while one resolves; that second batch only
// uses the unchanged global capacity. Active batches are never reclaimed.
const SharedAttributionReserve = MaxAttributionPerEndpoint

// SharedAttributionByteReserve is the matching share of MaxAttributionBytes
// that packets queued behind an endpoint's own active batch may not use.
const SharedAttributionByteReserve = MaxAttributionBytes * SharedAttributionReserve / MaxAttributionPackets
const AttributionWorkers = 8
const CensusWorkers = 2
const MaxCensusPackets = 32
const MaxCensusBytes = 1 << 19
const AttributionTimeout = 5 * time.Second
const AdmissionWait = 250 * time.Millisecond
const EndpointBurstWait = 2 * time.Millisecond
const endpointStallWindow = 100 * time.Millisecond
const endpointStallBudget = 10 * time.Millisecond
const recentCompletionWindow = time.Second
const MaxRecentPreferredTurns = 2

// Collect a small burst before obtaining fresh evidence. No packet arriving
// after the batch is frozen may use that observation. Bounds/deadlines stay fixed.
const udpCoalesceWindow = 250 * time.Microsecond

type packetJob struct {
	id            uint32
	size          int
	flow          identity.Flow
	token         string
	deadline      time.Time
	censusEntered time.Time
	firstProof    bool
}

// The scheduling key is deliberately broader than a flow: all remotes on the
// same local endpoint run serially. It is ordering only, never identity evidence.
func (p packetJob) key() string {
	return fmt.Sprintf("%s|%s|%s|%s", p.flow.NetNS, p.flow.Direction, p.flow.Protocol, p.flow.Local)
}

type rejectionCause uint8

const (
	rejectCensus rejectionCause = iota
	rejectShutdown
	rejectAdmission
)

type packetWorkers struct {
	firstHolding                        bool
	firstSeen                           map[string]firstProofDecision
	policyEpoch                         func() uint64
	seenEpoch                           uint64
	firstAdmissions, firstDisplacements uint64
	firstEvictions, firstFull           uint64
	nextFirstPrune                      time.Time
	firstPreferredTurns                 int
	diagnosticActive                    map[string]time.Time
	coalesceWindow                      time.Duration // constructor default; zero disables in benchmarks/tests
	mu                                  sync.Mutex
	wake                                [2]*sync.Cond
	jobs                                map[string][]packetJob // includes active jobs, even across lane transfer
	activeBatch                         map[string]int
	active                              map[string]bool      // heads currently owned by workers cannot be displaced
	recent                              map[string]time.Time // bounded scheduling hints, never ownership/policy evidence
	recentPreferredTurns                int                  // bounded overtaking of the oldest general endpoint
	census                              map[string]bool      // ordering only; never permission authority
	ready                               [2][]string
	count, bytes                        int
	censusCount, censusBytes            int
	burstWindow                         time.Time
	burstSpent                          time.Duration
	stopped                             bool
	capacity                            chan struct{}
	stopping                            chan struct{}
	displacing                          bool // at most one callback-owned displaced packet at a time
	wg                                  sync.WaitGroup
	processBatch                        func([]packetJob, bool, bool) bool
	process                             func(packetJob, bool, bool) bool // true = completed, false = needs census
	reject                              func(packetJob, rejectionCause)  // lane overflow or shutdown, exactly one drop
	admissionRejected                   func(uint8)                      // last observed limit mask, diagnostics only
}

// Single-lane adapter used by ordering/bounds tests.
func newPacketWorkers(n int, process func(packetJob, bool)) *packetWorkers {
	return newPacketLanes(n, 0, func(p packetJob, stop, census bool) bool { process(p, stop); return true }, nil)
}

func newPacketLanes(general, census int, process func(packetJob, bool, bool) bool, reject func(packetJob, rejectionCause)) *packetWorkers {
	return newPacketBatchLanes(general, census, process, nil, reject)
}

func newPacketBatchLanes(general, census int, process func(packetJob, bool, bool) bool, batch func([]packetJob, bool, bool) bool, reject func(packetJob, rejectionCause)) *packetWorkers {
	w := &packetWorkers{coalesceWindow: udpCoalesceWindow, jobs: make(map[string][]packetJob), census: make(map[string]bool), active: make(map[string]bool), activeBatch: make(map[string]int), recent: make(map[string]time.Time), capacity: make(chan struct{}, 1), stopping: make(chan struct{}), process: process, processBatch: batch, reject: reject}
	for lane, n := range []int{general, census} {
		w.wake[lane] = sync.NewCond(&w.mu)
		for i := 0; i < n; i++ {
			w.wg.Add(1)
			go w.run(lane)
		}
	}
	return w
}

// submitWait is used only by the single NFQUEUE receive callback. On a short
// burst, leave subsequent packets in bounded kernel/netlink buffers while workers
// make room, instead of immediately dropping this connection's SYN. This owns
// just the callback's existing packet; it creates no goroutines or extra queue.
// Never renew the packet's attribution deadline, and bound head-of-line delay.
func (w *packetWorkers) submitWait(ctx context.Context, p packetJob) (admitted bool) {
	defer diagnostics.Begin(diagnostics.AdmissionWait).End()
	var mask uint8
	defer func() {
		if !admitted && w.admissionRejected != nil {
			w.admissionRejected(mask)
		}
	}()
	started := time.Now()
	until := started.Add(AdmissionWait)
	if p.deadline.Before(until) {
		until = p.deadline
	}
	if p.size < 0 || p.size > MaxAttributionBytes {
		return false
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	for {
		if ctx.Err() != nil || !time.Now().Before(until) {
			return false
		}
		if w.submit(p) {
			return true
		}
		w.mu.Lock()
		key := p.key()
		// An active or recently progressing general endpoint may absorb a short burst,
		// but never use the much longer global-pressure wait for its own cap.
		// This is scheduling only: every admitted packet still gets a fresh
		// attribution/policy check. Global count/byte bounds never increase; the
		// per-endpoint bound counts waiting packets (see endpointFullLocked).
		endpointFull := w.endpointFullForLocked(p)
		now := time.Now()
		remaining := w.endpointWaitBudgetLocked(now)
		firstPressure := w.firstEligibleLocked(p) && (endpointFull || w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes)
		burst := (firstPressure || endpointFull && !w.census[key] && (w.active[key] || w.recentlyCompletedLocked(key, now))) && remaining > 0
		eligible := !w.stopped && (!firstPressure || burst) && (!endpointFull || burst) &&
			(!w.census[key] || w.censusRoomLocked(p))
		full := endpointFull || w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes
		mask = 0
		if endpointFull {
			mask |= 1
			waiting := len(w.jobs[key])
			if w.active[key] {
				waiting -= w.activeBatch[key]
			}
			if waiting < MaxAttributionPerEndpoint && !w.firstEligibleLocked(p) {
				mask |= 16
			} // shared global reserve, not a full waiting batch
		}
		if w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes {
			mask |= 2
		}
		if w.census[key] && !w.censusRoomLocked(p) {
			mask |= 4
		}
		if w.stopped {
			mask |= 8
		}
		var rejection any
		if mask&4 != 0 && !eligible && !diagnostics.ObservationTime().IsZero() {
			holders := make([]map[string]any, 0, 2)
			endpoints := 0
			for k, c := range w.census {
				if c {
					endpoints++
				}
				if c && w.active[k] && len(w.jobs[k]) > 0 {
					var elapsed any
					if at := w.diagnosticActive[k]; !at.IsZero() {
						elapsed = now.Sub(at).Nanoseconds()
					}
					holders = append(holders, map[string]any{"flow": w.jobs[k][0].flow, "batch": w.activeBatch[k], "started": w.diagnosticActive[k], "elapsed_ns": elapsed})
				}
			}
			rejection = map[string]any{"kind": "census_rejection", "at": now, "flow": p.flow, "mask": mask, "census_count": w.censusCount, "census_bytes": w.censusBytes, "census_endpoints": endpoints, "global_count": w.count, "global_bytes": w.bytes, "active_census": holders}
		}
		w.mu.Unlock()
		if rejection != nil {
			diagnostics.QueueEvidence("queue:"+p.flow.Key(), func() any { return rejection })
		}
		if !eligible {
			return false
		}
		if burst {
			limit := started.Add(EndpointBurstWait)
			if budgetLimit := now.Add(remaining); budgetLimit.Before(limit) {
				limit = budgetLimit
			}
			if limit.Before(until) {
				until = limit
				timer.Reset(time.Until(until))
			}
		}
		if !full {
			continue // capacity opened between submit and this inspection
		}
		waitStart := time.Now()
		resume := false
		select {
		case <-ctx.Done():
		case <-w.stopping:
		case <-timer.C:
		case <-w.capacity:
			resume = true
		}
		if burst {
			// Only the single receive callback spends this budget. Count actual
			// blocked time, including scheduler delay, on every exit path.
			w.mu.Lock()
			w.burstSpent += time.Since(waitStart)
			w.mu.Unlock()
		}
		if !resume {
			return false
		}
	}
}

// endpointFullLocked applies the per-endpoint waiting bound. Beyond the base
// allowance, a follower may borrow idle global packet slots but cannot displace
// another endpoint at the global limit. Keep the conservative byte reserve:
// one displaced tail need not free enough bytes for a larger incoming packet.
func (w *packetWorkers) endpointFullLocked(key string, size int) bool {
	total := len(w.jobs[key])
	waiting := total
	if w.active[key] {
		waiting -= w.activeBatch[key]
	}
	if waiting >= MaxAttributionPerEndpoint {
		return true
	}
	return total >= MaxAttributionPerEndpoint && (w.count >= MaxAttributionPackets || size > MaxAttributionBytes-SharedAttributionByteReserve-w.bytes)
}

func (w *packetWorkers) endpointWaitBudgetLocked(now time.Time) time.Duration {
	if w.burstWindow.IsZero() || now.Sub(w.burstWindow) >= endpointStallWindow {
		w.burstWindow, w.burstSpent = now, 0
	}
	return endpointStallBudget - w.burstSpent
}

// submit never waits for attribution or a worker. At capacity, an idle endpoint
// can displace one queued packet from another endpoint. General-lane followers
// can also displace waiting census work or a substantially deeper general queue.
// Recent general progress is preferred over cold work. The displaced packet
// takes the incoming callback's temporary slot until its drop verdict completes;
// it is never processed or allowed. Active heads and surviving endpoint FIFO
// are preserved. Global count/byte limits and the census subset do not increase.
func (w *packetWorkers) submit(p packetJob) bool {
	w.mu.Lock()
	key := p.key()
	q := w.jobs[key]
	p.firstProof = w.firstEligibleLocked(p)
	if w.stopped || p.size < 0 || p.size > MaxAttributionBytes || w.endpointFullForLocked(p) {
		w.mu.Unlock()
		return false
	}
	lane := 0
	if w.census[key] {
		if !w.censusRoomLocked(p) {
			w.mu.Unlock()
			return false
		}
		lane = 1
	}
	var displaced *packetJob
	if w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes {
		// Census followers do not compete for general capacity. Only the
		// callback owns a displaced drop; concurrent submitters cannot accumulate it.
		if (lane == 1 && !p.firstProof) || w.reject == nil || w.displacing {
			w.mu.Unlock()
			return false
		}
		if p.firstProof {
			displaced = w.displaceDeniedTailLocked(p, key)
		}
		if displaced == nil && lane == 0 && !p.firstProof {
			displaced = w.displaceLocked(p, key, len(q))
		}
		if displaced == nil {
			w.mu.Unlock()
			return false
		}
		w.displacing = true
		w.wg.Add(1) // shutdown must wait for this drop before closing the queue socket
	}
	if lane == 1 {
		p.censusEntered = diagnostics.ObservationTime()
		w.censusCount++
		w.censusBytes += p.size
	}
	if p.firstProof {
		if w.firstSeen == nil {
			w.firstSeen = map[string]firstProofDecision{}
		}
		if _, ok := w.firstSeen[p.flow.Key()]; !ok {
			w.makeFirstRoomLocked()
			w.firstSeen[p.flow.Key()] = firstProofDecision{until: p.deadline}
		}
		w.firstAdmissions++
	}
	w.jobs[key] = append(q, p)
	w.count++
	w.bytes += p.size
	if len(q) == 0 {
		w.ready[lane] = append(w.ready[lane], key)
		w.wake[lane].Signal()
	}
	w.mu.Unlock()
	if displaced != nil {
		// Netlink I/O and cancellation callbacks run outside the scheduler lock.
		w.reject(*displaced, rejectAdmission)
		w.mu.Lock()
		w.displacing = false
		w.mu.Unlock()
		w.wg.Done()
	}
	return true
}

// Prefer waiting census work, then the most backlogged endpoint and its oldest
// queued tail. A single victim must free enough bytes: no speculative drops and
// no unbounded sequence of verdict writes in the admission callback.
func (w *packetWorkers) displaceLocked(incoming packetJob, incomingKey string, incomingDepth int) *packetJob {
	now := time.Now()
	incomingRecent := w.recentlyCompletedLocked(incomingKey, now)
	needed := incoming.size - (MaxAttributionBytes - w.bytes)
	victimKey := ""
	var victim packetJob
	depth := 0
	victimBorrowed := false
	for key, q := range w.jobs {
		if key == incomingKey || len(q) == 0 || (w.active[key] && len(q) <= max(1, w.activeBatch[key])) {
			continue
		}
		// General followers may use slow-lane waiting capacity. Against
		// another general queue they must reduce a backlog imbalance instead
		// of taking its sole waiting head.
		victimRecent := w.recentlyCompletedLocked(key, now)
		borrowed := incomingDepth < MaxAttributionPerEndpoint && len(q) > MaxAttributionPerEndpoint
		// Fresh cold endpoints cannot displace established base work; borrowed
		// tails are reclaimable regardless of recent-progress hints.
		// This grants scheduling only, never a policy result or attribution.
		if !borrowed && victimRecent && !incomingRecent {
			continue
		}
		if !borrowed && !w.census[key] && (!incomingRecent || victimRecent) && incomingDepth > 0 && len(q) <= incomingDepth+1 {
			continue
		}
		tail := q[len(q)-1]
		if tail.size < needed {
			continue
		}
		if depth == 0 || borrowed && !victimBorrowed || borrowed == victimBorrowed && (w.census[key] && !w.census[victimKey] || w.census[key] == w.census[victimKey] && (len(q) > depth || len(q) == depth && tail.deadline.Before(victim.deadline))) {
			victimKey, victim, depth = key, tail, len(q)
			victimBorrowed = borrowed
		}
	}
	if depth == 0 {
		return nil
	}
	lane := 0
	if w.census[victimKey] {
		lane = 1
		w.censusCount--
		w.censusBytes -= victim.size
	}
	w.count--
	w.bytes -= victim.size
	if depth > 1 {
		w.jobs[victimKey] = w.jobs[victimKey][:depth-1]
	} else {
		delete(w.jobs, victimKey)
		delete(w.census, victimKey)
		for i, key := range w.ready[lane] {
			if key == victimKey {
				w.ready[lane] = append(w.ready[lane][:i], w.ready[lane][i+1:]...)
				break
			}
		}
	}
	return &victim
}

func (w *packetWorkers) run(lane int) {
	defer w.wg.Done()
	for {
		w.mu.Lock()
		for len(w.ready[lane]) == 0 && !w.stopped {
			w.wake[lane].Wait()
		}
		if len(w.ready[lane]) == 0 && w.stopped {
			w.mu.Unlock()
			return
		}
		// Keep short-burst priority, but bound how often hot endpoints can
		// overtake the oldest queued general endpoint. Then require a FIFO turn.
		next := 0
		if lane == 1 && w.firstPreferredTurns < MaxRecentPreferredTurns {
			for i, k := range w.ready[1] {
				if w.jobs[k][0].firstProof {
					next = i
					break
				}
			}
		}
		if lane == 1 {
			if next > 0 {
				w.firstPreferredTurns++
			} else {
				w.firstPreferredTurns = 0
			}
		}
		if lane == 0 && w.recentPreferredTurns < MaxRecentPreferredTurns {
			now := time.Now()
			for i, key := range w.ready[lane] {
				if w.recentlyCompletedLocked(key, now) {
					next = i
					break
				}
			}
		}
		if lane == 0 {
			if next > 0 {
				w.recentPreferredTurns++
			} else {
				w.recentPreferredTurns = 0
			}
		}
		key := w.ready[lane][next]
		w.ready[lane] = append(w.ready[lane][:next], w.ready[lane][next+1:]...)
		p := w.jobs[key][0]
		if lane == 0 && !w.stopped && w.processBatch != nil && p.flow.Protocol == "udp" && len(w.jobs[key]) < daemon.MaxUDPObservationBatch && w.coalesceWindow > 0 {
			// Reserve the endpoint/head while waiting so another worker cannot
			// overtake it. Tail packets remain bounded and displaceable until frozen.
			w.active[key], w.activeBatch[key] = true, 1
			until := time.Now().Add(w.coalesceWindow)
			if p.deadline.Before(until) {
				until = p.deadline
			}
			w.mu.Unlock()
			timer := time.NewTimer(time.Until(until))
			select {
			case <-timer.C:
			case <-w.stopping:
			}
			timer.Stop()
			w.mu.Lock()
		}
		n := 1
		if w.processBatch != nil && p.flow.Protocol == "udp" {
			for n < daemon.MaxUDPObservationBatch && n < len(w.jobs[key]) && w.jobs[key][n].flow == p.flow && w.jobs[key][n].token == p.token {
				n++
			}
		}
		// Freeze membership before the fresh check. No later arrival may share
		// its evidence, and all frozen packet IDs remain charged and protected.
		batch := append([]packetJob(nil), w.jobs[key][:n]...)
		w.activeBatch[key] = n
		w.active[key] = true
		stop := w.stopped
		if at := diagnostics.ObservationTime(); !at.IsZero() {
			if w.diagnosticActive == nil {
				w.diagnosticActive = map[string]time.Time{}
			}
			w.diagnosticActive[key] = at
		}
		w.mu.Unlock()
		for _, item := range batch {
			diagnostics.Since(diagnostics.QueueResidence, item.deadline.Add(-AttributionTimeout))
		}
		diagnostics.Count(diagnostics.WorkerVisits, uint64(n))
		diagnostics.Batch(n)
		work := diagnostics.Begin(diagnostics.WorkerBatch)
		var censusWork diagnostics.Span
		if lane == 1 {
			for _, item := range batch {
				diagnostics.Since(diagnostics.CensusResidence, item.deadline.Add(-AttributionTimeout))
				diagnostics.Since(diagnostics.CensusWait, item.censusEntered)
			}
			censusWork = diagnostics.Begin(diagnostics.CensusService)
		}
		var done bool
		if n > 1 {
			done = w.processBatch(batch, stop, lane == 1)
		} else {
			done = w.process(p, stop, lane == 1)
		}
		censusWork.End()
		work.End()
		if done {
			diagnostics.Count(diagnostics.CompletedVisits, uint64(n))
		}
		w.mu.Lock()
		delete(w.diagnosticActive, key)
		if !done {
			delete(w.recent, key)
			// Move the entire endpoint, including its active head, without releasing
			// global accounting. Later packets must not overtake this cold lookup.
			// Packets beyond the base per-endpoint allowance (a waiting second
			// batch) may not fit the census subset. Keep the frozen batch, the base
			// allowance and FIFO order; refuse only that extra tail, as base
			// admission would have. Within the base allowance nothing changes.
			q := w.jobs[key]
			keep, size := len(q), 0
			for _, j := range q {
				size += j.size
			}
			for keep > MaxAttributionPerEndpoint && keep > n && !w.queueCensusRoomLocked(q[:keep]) {
				keep--
				size -= q[keep].size
			}
			if lane == 0 && !w.stopped && w.queueCensusRoomLocked(q[:keep]) {
				// The trimmed tail is detached from the endpoint but stays charged
				// against the global count/byte bounds until its drop verdict is done.
				tail := append([]packetJob(nil), q[keep:]...)
				w.jobs[key] = q[:keep]
				entered := diagnostics.ObservationTime()
				for i := range w.jobs[key] {
					w.jobs[key][i].censusEntered = entered
				}
				w.census[key] = true
				w.censusCount += keep
				w.censusBytes += size
				delete(w.active, key)
				delete(w.activeBatch, key)
				w.ready[1] = append(w.ready[1], key)
				w.wake[1].Signal()
				w.mu.Unlock()
				for _, item := range tail {
					if w.reject != nil {
						w.reject(item, rejectCensus)
					}
					w.mu.Lock()
					w.count--
					w.bytes -= item.size
					w.mu.Unlock()
					select {
					case w.capacity <- struct{}{}:
					default:
					}
				}
				continue
			}
			stop = w.stopped
			w.mu.Unlock()
			cause := rejectCensus
			if stop {
				cause = rejectShutdown
			}
			for _, item := range batch {
				w.reject(item, cause)
			}
			w.mu.Lock()
		}
		if done && lane == 0 && !w.stopped {
			w.completedLocked(key, time.Now())
		}
		delete(w.active, key)
		delete(w.activeBatch, key)
		q := w.jobs[key][n:]
		size := 0
		for _, item := range batch {
			size += item.size
		}
		w.count -= n
		w.bytes -= size
		select {
		case w.capacity <- struct{}{}:
		default:
		}
		if lane == 1 {
			w.censusCount -= n
			w.censusBytes -= size
		}
		if len(q) == 0 {
			delete(w.jobs, key)
			delete(w.census, key)
		} else {
			w.jobs[key] = q
			w.ready[lane] = append(w.ready[lane], key)
			w.wake[lane].Signal()
		}
		w.mu.Unlock()
	}
}

// The hint expires after one second, holds at most the global packet bound,
// and is revoked as soon as a general lookup needs census. Socket replacement
// may inherit scheduling priority but never attribution or permission authority.
func (w *packetWorkers) recentlyCompletedLocked(key string, now time.Time) bool {
	at, ok := w.recent[key]
	return ok && !now.Before(at) && now.Sub(at) < recentCompletionWindow
}

func (w *packetWorkers) completedLocked(key string, now time.Time) {
	if _, ok := w.recent[key]; !ok && len(w.recent) >= MaxAttributionPackets {
		oldestKey := ""
		var oldest time.Time
		for candidate, at := range w.recent {
			if oldestKey == "" || at.Before(oldest) {
				oldestKey, oldest = candidate, at
			}
		}
		delete(w.recent, oldestKey)
	}
	w.recent[key] = now
}

// The owner cancels first; both lanes drain before the queue socket closes.
func (w *packetWorkers) stop() {
	w.mu.Lock()
	if !w.stopped {
		close(w.stopping)
	}
	w.stopped = true
	for _, wake := range w.wake {
		wake.Broadcast()
	}
	w.mu.Unlock()
	w.wg.Wait()
}

// Diagnostic snapshot only; count/bytes include active jobs and lane transfers.
func (w *packetWorkers) healthGauges() queuehealth.Gauges {
	w.mu.Lock()
	defer w.mu.Unlock()
	return queuehealth.Gauges{FirstProofAdmissions: fmt.Sprint(w.firstAdmissions), FirstProofDisplacements: fmt.Sprint(w.firstDisplacements), FirstProofHistory: len(w.firstSeen), FirstProofHistoryEvictions: fmt.Sprint(w.firstEvictions), FirstProofHistoryFull: fmt.Sprint(w.firstFull), AttributionPackets: w.count, AttributionBytes: w.bytes, CensusPackets: w.censusCount, CensusBytes: w.censusBytes, ActiveWorkers: len(w.activeBatch)}
}
