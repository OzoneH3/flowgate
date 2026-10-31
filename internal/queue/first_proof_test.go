package queue

import (
	"context"
	"flowgate/internal/daemon"
	"sync"
	"testing"
	"time"
)

func holdWorkers() *packetWorkers {
	w := newPacketLanes(0, 0, func(packetJob, bool, bool) bool { return true }, func(packetJob, rejectionCause) {})
	w.enableFirstProofHolding(func() uint64 { return 0 })
	return w
}
func firstJob(id uint32, port int) packetJob { p := job(id, port); p.flow.NetNS = "fixture"; return p }
func TestFirstProofHoldingUsesCensusHeadroomAndReclaimsOnlyDeniedTails(t *testing.T) {
	w := holdWorkers()
	defer w.stop()
	// Two already decided, never-allowed senders fill the old census subset.
	for _, port := range []int{8100, 8101} {
		p := firstJob(0, port)
		w.noteInitialDecision(daemon.Event{Flow: p.flow, State: "blocked", Deadline: time.Now().Add(time.Minute)}, false)
		w.census[p.key()] = true
		for i := 0; i < 16; i++ {
			p.id = uint32(port + i)
			if !w.submit(p) {
				t.Fatal("repeat census admission", i)
			}
		}
	}
	if w.censusCount != 32 {
		t.Fatal(w.censusCount)
	}
	p := firstJob(100, 8200)
	w.census[p.key()] = true
	for i := 0; i < MaxFirstProofPackets; i++ {
		p.id = uint32(100 + i)
		if !w.submit(p) {
			t.Fatal("initial proof lost reserved/reclaimed capacity", i)
		}
	}
	if w.count != 48 || w.bytes > MaxAttributionBytes || w.firstDisplacements != 16 {
		t.Fatal(w.count, w.bytes, w.firstDisplacements)
	}
	if w.submit(p) {
		t.Fatal("per-connection startup bound exceeded")
	}
	// Completion consumes first-proof credit even when the decision was Deny.
	w.noteInitialDecision(daemon.Event{Flow: p.flow, State: "blocked", Deadline: time.Now().Add(time.Minute)}, false)
	w.mu.Lock()
	eligible := w.firstEligibleLocked(p)
	w.mu.Unlock()
	if eligible {
		t.Fatal("repeat sender renewed startup credit")
	}
}
func TestFirstProofHoldingDoesNotReclaimAskAllowedActiveOrExpired(t *testing.T) {
	for _, scenario := range []string{"ask", "allowed", "active", "expired", "policy-edit"} {
		t.Run(scenario, func(t *testing.T) {
			w := holdWorkers()
			defer w.stop()
			epoch := uint64(0)
			w.policyEpoch = func() uint64 { return epoch }
			p := firstJob(1, 8300)
			state := "blocked"
			allowed := false
			until := time.Now().Add(time.Minute)
			if scenario == "ask" {
				state = "awaiting-decision"
			}
			if scenario == "allowed" {
				state = "allowed"
				allowed = true
			}
			if scenario == "expired" {
				until = time.Now().Add(-time.Second)
			}
			w.noteInitialDecision(daemon.Event{Flow: p.flow, State: state, Deadline: until}, allowed)
			if !w.submit(p) {
				t.Fatal("seed")
			}
			if scenario == "active" {
				w.active[p.key()] = true
				w.activeBatch[p.key()] = 1
			}
			if scenario == "policy-edit" {
				epoch++
			}
			w.mu.Lock()
			victim := w.displaceDeniedTailLocked(firstJob(2, 8400), "different")
			w.mu.Unlock()
			if victim != nil {
				t.Fatal("reclaimed protected or stale work", scenario)
			}
		})
	}
}
func TestFirstProofHoldingBoundedBytesMetadataAndNoNewCallbackWait(t *testing.T) {
	w := holdWorkers()
	defer w.stop()
	p := firstJob(1, 8500)
	p.size = MaxFirstProofBytes
	if !w.submit(p) || w.submit(firstJob(2, 8500)) {
		t.Fatal("per-connection byte bound")
	}
	w2 := holdWorkers()
	defer w2.stop()
	for i := 0; i < MaxFirstProofFlows; i++ {
		p := firstJob(1, 10000+i)
		w2.noteInitialDecision(daemon.Event{Flow: p.flow, State: "blocked", Deadline: time.Now().Add(time.Minute)}, false)
	}
	w2.mu.Lock()
	eligible := w2.firstEligibleLocked(firstJob(2, 30000))
	w2.mu.Unlock()
	if !eligible || len(w2.firstSeen) > MaxFirstProofFlows {
		t.Fatal("completed metadata disabled future startup holding")
	}
	// Saturated initial work gets only the existing 2ms attempt / 10ms per100ms
	// callback budget, never the250ms global wait.
	w3 := holdWorkers()
	defer w3.stop()
	for i := 0; i < 48; i++ {
		if !w3.submit(firstJob(uint32(i), 9000+i)) {
			t.Fatal(i)
		}
	}
	begin := time.Now()
	if w3.submitWait(context.Background(), firstJob(99, 9800)) {
		t.Fatal("over-capacity admission")
	}
	if time.Since(begin) > 100*time.Millisecond {
		t.Fatal("first proof stalled receive callback", time.Since(begin))
	}
}
func TestFirstProofHoldingWaitsForDecisionAndDrains(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	verdict := make(chan uint32, 64)
	var once sync.Once
	var w *packetWorkers
	w = newPacketLanes(1, 1, func(p packetJob, stop, census bool) bool {
		if !census && !stop {
			return false
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		verdict <- p.id
		w.noteInitialDecision(daemon.Event{Flow: p.flow, State: "allowed", Deadline: time.Now().Add(time.Minute)}, true)
		return true
	}, func(p packetJob, _ rejectionCause) { t.Error("unexpected reject", p.id) })
	w.enableFirstProofHolding(func() uint64 { return 0 })
	defer func() { once.Do(func() { close(release) }); w.stop() }()
	for i := 0; i < 24; i++ {
		if !w.submit(firstJob(uint32(i), 8600)) {
			t.Fatal("initial burst", i)
		}
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("census never started")
	}
	select {
	case <-verdict:
		t.Fatal("passed before first authorization")
	default:
	}
	once.Do(func() { close(release) })
	for i := 0; i < 24; i++ {
		select {
		case id := <-verdict:
			if id != uint32(i) {
				t.Fatal("FIFO changed", id, i)
			}
		case <-time.After(time.Second):
			t.Fatal("held packet stranded")
		}
	}
}

func TestFirstProofHistoryContinuesAfterManyCompletedFlows(t *testing.T) {
	w := holdWorkers()
	defer w.stop()
	for i := 0; i < MaxFirstProofFlows+80; i++ {
		p := firstJob(uint32(i), 10000+i)
		w.noteInitialDecision(daemon.Event{Flow: p.flow, State: "allowed", Deadline: time.Now().Add(time.Minute)}, true)
	}
	if len(w.firstSeen) > MaxFirstProofFlows || w.firstEvictions == 0 {
		t.Fatal("history did not remain bounded")
	}
	p := firstJob(9999, 30000)
	if !w.submit(p) || !w.jobs[p.key()][0].firstProof {
		t.Fatal("new startup lost holding after sequential connections")
	}
	q := firstJob(9998, 30001)
	w.noteInitialDecision(daemon.Event{Flow: q.flow, State: "allowed", Deadline: time.Now().Add(time.Millisecond)}, true)
	if time.Until(w.firstSeen[q.flow.Key()].until) < 20*time.Second {
		t.Fatal("completed allow scheduling history inherited packet deadline")
	}
	w.mu.Lock()
	eligible := w.firstEligibleLocked(q)
	w.mu.Unlock()
	if eligible {
		t.Fatal("active queue-allowed flow renewed startup credit")
	}
	w.mu.Lock()
	w.firstSeen = map[string]firstProofDecision{}
	for i := 0; i < MaxFirstProofFlows; i++ {
		w.firstSeen[string(rune(i+1))] = firstProofDecision{until: time.Now().Add(-time.Second)}
	}
	w.nextFirstPrune = time.Time{}
	eligible = w.firstEligibleLocked(firstJob(1111, 31000))
	w.mu.Unlock()
	if !eligible {
		t.Fatal("expired incomplete records disabled future startup")
	}
}
