package queue

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestFairAdmissionDisplacesQueuedTailPreservesFIFOAndCompletesOnce(t *testing.T) {
	release := make(chan struct{})
	started := make(chan uint32, 64)
	dropped := make(chan uint32, 64)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	seen := map[uint32]int{}
	w := newPacketLanes(1, 0, func(p packetJob, stop, census bool) bool {
		started <- p.id
		if p.id == 0 {
			<-release
		}
		mu.Lock()
		seen[p.id]++
		mu.Unlock()
		return true
	}, func(p packetJob, cause rejectionCause) {
		if cause != rejectAdmission {
			t.Errorf("unexpected rejection cause %v", cause)
		}
		dropped <- p.id
		mu.Lock()
		seen[p.id]++
		mu.Unlock()
	})
	defer func() { unblock(); w.stop() }()
	for i := 0; i < MaxAttributionPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i/MaxAttributionPerEndpoint)) {
			t.Fatal("fill", i)
		}
		if i == 0 && receiveID(t, started) != 0 {
			t.Fatal("head")
		}
	}
	if w.submit(job(900, 8000)) {
		t.Fatal("backlogged endpoint bypassed bound")
	}
	if !w.submit(job(1000, 9000)) {
		t.Fatal("idle endpoint denied by backlogged queues")
	}
	if id := receiveID(t, dropped); id != 15 {
		t.Fatal("did not displace oldest queued tail", id)
	}
	w.mu.Lock()
	if w.count != MaxAttributionPackets || !w.active[job(0, 8000).key()] {
		t.Error("budget/active head changed")
	}
	w.mu.Unlock()
	unblock()
	var firstEndpoint []uint32
	for i := 0; i < MaxAttributionPackets-1; i++ {
		id := receiveID(t, started)
		if id < 16 {
			firstEndpoint = append(firstEndpoint, id)
		}
	}
	for i, id := range firstEndpoint {
		if id != uint32(i+1) {
			t.Fatal("surviving endpoint FIFO changed", firstEndpoint)
		}
	}
	w.stop()
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < MaxAttributionPackets; i++ {
		if seen[uint32(i)] != 1 {
			t.Fatal("packet not completed exactly once", i, seen)
		}
	}
	if seen[1000] != 1 || w.count != 0 || w.bytes != 0 || len(w.active) != 0 {
		t.Fatal("leaked packet or accounting", seen)
	}
}

func TestFairAdmissionBytePressureNeverDisplacesActiveOrInsufficientVictim(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	started, dropped := make(chan uint32, 4), make(chan uint32, 4)
	w := newPacketLanes(1, 0, func(p packetJob, stop, census bool) bool {
		started <- p.id
		if p.id == 1 {
			<-release
		}
		return true
	}, func(p packetJob, _ rejectionCause) { dropped <- p.id })
	defer func() { unblock(); w.stop() }()
	head := job(1, 8000)
	head.size = 100
	if !w.submit(head) {
		t.Fatal("head")
	}
	receiveID(t, started)
	tail := job(2, 8000)
	tail.size = MaxAttributionBytes - 100
	if !w.submit(tail) {
		t.Fatal("tail")
	}
	incoming := job(3, 8001)
	incoming.size = MaxAttributionBytes
	if w.submit(incoming) {
		t.Fatal("active bytes displaced or byte budget exceeded")
	}
	select {
	case id := <-dropped:
		t.Fatal("speculative drop without enough space", id)
	default:
	}
	incoming.size = 100
	if !w.submit(incoming) {
		t.Fatal("queued bytes denied another endpoint")
	}
	if id := receiveID(t, dropped); id != 2 {
		t.Fatal("wrong byte victim", id)
	}
	w.mu.Lock()
	if w.bytes != 200 || w.count != 2 {
		t.Error("byte accounting", w.bytes, w.count)
	}
	w.mu.Unlock()
}

func TestFairAdmissionCanDisplaceWaitingCensusHeadButNotActiveHead(t *testing.T) {
	censusRelease, generalRelease := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(censusRelease); close(generalRelease) }) }
	dropped := make(chan uint32, 64)
	w := newPacketLanes(1, 1, func(p packetJob, stop, census bool) bool {
		if stop {
			return true
		}
		if p.id == 100 {
			<-generalRelease
			return true
		}
		if census {
			<-censusRelease
			return true
		}
		return false
	}, func(p packetJob, cause rejectionCause) {
		if cause == rejectAdmission {
			dropped <- p.id
		}
	})
	defer func() { unblock(); w.stop() }()
	for i := 1; i <= MaxCensusPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("census fill", i)
		}
	}
	waitWorkerState(t, w, func() bool { return w.censusCount == MaxCensusPackets && w.active[job(1, 8001).key()] })
	if !w.submit(job(100, 9000)) {
		t.Fatal("general blocker")
	}
	waitWorkerState(t, w, func() bool { return w.active[job(100, 9000).key()] })
	for i := 1; i < MaxAttributionPackets-MaxCensusPackets; i++ {
		if !w.submit(job(uint32(100+i), 9000+i)) {
			t.Fatal("general fill", i)
		}
	}
	if !w.submit(job(999, 9999)) {
		t.Fatal("idle endpoint could not enter full mixed queue")
	}
	if id := receiveID(t, dropped); id != 2 {
		t.Fatal("waiting census head not preferred/protected active head", id)
	}
	w.mu.Lock()
	if w.censusCount != MaxCensusPackets-1 || w.count != MaxAttributionPackets || !w.active[job(1, 8001).key()] {
		t.Error("census/active accounting")
	}
	w.mu.Unlock()
}

func TestFairAdmissionGeneralFollowersCanUseWaitingCensusCapacity(t *testing.T) {
	censusRelease, generalRelease := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(censusRelease); close(generalRelease) }) }
	dropped := make(chan uint32, 64)
	w := newPacketLanes(1, 1, func(p packetJob, stop, census bool) bool {
		if stop {
			return true
		}
		if p.id == 100 {
			<-generalRelease
			return true
		}
		if census {
			<-censusRelease
			return true
		}
		return false
	}, func(p packetJob, cause rejectionCause) {
		if cause == rejectAdmission {
			dropped <- p.id
		}
	})
	defer func() { unblock(); w.stop() }()
	for i := 1; i <= MaxCensusPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("census fill")
		}
	}
	waitWorkerState(t, w, func() bool { return w.censusCount == MaxCensusPackets && w.active[job(1, 8001).key()] })
	if !w.submit(job(100, 9000)) {
		t.Fatal("blocker")
	}
	waitWorkerState(t, w, func() bool { return w.active[job(100, 9000).key()] })
	for i := 1; i < MaxAttributionPackets-MaxCensusPackets; i++ {
		if !w.submit(job(uint32(100+i), 9000+i)) {
			t.Fatal("general fill")
		}
	}
	for i := 0; i < 3; i++ {
		if !w.submit(job(uint32(999+i), 9999)) {
			t.Fatal("general follower dropped behind full slow lane", i)
		}
		if id := receiveID(t, dropped); id != uint32(2+i) {
			t.Fatal("wrong waiting census victim", id)
		}
	}
	if w.submit(job(2000, 8001)) {
		t.Fatal("census follower displaced general work")
	}
	w.mu.Lock()
	if len(w.jobs[job(999, 9999).key()]) != 3 || w.count != MaxAttributionPackets || w.censusCount != MaxCensusPackets-3 {
		t.Error("follower/accounting mismatch")
	}
	w.mu.Unlock()
}

func TestFairAdmissionShutdownWaitsForDisplacedVerdictAndBoundsConcurrentDrops(t *testing.T) {
	processRelease, dropRelease := make(chan struct{}), make(chan struct{})
	entered := make(chan uint32, 1)
	var processOnce, dropOnce sync.Once
	unblockProcess := func() { processOnce.Do(func() { close(processRelease) }) }
	unblockDrop := func() { dropOnce.Do(func() { close(dropRelease) }) }
	w := newPacketLanes(1, 0, func(p packetJob, stop, census bool) bool {
		if p.id == 0 {
			entered <- p.id
			<-processRelease
		}
		return true
	}, func(p packetJob, cause rejectionCause) {
		if cause != rejectAdmission {
			t.Errorf("cause %v", cause)
		}
		<-dropRelease
	})
	defer func() { unblockProcess(); unblockDrop(); w.stop() }()
	for i := 0; i < MaxAttributionPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i/MaxAttributionPerEndpoint)) {
			t.Fatal("fill", i)
		}
		if i == 0 {
			receiveID(t, entered)
		}
	}
	admitted := make(chan bool, 1)
	go func() { admitted <- w.submit(job(1000, 9000)) }()
	waitWorkerState(t, w, func() bool { return w.displacing })
	if w.submit(job(1001, 9001)) {
		t.Fatal("concurrent callback accumulated displaced drops")
	}
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	waitWorkerState(t, w, func() bool { return w.stopped })
	unblockProcess()
	waitWorkerState(t, w, func() bool { return w.count == 0 })
	select {
	case <-stopped:
		t.Fatal("queue closed before displaced verdict finished")
	default:
	}
	unblockDrop()
	if !<-admitted {
		t.Fatal("admitted packet lost ownership")
	}
	<-stopped
	if w.displacing || w.count != 0 || w.bytes != 0 {
		t.Fatal("shutdown leak")
	}
}

func TestRecentCompletionProtectsAndPrioritizesEstablishedGeneralWork(t *testing.T) {
	release := make(chan struct{})
	started, dropped := make(chan uint32, 64), make(chan uint32, 64)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	w := newPacketLanes(1, 0, func(p packetJob, stop, census bool) bool {
		started <- p.id
		if p.id == 0 {
			<-release
		}
		return true
	}, func(p packetJob, _ rejectionCause) { dropped <- p.id })
	defer func() { unblock(); w.stop() }()
	for i := 0; i < MaxAttributionPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("fill", i)
		}
		if i == 0 {
			receiveID(t, started)
		}
	}
	native := job(1000, 9000)
	w.mu.Lock()
	w.completedLocked(native.key(), time.Now())
	w.mu.Unlock()
	if !w.submit(native) || !w.submit(job(1001, 9000)) {
		t.Fatal("established endpoint/follower denied")
	}
	receiveID(t, dropped)
	receiveID(t, dropped)
	if !w.submit(job(2000, 9001)) {
		t.Fatal("cold endpoint denied despite cold queued victim")
	}
	id := receiveID(t, dropped)
	if id == 1000 || id == 1001 {
		t.Fatal("cold endpoint displaced established work")
	}
	unblock()
	if id := receiveID(t, started); id != 1000 {
		t.Fatal("established head delayed behind cold queues", id)
	}
	if id := receiveID(t, started); id != 1001 {
		t.Fatal("established follower delayed/reordered", id)
	}
}

func TestRecentCompletionHintsAreBoundedExpireAndRevokeOnCensus(t *testing.T) {
	w := newPacketLanes(0, 0, nil, nil)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		w.completedLocked(fmt.Sprint(i), now.Add(time.Duration(i)*time.Nanosecond))
	}
	if len(w.recent) != MaxAttributionPackets {
		t.Fatal("unbounded hint history", len(w.recent))
	}
	if _, ok := w.recent["0"]; ok {
		t.Fatal("old hint retained instead of least recent eviction")
	}
	at := now.Add(999 * time.Nanosecond)
	if !w.recentlyCompletedLocked("999", at) || w.recentlyCompletedLocked("999", at.Add(recentCompletionWindow)) || w.recentlyCompletedLocked("999", now) {
		t.Fatal("hint freshness/clock rollback")
	}
	// A socket that was cheap before can become cold again. Deferral must revoke
	// its priority, rather than carrying that hint into the census lane.
	entered, release := make(chan uint32, 2), make(chan struct{})
	x := newPacketLanes(1, 1, func(p packetJob, stop, census bool) bool {
		if !census {
			return false
		}
		entered <- p.id
		<-release
		return true
	}, func(packetJob, rejectionCause) { t.Error("unexpected rejection") })
	defer func() { close(release); x.stop() }()
	p := job(1, 8000)
	x.mu.Lock()
	x.completedLocked(p.key(), time.Now())
	x.mu.Unlock()
	if !x.submit(p) {
		t.Fatal("submit")
	}
	receiveID(t, entered)
	x.mu.Lock()
	_, exists := x.recent[p.key()]
	x.mu.Unlock()
	if exists {
		t.Fatal("deferring endpoint retained recent-completion priority")
	}
}
