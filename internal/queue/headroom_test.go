package queue

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

// startBlockedBatch freezes a full batch on endpoint port and holds it active.
func startBlockedBatch(t *testing.T, ports ...int) (*packetWorkers, chan []uint32, context.CancelFunc) {
	return startBlockedBatchWithReject(t, nil, ports...)
}

func startBlockedBatchWithReject(t *testing.T, reject func(packetJob, rejectionCause), ports ...int) (*packetWorkers, chan []uint32, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	batches := make(chan []uint32, 16)
	w := newPacketBatchLanes(0, 0, func(p packetJob, _, _ bool) bool {
		select {
		case batches <- []uint32{p.id}:
		default:
		}
		<-ctx.Done()
		return true
	}, func(js []packetJob, _, _ bool) bool {
		ids := []uint32{}
		for _, j := range js {
			ids = append(ids, j.id)
		}
		select {
		case batches <- ids:
		default:
		}
		<-ctx.Done()
		return true
	}, reject)
	id := uint32(1000)
	for _, port := range ports {
		for i := 0; i < MaxAttributionPerEndpoint; i++ {
			if !w.submit(job(id, port)) {
				t.Fatal("base allowance refused", port, i)
			}
			id++
		}
		w.wg.Add(1)
		go w.run(0)
		select {
		case ids := <-batches:
			if len(ids) != MaxUDPBatchForTest() {
				t.Fatal("batch not frozen at full size", ids)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no batch")
		}
	}
	return w, batches, cancel
}

func MaxUDPBatchForTest() int { return MaxAttributionPerEndpoint }

func TestActiveBatchPlusWaitingBatchWithinGlobalBounds(t *testing.T) {
	w, batches, cancel := startBlockedBatch(t, 8000)
	defer func() { cancel(); w.stop() }()
	// 16 active + 16 waiting on one endpoint; the 17th waiting packet is refused.
	for i := 0; i < MaxAttributionPerEndpoint; i++ {
		if !w.submit(job(uint32(i), 8000)) {
			t.Fatal("double buffer refused", i)
		}
	}
	if w.submit(job(99, 8000)) {
		t.Fatal("waiting bound exceeded")
	}
	w.mu.Lock()
	key := job(0, 8000).key()
	ok := w.count == 2*MaxAttributionPerEndpoint && w.activeBatch[key] == MaxAttributionPerEndpoint && len(w.jobs[key]) == 2*MaxAttributionPerEndpoint
	victim := w.displaceLocked(job(98, 9000), job(98, 9000).key(), 0)
	w.mu.Unlock()
	if !ok {
		t.Fatal("active batch not charged globally")
	}
	// Only the waiting tail may be displaced; never the frozen active batch.
	if victim != nil && victim.id >= 1000 {
		t.Fatal("active batch member displaced", victim.id)
	}
	if victim != nil {
		w.mu.Lock()
		w.displacing = false
		w.mu.Unlock()
	}
	_ = batches
}

func TestHotEndpointsBorrowIdleReserveAndColdReclaimsIt(t *testing.T) {
	// Two hot endpoints with active full batches: 32 charged.
	dropped := make(chan uint32, SharedAttributionReserve)
	w, _, cancel := startBlockedBatchWithReject(t, func(p packetJob, cause rejectionCause) {
		if cause != rejectAdmission {
			t.Error("unexpected rejection", cause)
		}
		dropped <- p.id
	}, 8000, 8001)
	defer func() { cancel(); w.stop() }()
	// Unused reserved packet slots need not drop a burst. All loans are tails
	// beyond the base allowance, outside the frozen/protected active batches.
	for i := 0; i < SharedAttributionReserve; i++ {
		if !w.submit(job(uint32(i+1), 8000+i%2)) {
			t.Fatal("idle slot unavailable", i)
		}
	}
	w.mu.Lock()
	for _, port := range []int{8000, 8001} {
		w.completedLocked(job(0, port).key(), time.Now())
	}
	w.mu.Unlock()
	// Cold TCP/UDP endpoints reclaim all 16 loans despite hot recent hints.
	for i := 0; i < SharedAttributionReserve; i++ {
		p := job(uint32(100+i), 9000+i)
		if i%2 == 1 {
			p.flow.Protocol, p.token = "tcp", "1"
		}
		if !w.submit(p) {
			t.Fatal("cold endpoint could not reclaim loan", i)
		}
	}
	seen := map[uint32]bool{}
	for i := 0; i < SharedAttributionReserve; i++ {
		id := receiveID(t, dropped)
		if id < 1 || id > SharedAttributionReserve || seen[id] {
			t.Fatal("active/base/duplicate victim", id)
		}
		seen[id] = true
	}
	if w.submit(job(50, 8000)) {
		t.Fatal("borrower displaced base work")
	}
	w.mu.Lock()
	full := w.count == MaxAttributionPackets && len(w.jobs[job(0, 8000).key()]) == MaxAttributionPerEndpoint && len(w.jobs[job(0, 8001).key()]) == MaxAttributionPerEndpoint
	w.mu.Unlock()
	if !full {
		t.Fatal("global accounting")
	}
}

// Proves only scheduling: the waiting packets form a distinct batch with its own
// processBatch call, order and accounting. Fresh ownership/policy per batch is
// covered by the daemon-backed UDP batch tests (PrepareUDPBatch closures).
func TestSecondBatchSeparateProcessingCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{}, 4)
	batches := make(chan []uint32, 8)
	w := newPacketBatchLanes(0, 0, func(p packetJob, _, _ bool) bool { batches <- []uint32{p.id}; return true }, func(js []packetJob, _, _ bool) bool {
		ids := []uint32{}
		for _, j := range js {
			ids = append(ids, j.id)
		}
		batches <- ids
		select {
		case <-release:
		case <-ctx.Done():
		}
		return true
	}, nil)
	defer func() { cancel(); w.stop() }()
	for i := uint32(0); i < 16; i++ {
		w.submit(job(i, 8000))
	}
	w.wg.Add(1)
	go w.run(0)
	var first []uint32
	select {
	case first = <-batches:
	case <-time.After(2 * time.Second):
		t.Fatal("first batch stuck")
	}
	for i := uint32(16); i < 32; i++ {
		if !w.submit(job(i, 8000)) {
			t.Fatal("second batch refused", i)
		}
	}
	release <- struct{}{}
	// The waiting packets form their own batch with their own fresh check.
	var second []uint32
	select {
	case second = <-batches:
	case <-time.After(2 * time.Second):
		t.Fatal("second batch stuck")
	}
	release <- struct{}{}
	want1, want2 := []uint32{}, []uint32{}
	for i := uint32(0); i < 16; i++ {
		want1 = append(want1, i)
		want2 = append(want2, i+16)
	}
	if !reflect.DeepEqual(first, want1) || !reflect.DeepEqual(second, want2) {
		t.Fatal("batch membership/order", first, second)
	}
	waitWorkerState(t, w, func() bool { return w.count == 0 && w.bytes == 0 && len(w.jobs) == 0 })
}

func TestHotEndpointCannotTakeColdByteReserve(t *testing.T) {
	const large = 40000
	ctx, cancel := context.WithCancel(context.Background())
	batches := make(chan int, 4)
	w := newPacketBatchLanes(0, 0, func(packetJob, bool, bool) bool {
		select {
		case batches <- 1:
		default:
		}
		<-ctx.Done()
		return true
	}, func(js []packetJob, _, _ bool) bool {
		select {
		case batches <- len(js):
		default:
		}
		<-ctx.Done()
		return true
	}, nil)
	defer func() { cancel(); w.stop() }()
	big := func(id uint32, port int) packetJob { p := job(id, port); p.size = large; return p }
	for i := uint32(0); i < MaxAttributionPerEndpoint; i++ {
		if !w.submit(big(i, 8000)) {
			t.Fatal("base allowance refused", i)
		}
	}
	w.wg.Add(1)
	go w.run(0)
	select {
	case n := <-batches:
		if n != MaxAttributionPerEndpoint {
			t.Fatal("batch size", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no batch")
	}
	// Extra large packets behind the active batch stop at the byte reserve,
	// long before the packet reserve would.
	extra := 0
	for i := uint32(100); i < 116; i++ {
		if !w.submit(big(i, 8000)) {
			break
		}
		extra++
	}
	w.mu.Lock()
	used := w.bytes
	w.mu.Unlock()
	if extra == MaxAttributionPerEndpoint || used > MaxAttributionBytes-SharedAttributionByteReserve {
		t.Fatal("hot endpoint consumed the byte reserve", extra, used)
	}
	// Cold endpoints can still use at least the reserved bytes.
	cold := 0
	for i := 0; i < 40; i++ {
		if !w.submit(big(uint32(200+i), 9000+i)) {
			break
		}
		cold++
	}
	if cold*large < SharedAttributionByteReserve-large {
		t.Fatal("cold endpoints lost the byte reserve", cold)
	}
	t.Logf("hot extra=%d cold=%d bytes after hot=%d reserve=%d", extra, cold, used, SharedAttributionByteReserve)
}

func TestCensusTransferOfDoubleBufferedEndpointKeepsBatchAndOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	gate := make(chan struct{})
	started := make(chan int, 4)
	rejectedCh := make(chan uint32, 32)
	otherCh := make(chan rejectionCause, 128)
	w := newPacketBatchLanes(0, 0, func(packetJob, bool, bool) bool { return true }, func(js []packetJob, _, census bool) bool {
		if census {
			return true
		}
		select {
		case started <- len(js):
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return false // needs the census lane
	}, func(p packetJob, c rejectionCause) {
		if c != rejectCensus {
			// Admission displacement or shutdown: existing paths, not gated.
			otherCh <- c
			return
		}
		// Hold each tail verdict until the test has checked the budget.
		select {
		case <-gate:
		case <-ctx.Done():
		}
		rejectedCh <- p.id
	})
	defer func() { cancel(); w.stop() }()
	for i := uint32(0); i < 16; i++ {
		w.submit(job(i, 8000))
	}
	w.wg.Add(1)
	go w.run(0)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("no batch")
	}
	for i := uint32(16); i < 32; i++ {
		if !w.submit(job(i, 8000)) {
			t.Fatal("second batch refused", i)
		}
	}
	close(release)
	key := job(0, 8000).key()
	waitWorkerState(t, w, func() bool { return w.census[key] })
	w.mu.Lock()
	ids := []uint32{}
	for _, j := range w.jobs[key] {
		ids = append(ids, j.id)
	}
	// 24 retained in census + 8 detached tail packets still charged.
	charged := w.count == 32 && w.bytes == 3200 && w.censusCount == MaxCensusPackets && w.censusBytes == MaxCensusPackets*100
	w.mu.Unlock()
	want := []uint32{}
	for i := uint32(0); i < MaxCensusPackets; i++ {
		want = append(want, i)
	}
	if !reflect.DeepEqual(ids, want) || !charged {
		t.Fatal("transfer kept wrong packets or released the blocked tail budget", ids, charged)
	}
	// While tail verdicts are blocked, admission cannot reuse their budget.
	// Admission may displace waiting census packets (existing behaviour), but
	// the 8 blocked tail packets stay charged and the global bound holds.
	admitted := 0
	for i := 0; i < 40; i++ {
		if w.submit(job(uint32(300+i), 9000+i)) {
			admitted++
		}
		w.mu.Lock()
		over := w.count > MaxAttributionPackets || w.bytes > MaxAttributionBytes
		w.mu.Unlock()
		if over {
			t.Fatal("global bound exceeded while tail verdicts blocked")
		}
	}
	displaced := len(otherCh)
	for i := 0; i < displaced; i++ {
		if c := <-otherCh; c != rejectAdmission {
			t.Fatal("unexpected cause", c)
		}
	}
	if admitted-displaced != MaxAttributionPackets-32 {
		t.Fatal("blocked tail budget reused", admitted, displaced)
	}
	close(gate)
	got := map[uint32]int{}
	for i := 0; i < 32-MaxCensusPackets; i++ {
		select {
		case id := <-rejectedCh:
			got[id]++
		case <-time.After(2 * time.Second):
			t.Fatal("tail rejection did not complete", got)
		}
	}
	for id := uint32(MaxCensusPackets); id < 32; id++ {
		if got[id] != 1 {
			t.Fatal("tail packet rejected", got[id], "times:", id)
		}
	}
	// After the tail verdicts and the admitted cold packets drain, only the
	// census prefix (minus displaced members) remains charged: no budget leak.
	remaining := MaxCensusPackets - displaced
	waitWorkerState(t, w, func() bool {
		return w.count == remaining && w.bytes == remaining*100 && w.censusCount == remaining
	})
	select {
	case id := <-rejectedCh:
		t.Fatal("extra rejection", id)
	default:
	}
}

func TestCensusTransferWithinBaseAllowanceUnchanged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	rejected := 0
	w := newPacketBatchLanes(0, 0, func(packetJob, bool, bool) bool { return true }, func(js []packetJob, _, census bool) bool {
		<-ctx.Done()
		return true
	}, func(packetJob, rejectionCause) { mu.Lock(); rejected++; mu.Unlock() })
	defer func() { cancel(); w.stop() }()
	// Census lane nearly full (20 of 24) from another endpoint.
	w.mu.Lock()
	other := job(500, 7000).key()
	for i := 0; i < 20; i++ {
		p := job(uint32(500+i), 7000)
		w.jobs[other] = append(w.jobs[other], p)
		w.count++
		w.bytes += p.size
	}
	w.census[other] = true
	w.censusCount, w.censusBytes = 20, 2000
	w.mu.Unlock()
	processed := make(chan struct{}, 1)
	w2 := w
	w2.processBatch = func(js []packetJob, _, census bool) bool {
		if js[0].flow.Local.Port() == 7000 {
			<-ctx.Done()
			return true
		}
		select {
		case processed <- struct{}{}:
		default:
		}
		return false
	}
	for i := uint32(0); i < 16; i++ {
		w.submit(job(i, 8000))
	}
	w.wg.Add(1)
	go w.run(0)
	select {
	case <-processed:
	case <-time.After(2 * time.Second):
		t.Fatal("no batch")
	}
	// 16 base packets do not fit the 4 census slots: as before, the frozen
	// batch is refused, not trimmed.
	waitWorkerState(t, w, func() bool { return len(w.jobs[job(0, 8000).key()]) == 0 })
	mu.Lock()
	defer mu.Unlock()
	if rejected != 16 {
		t.Fatal("base allowance behaviour changed", rejected)
	}
}
