package queue

import (
	"flowgate/internal/identity"
	"fmt"
	"sync"
	"testing"
	"time"
)

func job(id uint32, port int) packetJob {
	f, _ := identity.ParseFlow("udp", "outgoing", fmt.Sprintf("127.0.0.1:%d", port), "127.0.0.1:9000")
	return packetJob{id: id, size: 100, flow: f, token: "udp", deadline: time.Now().Add(time.Minute)}
}
func receiveID(t *testing.T, ch <-chan uint32) uint32 {
	t.Helper()
	select {
	case id := <-ch:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not progress")
		return 0
	}
}
func TestWorkersIndependentEndpointsAndOrdering(t *testing.T) {
	started := make(chan uint32, 10)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	w := newPacketWorkers(2, func(p packetJob, _ bool) {
		started <- p.id
		if p.id == 1 {
			<-release
		}
	})
	defer func() { unblock(); w.stop() }()
	if !w.submit(job(1, 8000)) {
		t.Fatal("submit")
	}
	if receiveID(t, started) != 1 {
		t.Fatal("first")
	}
	// A new remote on the same endpoint must not overtake the active packet.
	second := job(2, 8000)
	second.flow.Remote = job(0, 9001).flow.Local
	if !w.submit(second) || !w.submit(job(3, 8001)) {
		t.Fatal("submit")
	}
	if id := receiveID(t, started); id != 3 {
		t.Fatalf("same socket overtook active attribution: %d", id)
	}
	unblock()
	if id := receiveID(t, started); id != 2 {
		t.Fatal(id)
	}
}
func TestWorkerBoundsIncludeActiveAndStopDrains(t *testing.T) {
	started := make(chan uint32, 100)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	seen := map[uint32]int{}
	w := newPacketWorkers(1, func(p packetJob, stopped bool) {
		started <- p.id
		if p.id == 0 {
			<-release
		} else if !stopped {
			t.Error("queued job resolved during stop")
		}
		mu.Lock()
		seen[p.id]++
		mu.Unlock()
	})
	defer func() { unblock(); w.stop() }()
	if !w.submit(job(0, 8000)) {
		t.Fatal("submit")
	}
	receiveID(t, started)
	for i := 1; i < MaxAttributionPerEndpoint; i++ {
		if !w.submit(job(uint32(i), 8000)) {
			t.Fatal("flow cap early")
		}
	}
	if w.submit(job(99, 8000)) {
		t.Fatal("flow cap exceeded")
	}
	for i := MaxAttributionPerEndpoint; i < MaxAttributionPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("global cap early")
		}
	}
	if w.submit(job(100, 9999)) {
		t.Fatal("global cap exceeded")
	}
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	// Synchronize on the state instead of depending on goroutine scheduling.
	w.mu.Lock()
	for !w.stopped {
		w.mu.Unlock()
		time.Sleep(time.Millisecond)
		w.mu.Lock()
	}
	w.mu.Unlock()
	if w.submit(job(101, 9998)) {
		t.Fatal("submitted after stop")
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop stalled")
	}
	for i := 0; i < MaxAttributionPackets; i++ {
		if seen[uint32(i)] != 1 {
			t.Fatalf("packet %d processed %d times", i, seen[uint32(i)])
		}
	}
	if w.count != 0 || w.bytes != 0 {
		t.Fatal("budget leaked")
	}
}
func TestWorkerByteBound(t *testing.T) {
	release := make(chan struct{})
	w := newPacketWorkers(1, func(packetJob, bool) { <-release })
	defer func() { close(release); w.stop() }()
	p := job(1, 8000)
	p.size = MaxAttributionBytes
	if !w.submit(p) {
		t.Fatal("byte cap early")
	}
	if w.submit(job(2, 8001)) {
		t.Fatal("byte cap exceeded")
	}
	p.size = -1
	if w.submit(p) {
		t.Fatal("negative size accepted")
	}
}

func waitWorkerState(t *testing.T, w *packetWorkers, ready func() bool) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		w.mu.Lock()
		ok := ready()
		w.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("worker state deadline")
}

func TestCensusLaneReservesNativeProgressAndPreservesEndpointOrder(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	native := make(chan uint32, 1)
	done := make(chan uint32, 32)
	var mu sync.Mutex
	general := map[uint32]int{}
	w := newPacketLanes(AttributionWorkers, CensusWorkers, func(p packetJob, stop, census bool) bool {
		if stop {
			done <- p.id
			return true
		}
		if !census {
			mu.Lock()
			general[p.id]++
			mu.Unlock()
			if p.id == 100 {
				native <- p.id
				return true
			}
			return false
		}
		<-release
		done <- p.id
		return true
	}, func(p packetJob, _ bool) { t.Errorf("unexpected lane rejection %d", p.id) })
	defer func() { unblock(); w.stop() }()
	// More cold sockets than general workers, all parked in the census lane.
	for i := 1; i <= 12; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("submit")
		}
	}
	waitWorkerState(t, w, func() bool { return w.censusCount == 12 })
	if !w.submit(job(20, 8001)) {
		t.Fatal("same-endpoint follower")
	}
	if !w.submit(job(100, 9000)) {
		t.Fatal("native capacity lost")
	}
	if receiveID(t, native) != 100 {
		t.Fatal("native stalled behind census")
	}
	mu.Lock()
	followedGeneral := general[20]
	mu.Unlock()
	if followedGeneral != 0 {
		t.Fatal("endpoint follower jumped to general lane")
	}
	unblock()
	order := []uint32{}
	for i := 0; i < 13; i++ {
		order = append(order, receiveID(t, done))
	}
	first, second := -1, -1
	for i, id := range order {
		if id == 1 {
			first = i
		}
		if id == 20 {
			second = i
		}
	}
	if first < 0 || second <= first {
		t.Fatalf("same endpoint reordered across lanes: %v", order)
	}
	waitWorkerState(t, w, func() bool {
		return w.count == 0 && w.censusCount == 0 && w.bytes == 0 && w.censusBytes == 0 && len(w.census) == 0
	})
}

func TestCensusLaneSaturationDropsOnlyOverflowAndDrains(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	dropped := make(chan uint32, 64)
	native := make(chan uint32, 1)
	var mu sync.Mutex
	completions := map[uint32]int{}
	w := newPacketLanes(AttributionWorkers, CensusWorkers, func(p packetJob, stop, census bool) bool {
		if !stop && !census {
			if p.id == 100 {
				native <- p.id
			} else {
				return false
			}
		}
		if !stop && census {
			<-release
		}
		mu.Lock()
		completions[p.id]++
		mu.Unlock()
		return true
	}, func(p packetJob, _ bool) { dropped <- p.id; mu.Lock(); completions[p.id]++; mu.Unlock() })
	defer func() { unblock(); w.stop() }()
	for i := 1; i <= MaxCensusPackets; i++ {
		if !w.submit(job(uint32(i), 8000+i)) {
			t.Fatal("submit")
		}
	}
	waitWorkerState(t, w, func() bool { return w.censusCount == MaxCensusPackets })
	// New packets on a pinned endpoint obey the lane subset bound too.
	if w.submit(job(50, 8001)) {
		t.Fatal("pinned endpoint bypassed census bound")
	}
	if !w.submit(job(51, 8051)) {
		t.Fatal("general budget incorrectly consumed")
	}
	if receiveID(t, dropped) != 51 {
		t.Fatal("wrong overflow packet")
	}
	if !w.submit(job(100, 9000)) {
		t.Fatal("native budget unavailable")
	}
	receiveID(t, native)
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	waitWorkerState(t, w, func() bool { return w.stopped })
	unblock()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("lane shutdown stalled")
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i <= MaxCensusPackets; i++ {
		if completions[uint32(i)] != 1 {
			t.Fatal("packet not completed exactly once", i, completions)
		}
	}
	if completions[51] != 1 || completions[100] != 1 || w.count != 0 || w.bytes != 0 || w.censusCount != 0 || w.censusBytes != 0 {
		t.Fatal("drop or accounting error", completions)
	}
}

func TestCensusLaneByteBound(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	dropped := make(chan uint32, 2)
	w := newPacketLanes(2, 1, func(p packetJob, stop, census bool) bool {
		if stop {
			return true
		}
		if !census {
			return false
		}
		<-release
		return true
	}, func(p packetJob, _ bool) { dropped <- p.id })
	defer func() { unblock(); w.stop() }()
	p := job(1, 8000)
	p.size = MaxCensusBytes
	if !w.submit(p) {
		t.Fatal("submit")
	}
	waitWorkerState(t, w, func() bool { return w.censusBytes == MaxCensusBytes })
	if w.submit(job(2, 8000)) {
		t.Fatal("pinned endpoint bypassed byte limit")
	}
	if !w.submit(job(3, 8001)) {
		t.Fatal("remaining general byte budget lost")
	}
	if receiveID(t, dropped) != 3 {
		t.Fatal("byte overflow did not drop")
	}
}
