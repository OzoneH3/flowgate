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
