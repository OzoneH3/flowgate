package queue

import (
	"flowgate/internal/identity"
	"fmt"
	"sync"
	"time"
)

// Together with MaxRetainedPackets these leave room in the 128-packet kernel
// queue for callback processing. Attribution owns no packet payload copies.
const MaxAttributionPackets = 48
const MaxAttributionBytes = 1 << 20
const MaxAttributionPerEndpoint = 16
const AttributionWorkers = 8
const AttributionTimeout = 5 * time.Second

type packetJob struct {
	id       uint32
	size     int
	flow     identity.Flow
	token    string
	deadline time.Time
}

// The scheduling key is deliberately broader than a flow: all remotes on the
// same local endpoint run serially. It is ordering only, never identity evidence.
func (p packetJob) key() string {
	return fmt.Sprintf("%s|%s|%s|%s", p.flow.NetNS, p.flow.Direction, p.flow.Protocol, p.flow.Local)
}

type packetWorkers struct {
	mu           sync.Mutex
	wake         *sync.Cond
	jobs         map[string][]packetJob // includes the active job until it completes
	ready        []string
	count, bytes int
	stopped      bool
	wg           sync.WaitGroup
	process      func(packetJob, bool)
}

func newPacketWorkers(n int, process func(packetJob, bool)) *packetWorkers {
	w := &packetWorkers{jobs: make(map[string][]packetJob), process: process}
	w.wake = sync.NewCond(&w.mu)
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go w.run()
	}
	return w
}

// submit never waits for attribution or for a worker to become free.
func (w *packetWorkers) submit(p packetJob) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := p.key()
	q := w.jobs[key]
	if w.stopped || p.size < 0 || w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes || len(q) >= MaxAttributionPerEndpoint {
		return false
	}
	w.jobs[key] = append(q, p)
	w.count++
	w.bytes += p.size
	if len(q) == 0 {
		w.ready = append(w.ready, key)
		w.wake.Signal()
	}
	return true
}

func (w *packetWorkers) run() {
	defer w.wg.Done()
	for {
		w.mu.Lock()
		for len(w.ready) == 0 && !w.stopped {
			w.wake.Wait()
		}
		if len(w.ready) == 0 && w.stopped {
			w.mu.Unlock()
			return
		}
		key := w.ready[0]
		w.ready = w.ready[1:]
		p := w.jobs[key][0]
		stop := w.stopped
		w.mu.Unlock()
		w.process(p, stop)
		w.mu.Lock()
		q := w.jobs[key][1:]
		w.count--
		w.bytes -= p.size
		if len(q) == 0 {
			delete(w.jobs, key)
		} else {
			w.jobs[key] = q
			w.ready = append(w.ready, key)
			w.wake.Signal()
		}
		w.mu.Unlock()
	}
}

// stop drains every admitted job before the queue socket is closed. The owner
// cancels its context first so an in-flight resolver cannot release an Allow.
func (w *packetWorkers) stop() {
	w.mu.Lock()
	w.stopped = true
	w.wake.Broadcast()
	w.mu.Unlock()
	w.wg.Wait()
}
