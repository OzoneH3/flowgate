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
const CensusWorkers = 2
const MaxCensusPackets = 24
const MaxCensusBytes = 1 << 19
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
	mu                       sync.Mutex
	wake                     [2]*sync.Cond
	jobs                     map[string][]packetJob // includes active jobs, even across lane transfer
	census                   map[string]bool        // ordering only; never permission authority
	ready                    [2][]string
	count, bytes             int
	censusCount, censusBytes int
	stopped                  bool
	wg                       sync.WaitGroup
	process                  func(packetJob, bool, bool) bool // true = completed, false = needs census
	reject                   func(packetJob, bool)            // lane overflow or shutdown, exactly one drop
}

// Single-lane adapter used by ordering/bounds tests.
func newPacketWorkers(n int, process func(packetJob, bool)) *packetWorkers {
	return newPacketLanes(n, 0, func(p packetJob, stop, census bool) bool { process(p, stop); return true }, nil)
}

func newPacketLanes(general, census int, process func(packetJob, bool, bool) bool, reject func(packetJob, bool)) *packetWorkers {
	w := &packetWorkers{jobs: make(map[string][]packetJob), census: make(map[string]bool), process: process, reject: reject}
	for lane, n := range []int{general, census} {
		w.wake[lane] = sync.NewCond(&w.mu)
		for i := 0; i < n; i++ {
			w.wg.Add(1)
			go w.run(lane)
		}
	}
	return w
}

// submit never waits for attribution or a worker. The census lane is a subset
// of the global budget, leaving half the count/bytes available to other flows.
func (w *packetWorkers) submit(p packetJob) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := p.key()
	q := w.jobs[key]
	if w.stopped || p.size < 0 || w.count >= MaxAttributionPackets || p.size > MaxAttributionBytes-w.bytes || len(q) >= MaxAttributionPerEndpoint {
		return false
	}
	lane := 0
	if w.census[key] {
		if w.censusCount >= MaxCensusPackets || p.size > MaxCensusBytes-w.censusBytes {
			return false
		}
		lane = 1
		w.censusCount++
		w.censusBytes += p.size
	}
	w.jobs[key] = append(q, p)
	w.count++
	w.bytes += p.size
	if len(q) == 0 {
		w.ready[lane] = append(w.ready[lane], key)
		w.wake[lane].Signal()
	}
	return true
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
		key := w.ready[lane][0]
		w.ready[lane] = w.ready[lane][1:]
		p := w.jobs[key][0]
		stop := w.stopped
		w.mu.Unlock()
		done := w.process(p, stop, lane == 1)
		w.mu.Lock()
		if !done {
			// Move the entire endpoint, including its active head, without releasing
			// global accounting. Later packets must not overtake this cold lookup.
			q := w.jobs[key]
			size := 0
			for _, j := range q {
				size += j.size
			}
			if lane == 0 && !w.stopped && len(q) <= MaxCensusPackets-w.censusCount && size <= MaxCensusBytes-w.censusBytes {
				w.census[key] = true
				w.censusCount += len(q)
				w.censusBytes += size
				w.ready[1] = append(w.ready[1], key)
				w.wake[1].Signal()
				w.mu.Unlock()
				continue
			}
			stop = w.stopped
			w.mu.Unlock()
			w.reject(p, stop)
			w.mu.Lock()
		}
		q := w.jobs[key][1:]
		w.count--
		w.bytes -= p.size
		if lane == 1 {
			w.censusCount--
			w.censusBytes -= p.size
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

// The owner cancels first; both lanes drain before the queue socket closes.
func (w *packetWorkers) stop() {
	w.mu.Lock()
	w.stopped = true
	for _, wake := range w.wake {
		wake.Broadcast()
	}
	w.mu.Unlock()
	w.wg.Wait()
}
