package queue

import (
	"flowgate/internal/daemon"
	"flowgate/internal/queuehealth"
	"sync"
	"time"
)

const MaxRetainedPackets = 64
const MaxRetainedBytes = 1 << 20
const MaxFlowBytes = 65536
const MaxFlowPackets = 4

// No payload copy is retained in Go. The kernel retains the packet until verdict.
type held struct {
	flow        string
	id          uint32
	size        int
	event       string
	fingerprint string
	deadline    time.Time
}
type Retainer struct {
	diagnostic func(queuehealth.Cause)
	flushMu    sync.Mutex // serialize flushes, never block Add on attribution
	mu         sync.Mutex
	packets    []held
	bytes      int
}

func (r *Retainer) Add(id uint32, size int, v daemon.Event) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	count, bytes := 0, 0
	for _, p := range r.packets {
		if p.flow == v.Flow.Key()+"|"+v.Token {
			count++
			bytes += p.size
		}
	}
	max := MaxFlowPackets
	if v.Flow.Protocol == "tcp" {
		max = 1
	} // collapse retransmitted SYNs
	if size < 0 || len(r.packets) >= MaxRetainedPackets || r.bytes+size > MaxRetainedBytes || count >= max || bytes+size > MaxFlowBytes {
		return false
	}
	r.packets = append(r.packets, held{v.Flow.Key() + "|" + v.Token, id, size, v.ID, v.Attribution.Fingerprint, v.Deadline})
	r.bytes += size
	return true
}
func (r *Retainer) Flush(now time.Time, state func(string, string) string, verdict func(uint32, bool) error, stop bool) error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	batch := append([]held(nil), r.packets...)
	r.mu.Unlock()
	var remaining []held
	releasedBytes := 0
	var first error
	for _, p := range batch {
		s := "drop"
		// The supplied tick may be stale after an earlier packet's slow check
		// (or after waiting for another flush). Never resolve an expired packet.
		if !stop && now.Before(p.deadline) && time.Now().Before(p.deadline) {
			s = state(p.event, p.fingerprint)
		}
		// Deadline is independently checked after potentially slow attribution.
		if !stop && s == "pending" && time.Now().Before(p.deadline) {
			remaining = append(remaining, p)
			continue
		}
		if r.diagnostic != nil {
			if stop {
				r.diagnostic(queuehealth.RetainedShutdown)
			} else if !time.Now().Before(p.deadline) {
				r.diagnostic(queuehealth.RetainedDeadline)
			}
		}
		if err := verdict(p.id, s == "allow" && time.Now().Before(p.deadline)); err != nil && first == nil {
			first = err
		}
		releasedBytes += p.size
	}
	r.mu.Lock()
	r.packets = append(remaining, r.packets[len(batch):]...)
	r.bytes -= releasedBytes
	r.mu.Unlock()
	return first
}

func (r *Retainer) gauges() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.packets), r.bytes
}
