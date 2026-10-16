package queue

import (
	"flowgate/internal/daemon"
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
	mu      sync.Mutex
	packets []held
	bytes   int
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
	r.mu.Lock()
	defer r.mu.Unlock()
	var remaining []held
	var first error
	for _, p := range r.packets {
		s := "drop"
		if !stop && now.Before(p.deadline) {
			s = state(p.event, p.fingerprint)
		}
		// Deadline is independently checked after potentially slow attribution.
		if !stop && s == "pending" {
			remaining = append(remaining, p)
			continue
		}
		if err := verdict(p.id, s == "allow" && time.Now().Before(p.deadline)); err != nil && first == nil {
			first = err
		}
		r.bytes -= p.size
	}
	r.packets = remaining
	return first
}
