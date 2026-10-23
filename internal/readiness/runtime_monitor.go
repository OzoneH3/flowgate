package readiness

import (
	"context"
	"sync"
	"time"
)

// RuntimeMonitor publishes snapshots without making API readers wait for probes.
// Run has one owner and Snapshot returns a copy, so readers cannot mutate health.
type RuntimeMonitor struct {
	mu     sync.RWMutex
	checks []Check
}

func NewRuntimeMonitor() *RuntimeMonitor { return &RuntimeMonitor{checks: Runtime()} }
func (m *RuntimeMonitor) Snapshot() []Check {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Check(nil), m.checks...)
}
func (m *RuntimeMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checks := Runtime()
			m.mu.Lock()
			m.checks = checks
			m.mu.Unlock()
		}
	}
}
