// Package monitor collects read-only snapshots independently of API polling.
package monitor

import (
	"context"
	"encoding/json"
	"flowgate/internal/identity"
	"sync"
	"time"
)

type Observer struct {
	UDP      func() identity.UDPSnapshot
	mu       sync.RWMutex
	snapshot identity.ActivitySnapshot
	interval time.Duration
}

func New(interval time.Duration) *Observer {
	return &Observer{interval: interval, snapshot: identity.ActivitySnapshot{Error: "Initial collection in progress", Complete: false}}
}
func (o *Observer) Run(ctx context.Context) {
	collector := identity.ActivityCollector{UDP: o.UDP}
	for {
		snapshot := collector.Collect()
		// Cap serialized API retention as well as row/process counts. Never return an
		// old success as current after a failure or oversized snapshot.
		if b, err := json.Marshal(snapshot); err != nil || len(b) > 3*1024*1024 {
			snapshot.Rows = nil
			snapshot.Processes = nil
			snapshot.Complete = false
			snapshot.Error = "Snapshot exceeded 3 MiB response budget"
		}
		o.mu.Lock()
		o.snapshot = snapshot
		o.mu.Unlock()
		timer := time.NewTimer(o.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (o *Observer) Snapshot() identity.ActivitySnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()
	snapshot := o.snapshot
	if !snapshot.Collected.IsZero() && time.Since(snapshot.Collected) > o.interval+5*time.Second {
		snapshot.Rows = nil
		snapshot.Processes = nil
		snapshot.Complete = false
		snapshot.Error = "Collection overdue; old activity withheld"
	}
	return snapshot
}
