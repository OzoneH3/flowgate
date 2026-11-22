// Package monitor collects read-only snapshots independently of API polling.
package monitor

import (
	"context"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/serveprofile"
	"sync"
	"time"
)

type Observer struct {
	// Observed consumes each completed, annotated, size-bounded collection once.
	// It is configured before Run and is never invoked by API polling.
	Observed         func(identity.ActivitySnapshot)
	Annotate         func(*identity.ActivitySnapshot)
	AnalyzeRuntime   func(*identity.ActivitySnapshot)
	InitiationEvents func([]identity.Socket) identity.InitiationEvents
	Zones            identity.NetworkZones
	ZoneSource       func() identity.NetworkZones
	UDP              func() identity.UDPSnapshot
	mu               sync.RWMutex
	snapshot         identity.ActivitySnapshot
	interval         time.Duration
}

func New(interval time.Duration) *Observer {
	return &Observer{Zones: identity.DefaultNetworkZones(), interval: interval, snapshot: identity.ActivitySnapshot{Error: "Initial collection in progress", Complete: false}}
}
func (o *Observer) Run(ctx context.Context) {
	collector := identity.ActivityCollector{UDP: o.UDP, Zones: o.Zones, InitiationEvents: o.InitiationEvents}
	for {
		if o.ZoneSource != nil {
			collector.Zones = o.ZoneSource()
		}
		var snapshot identity.ActivitySnapshot
		serveprofile.Work(ctx, "activity_collection", func() { snapshot = collector.Collect() })
		o.publish(snapshot)
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

// ConnectionSample is independent of publishing, byte accounting and policy.
func (o *Observer) ConnectionSample(localPort uint16) identity.ConnectionSample {
	return identity.CollectConnectionSample(localPort, o.AnalyzeRuntime)
}

func (o *Observer) publish(snapshot identity.ActivitySnapshot) {
	if o.Annotate != nil {
		serveprofile.Work(context.Background(), "activity_wine", func() { o.Annotate(&snapshot) })
	}
	// Cap serialized API retention as well as row/process counts. Never return an
	// old success as current after a failure or oversized snapshot.
	if b, err := json.Marshal(snapshot); err != nil || len(b) > 3*1024*1024 {
		snapshot.Rows = nil
		snapshot.Processes = nil
		snapshot.Complete = false
		snapshot.Error = "Snapshot exceeded 3 MiB response budget"
	}
	if o.Observed != nil {
		serveprofile.Work(context.Background(), "accounting", func() { o.Observed(snapshot) })
	}
	o.mu.Lock()
	o.snapshot = snapshot
	o.mu.Unlock()
}
