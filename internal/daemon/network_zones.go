package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

const AutomaticNetworkZoneCapability = "automatic-network-zones-v1"
const ZoneMigrationCapability = "zone-migration-v1"

// Caller holds mu. The source publishes immutable generations. Network changes
// invalidate cached admissions, not pending deadlines or completed receipts.
func (e *Engine) refreshZonesLocked() {
	if e.ZoneSource == nil {
		return
	}
	next := e.ZoneSource()
	if next.Revision == e.Zones.Revision {
		return
	}
	e.Zones = next
	for _, v := range e.events {
		v.Flow.NetworkScope = next.ClassifyFlow(v.Flow)
	}
	e.resetCachedLocked("network classification revision changed")
}
func (e *Engine) CurrentZones() identity.NetworkZones {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshZonesLocked()
	return e.Zones
}
func (e *Engine) bindZoneModel(r *policy.Rule) {
	if r.Filter.NetworkZone != "" && e.Zones.Model == identity.AutomaticZoneModel {
		r.Schema = 6
		r.Filter.ZoneModel = identity.AutomaticZoneModel
	}
}
func ClassifyActivity(a identity.ActivitySnapshot, z identity.NetworkZones) identity.ActivitySnapshot {
	a.Rows = append(a.Rows[:0:0], a.Rows...)
	for i := range a.Rows {
		a.Rows[i].NetworkScope = z.SocketScope(a.Rows[i].Socket)
	}
	return a
}
