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
	// Cached verdicts are dropped now. Re-settling awaiting requests needs their
	// ownership, so it runs as its own operation instead of resolving inside
	// whichever caller (packet, snapshot, API) noticed the revision change.
	// Requests simply keep waiting meanwhile; nothing is admitted by deferral.
	e.resetCachedLocked("network classification revision changed")
	if e.prefetched == nil && !e.settling {
		e.settleLaterLocked() // noticed outside an interaction operation
	}
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

// PublishNetworkZones serializes kernel revocation with zone publication and
// renewal publication. commit must only publish the supplied immutable snapshot;
// it must not call back into Engine or acquire a zone publication mutex. The
// caller holds that publication mutex before entering this method.
//
// A failed accelerator cannot roll back an observed network change. Existing
// kernel grants retain their absolute deadlines, while all future publication
// stops and the failure is returned for status reporting.
func (e *Engine) PublishNetworkZones(next identity.NetworkZones, commit func()) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var revokeErr error
	if next.Revision != e.Zones.Revision {
		revokeErr = e.revokeSocketGrantsLocked()
		if revokeErr != nil && e.socketAuthorization != nil {
			e.socketAuthorization.disabled = true
			e.socketAuthorization.failure = revokeErr
		}
	}
	commit()
	if next.Revision == e.Zones.Revision {
		return revokeErr
	}
	e.Zones = next
	for _, v := range e.events {
		v.Flow.NetworkScope = next.ClassifyFlow(v.Flow)
	}
	e.resetCachedLocked("network classification revision changed")
	if e.prefetched == nil && !e.settling {
		e.settleLaterLocked()
	}
	return revokeErr
}

// NetworkZonePublisher installs the required publication transaction before a
// dynamic zone source is exposed to optional kernel authorization.
func (e *Engine) NetworkZonePublisher() func(identity.NetworkZones, func()) error {
	e.mu.Lock()
	e.zonePublisherInstalled = true
	e.mu.Unlock()
	return e.PublishNetworkZones
}
