package uploadshape

import (
	"errors"
	"flowgate/internal/identity"
	"time"
)

const DiscoveryCapacity = 4096
const DiscoveryScanBudget = 512

// DiscoveryProgress describes examination of a historical hint set, never
// application-wide coverage. Cap edits deliberately do not reset its cursor.
type DiscoveryProgress struct {
	NextRetry     time.Time `json:"next_retry"`
	Generation    uint64    `json:"generation"`
	Capacity      int       `json:"capacity"`
	Retained      int       `json:"retained_rows"`
	Cursor        int       `json:"cursor"`
	Pending       int       `json:"pending_rows"`
	Incomplete    bool      `json:"incomplete"`
	Overloaded    bool      `json:"overloaded"`
	LastError     string    `json:"last_error,omitempty"`
	DumpMillis    int64     `json:"dump_duration_ms"`
	LastDump      time.Time `json:"last_dump"`
	LastProgress  time.Time `json:"last_progress"`
	LastCompleted time.Time `json:"last_completed"`
}

type discoverySnapshot struct {
	rows       []identity.Socket
	retryDelay time.Duration
	view       DiscoveryProgress
}

func (d *discoverySnapshot) reset() {
	d.rows = nil
	d.retryDelay = 0
	d.view = DiscoveryProgress{Capacity: DiscoveryCapacity}
}

// load rejects every incomplete dump, including its partial prefix. The caller
// retries on a subsequent tick; it never interprets an error as an empty census.
func (d *discoverySnapshot) load(rows []identity.Socket, err error, start time.Time) error {
	d.rows = nil
	d.view.Capacity = DiscoveryCapacity
	d.view.Cursor, d.view.Retained, d.view.Pending = 0, 0, 0
	d.view.LastDump = time.Now()
	d.view.DumpMillis = time.Since(start).Milliseconds()
	if len(rows) > DiscoveryCapacity {
		err = identity.ErrSocketCensusCapacity
	}
	d.view.Incomplete = err != nil
	d.view.Overloaded = errors.Is(err, identity.ErrSocketCensusCapacity)
	d.view.LastError = ""
	if err != nil {
		d.view.LastError = err.Error()
		if d.retryDelay == 0 {
			d.retryDelay = time.Second
		} else {
			d.retryDelay *= 2
		}
		if d.retryDelay > 30*time.Second {
			d.retryDelay = 30 * time.Second
		}
		d.view.NextRetry = time.Now().Add(d.retryDelay)
		return err
	}
	d.clearRetry()
	d.rows = append([]identity.Socket(nil), rows...)
	d.view.Generation++
	d.view.Retained, d.view.Pending = len(rows), len(rows)
	if len(rows) == 0 {
		d.view.LastCompleted = time.Now()
	}
	return nil
}

func (d *discoverySnapshot) next() (identity.Socket, bool) {
	if d.view.Cursor >= len(d.rows) {
		return identity.Socket{}, false
	}
	s := d.rows[d.view.Cursor]
	d.view.Cursor++
	d.view.Pending = len(d.rows) - d.view.Cursor
	d.view.LastProgress = time.Now()
	if d.view.Pending == 0 {
		d.view.LastCompleted = d.view.LastProgress
	}
	return s, true
}

func (m *Manager) publishDiscovery(d *discoverySnapshot) {
	m.mu.Lock()
	m.snap.DiscoverySnapshot = d.view
	m.mu.Unlock()
}

func (d *discoverySnapshot) clearRetry() { d.retryDelay = 0; d.view.NextRetry = time.Time{} }
