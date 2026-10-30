package identity

import (
	"golang.org/x/sys/unix"
	"sync"
)

// Observation-only, bounded prototype diagnostics. These elapsed stages are not
// CPU time. Post-slot includes session setup, table serialization and validation.
const renewalPhaseLimit = 4096

type renewalPhase struct {
	Status        string `json:"status,omitempty"`
	InitialSource string `json:"initial_source,omitempty"`
	Sequence      uint64 `json:"sequence"`
	Flow          string `json:"flow"`
	Start         uint64 `json:"start_boot_ns"`
	InitialDone   uint64 `json:"initial_done_boot_ns"`
	SlotRequested uint64 `json:"slot_requested_boot_ns,omitempty"`
	SlotAcquired  uint64 `json:"slot_acquired_boot_ns,omitempty"`
	SessionDone   uint64 `json:"session_done_boot_ns,omitempty"`
	Finished      uint64 `json:"finished_boot_ns"`
	GroupSize     int    `json:"group_size"`
}
type renewalPhaseLog struct {
	mu    sync.Mutex
	rows  []renewalPhase
	count uint64
}

func renewalBootNow() uint64 {
	var t unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &t) != nil {
		return 0
	}
	return uint64(t.Nano())
}
func (l *renewalPhaseLog) add(row renewalPhase) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rows == nil {
		l.rows = make([]renewalPhase, renewalPhaseLimit)
	}
	row.Sequence = l.count
	l.rows[l.count%renewalPhaseLimit] = row
	l.count++
}
func (l *renewalPhaseLog) snapshot() ([]renewalPhase, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	start := uint64(0)
	if l.count > renewalPhaseLimit {
		start = l.count - renewalPhaseLimit
	}
	out := make([]renewalPhase, 0, l.count-start)
	for i := start; i < l.count; i++ {
		out = append(out, l.rows[i%renewalPhaseLimit])
	}
	return out, start
}
