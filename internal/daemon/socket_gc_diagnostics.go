package daemon

import (
	"flowgate/internal/socketgrant"
	"runtime/debug"
	"time"
)

// Snapshot runtime's bounded recent GC pause history, not a forced collection.
// Pause ends are wall timestamps; the adjacent wall/BOOTTIME samples permit
// correlation with renewal records, subject to wall-clock adjustments. Runtime
// pause history is process-wide, not attributable to an individual renewal.
func socketGCDiagnostics() map[string]any {
	var gc debug.GCStats
	debug.ReadGCStats(&gc)
	wall := time.Now()
	boot := socketgrant.BootNow()
	n := min(len(gc.Pause), len(gc.PauseEnd), 256)
	rows := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		rows[i] = map[string]any{"end_wall": gc.PauseEnd[i], "duration_ns": gc.Pause[i].Nanoseconds()}
	}
	return map[string]any{"sample_wall": wall, "sample_boot_ns": boot, "cycles_total": gc.NumGC, "pause_total_ns": gc.PauseTotal.Nanoseconds(), "recent_pauses": rows, "history_bounded": true}
}
