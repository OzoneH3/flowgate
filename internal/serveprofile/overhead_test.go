package serveprofile

import (
	"testing"
	"time"
)

func BenchmarkDiagnosticStages(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			if enabled {
				active.Store(&session{from: time.Now(), until: time.Now().Add(time.Hour)})
			}
			defer active.Store(nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := Begin(WineRuntimeQuery)
				Count(WineHintHit, 1)
				s.End()
			}
		})
	}
}
