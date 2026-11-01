package udpaccount

import (
	"flowgate/internal/identity"
	"strings"
	"testing"
	"time"
)

func TestTracingSkipDiagnosticsDoNotManufactureUsage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skips   *uint64
		partial bool
		reason  string
	}{
		{"unknown", nil, true, "Tracing-skip diagnostics unavailable"},
		{"zero", skipPointer(0), false, ""},
		{"missed", skipPointer(7), true, "Possible undercount: 7 skipped tracing runs across all socket families; UDP operations and missing bytes are unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := identity.UDPSnapshot{State: "active", Collected: time.Now(), TracingSkipped: tc.skips, Rows: map[string]identity.UDPCount{"registered": {Uploaded: 1200}}}
			state.Reason = sampleReason(state)
			m := &Manager{status: Status{State: "active"}, run: &session{state: state}}
			status := m.Status()
			if status.Partial != tc.partial || tc.reason != "" && !strings.Contains(status.Reason, tc.reason) {
				t.Fatal(status)
			}
			if m.run.snapshot().Rows["registered"].Uploaded != 1200 {
				t.Fatal("diagnostics estimated bytes")
			}
		})
	}
}
func skipPointer(v uint64) *uint64 { return &v }
