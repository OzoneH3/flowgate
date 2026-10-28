package uploadshape

import (
	"encoding/json"
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestDirectionalCapValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		up, down uint64
		valid    bool
	}{
		{"upload", 8_000_000, 0, true}, {"download", 0, 8_000_000, true},
		{"both", 8_000_000, 16_000_000, true}, {"empty", 0, 0, false},
		{"small download", 0, 999_999, false}, {"large download", 8_000_000, 1_000_000_001, false},
		{"invalid upload with download", 1, 8_000_000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfig(Config{Enabled: true, Caps: []Cap{{Application: "native-key", BitsPerSecond: tc.up, DownloadBitsPerSecond: tc.down}}})
			if (err == nil) != tc.valid {
				t.Fatalf("validation error=%v valid=%v", err, tc.valid)
			}
		})
	}
	if err := validateConfig(Config{Enabled: true, Caps: []Cap{{Application: "native-key", BitsPerSecond: 8_000_000}, {Application: "native-key", DownloadBitsPerSecond: 8_000_000}}}); err == nil {
		t.Fatal("directions must share one application cap")
	}
}

type directionTransport struct{ calls []map[string]any }

func (d *directionTransport) Call(q map[string]any) (json.RawMessage, error) {
	d.calls = append(d.calls, q)
	return json.RawMessage(`{"status":"Partial"}`), nil
}
func (d *directionTransport) Close() error { return nil }
func TestDirectionalBindingTransportAndExpiry(t *testing.T) {
	m := newManager(Options{})
	d := &directionTransport{}
	row := censusRows(1)[0]
	h := hint{flow: identity.Flow{Protocol: row.Protocol, Local: row.Local, Remote: row.Remote}, app: "0:native-key", cookie: row.Cookie}
	m.cfg = Config{Enabled: true, Caps: []Cap{{Application: "native-key", DownloadBitsPerSecond: 8_000_000}}}
	if !m.bind(d, h, 1) {
		t.Fatal("download-only skipped")
	}
	q := d.calls[0]
	if q["rate"] != uint64(0) || q["download_rate"] != uint64(8_000_000) || q["expected_cookie"] != row.Cookie || q["expected_app"] != h.app {
		t.Fatal(q)
	}
	m.cfg.Caps[0].BitsPerSecond = 16_000_000
	if !m.bind(d, h, 1) {
		t.Fatal("bidirectional skipped")
	}
	q = d.calls[1]
	if q["rate"] != uint64(16_000_000) || q["download_rate"] != uint64(8_000_000) {
		t.Fatal(q)
	}
	m.cfg.Caps[0].DownloadBitsPerSecond = 0
	if !m.bind(d, h, 1) {
		t.Fatal("upload-only skipped")
	}
	q = d.calls[2]
	if q["rate"] != uint64(16_000_000) || q["download_rate"] != uint64(0) {
		t.Fatal(q)
	}
	if m.bind(d, h, 2) || len(d.calls) != 3 {
		t.Fatal("stale version reached controller")
	}
	m.snap.Status = "Active"
	m.snap.VerifiedUntil = time.Now().Add(-time.Second)
	m.snap.Kernel = &KernelStatus{Covered: 1, Bindings: []Binding{{Download: true, Covered: true}}}
	got := m.Snapshot()
	if !got.CoverageExpired || got.Kernel.Bindings[0].Covered || !got.Kernel.Bindings[0].Download {
		t.Fatal(got)
	}
}
