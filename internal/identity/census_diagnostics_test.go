package identity

import (
	"context"
	"encoding/json"
	diagnostics "flowgate/internal/serveprofile"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiagnosticCaptureRetainsCookieComparisonWithoutChangingRefusal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLOWGATE_PROFILE_DIR", dir)
	t.Setenv("FLOWGATE_PROFILE_MANUAL", "1")
	ctx, cancel := context.WithCancel(context.Background())
	stop := diagnostics.StartFromEnvironment(ctx, nil)
	defer func() { cancel(); stop() }()
	if err := diagnostics.StartManual(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for diagnostics.ManualStatus()["state"] != "running" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if diagnostics.ManualStatus()["state"] != "running" {
		t.Fatal(diagnostics.ManualStatus())
	}
	// Same synthetic cookie-replacement regression, now while capture is active.
	TestWineAdmissionInitialCookieCannotSurviveReplacement(t)
	cancel()
	stop()
	raw, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Evidence []struct {
			Kind        string          `json:"kind"`
			Comparisons map[string]bool `json:"comparisons"`
			Result      string          `json:"result"`
			Initial     struct {
				Sockets []Socket `json:"sockets"`
			} `json:"initial"`
			Fresh struct {
				Sockets []Socket `json:"sockets"`
			} `json:"fresh"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Evidence) != 1 {
		t.Fatal("missing evidence", string(raw))
	}
	e := out.Evidence[0]
	if e.Kind != "wine_bookends" || e.Comparisons["same_sockets"] || e.Result != ReasonRuntimeOwnershipChanged || e.Initial.Sockets[0].Cookie != "old" || e.Fresh.Sockets[0].Cookie != "replacement" {
		t.Fatal(e)
	}
}
