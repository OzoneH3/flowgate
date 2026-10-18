package hostfirewall

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/readiness"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func configuredProtection(t *testing.T) *Evaluation {
	t.Helper()
	dir := t.TempDir()
	m := NewEvaluation(context.Background(), daemon.New(time.Second), filepath.Join(dir, "run"), filepath.Join(dir, "api.sock"), filepath.Join(dir, "db"))
	m.desiredPath = filepath.Join(dir, "desired.json")
	m.desiredMode = "monitoring"
	return m
}
func TestContinuousDesiredDurabilityCASAndEvaluationExclusion(t *testing.T) {
	m := configuredProtection(t)
	// Refuse before privileged setup. A retry must not renew or replace the mode.
	m.probe = func() []readiness.Check {
		return []readiness.Check{{ID: "fixture", Status: readiness.Blocked, Code: "fixture_refusal"}}
	}
	s, err := m.ProtectionStart("", strings.Repeat("a", 32), "both")
	if err != nil {
		t.Fatal(err)
	}
	waitEvaluation(t, m, "degraded")
	s = m.ProtectionStatus()
	if s.DesiredMode != "both" || s.State != "degraded" || !m.Status().StopsAt.IsZero() || m.Status().DurationSeconds != 0 {
		t.Fatal(s, m.Status())
	}
	b, _ := os.ReadFile(m.desiredPath)
	if !strings.Contains(string(b), `"both"`) {
		t.Fatal(string(b))
	}
	if _, err = m.ProtectionStart(s.ID, strings.Repeat("a", 32), "incoming"); err == nil {
		t.Fatal("nonce rebound")
	}
	if _, err = m.Start(s.ID, strings.Repeat("b", 32)); err == nil {
		t.Fatal("evaluation bypassed desired protection")
	}
	if _, err = m.ProtectionStop("wrong"); err == nil {
		t.Fatal("stale stop")
	}
	if m.ProtectionStatus().DesiredMode != "both" {
		t.Fatal("stale stop persisted")
	}
}
func TestContinuousInvalidConfigNeverFallsBackToMonitoring(t *testing.T) {
	m := configuredProtection(t)
	if err := os.WriteFile(m.desiredPath, []byte(`{"schema":2,"mode":"both"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureProtection(m.desiredPath); err == nil {
		t.Fatal("corrupt desired state ignored")
	}
	if _, err := m.ProtectionStart("", strings.Repeat("a", 32), "outgoing"); err == nil {
		t.Fatal("unsupported profile")
	}
}
