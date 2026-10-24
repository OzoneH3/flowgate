package daemon

import (
	"flowgate/internal/accounting"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUsageHistoryAuthenticatedSettingsAndCompanion(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	e := New(time.Second)
	ledger := accounting.New()
	history, err := accounting.OpenHistory(filepath.Join(dir, "usage.db"), ledger, e.Generation)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Close()
	e.UsageHistory = history
	e.SaveRules = func([]policy.Rule) error { return nil }
	primary := filepath.Join(dir, "p.sock")
	p, err := Serve(primary, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	companion := filepath.Join(dir, "r.sock")
	r, err := Serve(companion, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	q := accounting.HistoryQuery{Range: "24h", Source: accounting.TCP}
	snap, err := Call(primary, Request{Version: 1, Operation: "usage-history", Generation: e.Generation, HistoryQuery: &q})
	if err != nil || snap.Error != "" || snap.UsageHistory == nil || snap.UsageHistory.Settings.Enabled {
		t.Fatal(snap, err)
	}
	yes := true
	options := accounting.HistoryOptions{Enabled: &yes, RetentionDays: 7, ExpectedRevision: "1"}
	write := Request{Version: 1, Operation: "usage-history-configure", Generation: e.Generation, HistoryOptions: &options}
	denied, err := Call(companion, write)
	if denied.ErrorCode != "forbidden" {
		t.Fatal("readonly settings accepted", denied, err)
	}
	changed, err := Call(primary, write)
	if os.Geteuid() != 0 {
		if changed.ErrorCode != "forbidden" {
			t.Fatal("ordinary user configured machine history", changed)
		}
		return
	}
	if err != nil || changed.Error != "" || changed.HistorySettings == nil || !changed.HistorySettings.Enabled || changed.HistorySettings.Revision != "2" {
		t.Fatal(changed)
	}
	duplicate, _ := Call(primary, write)
	if duplicate.Error == "" {
		t.Fatal("stale CAS replay accepted")
	}
	write.Generation = "old"
	options.ExpectedRevision = "2"
	stale, _ := Call(primary, write)
	if stale.ErrorCode != "stale_generation" {
		t.Fatal(stale)
	}
	read, _ := Call(companion, Request{Version: 1, Operation: "usage-history", Generation: e.Generation, HistoryQuery: &q})
	if read.Error != "" || read.UsageHistory.Settings.Revision != "2" {
		t.Fatal(read)
	}
	if len(e.rules) != 0 {
		t.Fatal("history changed firewall policy")
	}
}
func TestUsageHistoryUnavailableIsDiagnosticOnly(t *testing.T) {
	e := New(time.Second)
	e.UsageHistory = accounting.UnavailableHistory(os.ErrPermission)
	s, err := e.UsageHistoryRead(e.Generation, accounting.HistoryQuery{Range: "24h", Source: accounting.TCP}, 1000, false)
	if err != nil || s.State != "unavailable" || s.Error != "" || len(s.Entries) != 0 {
		t.Fatal(s, err)
	}
	if _, err = e.UsageHistoryRead("other", accounting.HistoryQuery{}, 0, true); err == nil {
		t.Fatal("generation ignored")
	}
}
