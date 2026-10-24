package accounting

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func historyFixture(t *testing.T) (*History, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h, err := openHistory(filepath.Join(dir, "history.db"), New(), "daemon-one", false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	h.now = func() time.Time { return at }
	t.Cleanup(func() { h.Close() })
	return h, &at
}
func historySample(h *History, at time.Time, seq uint64, up uint64, uid uint32) Snapshot {
	return Snapshot{Version: 1, Epoch: h.epoch, Sequence: decimal(seq), StartedAt: at.Add(-time.Hour), SampledAt: &at, Partial: true, Attribution: "sampled-owner", Sources: []Source{{TCP, "active", "sampled"}, {UDP, "unavailable", "no collector"}}, Entries: []Entry{{ID: strings.Repeat("a", 64), UID: uid, Application: Application{"app-a", "rev-a", "native", "Synthetic alpha"}, Source: TCP, Uploaded: decimal(up), Downloaded: "0", FirstObservedAt: at.Add(-time.Hour), LastObservedAt: at, Partial: true}}, Unattributed: []Total{{TCP, "0", "0"}, {UDP, "0", "0"}}}
}
func enableHistory(t *testing.T, h *History) {
	t.Helper()
	yes := true
	if _, err := h.Configure(HistoryOptions{&yes, 7, h.settings.Revision}); err != nil {
		t.Fatal(err)
	}
}
func readHistory(t *testing.T, h *History, uid uint32, admin bool) HistorySnapshot {
	t.Helper()
	v, err := h.Query(HistoryQuery{Range: "24h", Source: TCP}, uid, admin)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestHistoryOptInAtomicReplayAndRegression(t *testing.T) {
	h, now := historyFixture(t)
	h.record(historySample(h, *now, 1, 100, 1000))
	if len(readHistory(t, h, 1000, false).Entries) != 0 {
		t.Fatal("recorded while disabled")
	}
	enableHistory(t, h)
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 2, 110, 1000))
	if len(readHistory(t, h, 1000, false).Points) != 0 {
		t.Fatal("baseline backfilled")
	}
	*now = now.Add(time.Minute)
	s := historySample(h, *now, 3, 140, 1000)
	h.record(s)
	h.record(s)
	v := readHistory(t, h, 1000, false)
	if len(v.Entries) != 1 || v.Entries[0].Uploaded != "30" {
		t.Fatal(v)
	}
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 4, 130, 1000))
	if h.lastErr == nil {
		t.Fatal("regression accepted")
	}
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 5, 150, 1000))
	v = readHistory(t, h, 1000, false)
	if v.Entries[0].Uploaded != "40" {
		t.Fatal("rebound inflated", v)
	}
	// Fail after bucket writes, before checkpoint: the complete transaction rolls back.
	if _, err := h.db.Exec("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON checkpoint BEGIN SELECT RAISE(ABORT,'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	s = historySample(h, *now, 6, 170, 1000)
	h.record(s)
	if h.lastErr == nil {
		t.Fatal("injection did not fail")
	}
	if readHistory(t, h, 1000, false).Entries[0].Uploaded != "40" {
		t.Fatal("partial transaction visible")
	}
	h.db.Exec("DROP TRIGGER reject_checkpoint")
	h.record(s)
	if readHistory(t, h, 1000, false).Entries[0].Uploaded != "60" {
		t.Fatal("retry duplicated/lost bytes")
	}
}
func TestHistoryProjectionDisableRestartAndExactValues(t *testing.T) {
	h, now := historyFixture(t)
	enableHistory(t, h)
	h.record(historySample(h, *now, 1, 0, 1000))
	*now = now.Add(time.Minute)
	s := historySample(h, *now, 2, 9007199254740993, 1000)
	s.Unattributed[0].Uploaded = "7"
	h.record(s)
	own := readHistory(t, h, 1000, false)
	if own.Entries[0].Uploaded != "9007199254740993" {
		t.Fatal(own)
	}
	if len(readHistory(t, h, 2000, false).Entries) != 0 {
		t.Fatal("foreign UID leak")
	}
	if _, err := h.Query(HistoryQuery{Range: "24h", Source: TCP, Unattributed: true}, 1000, false); err == nil {
		t.Fatal("global history exposed")
	}
	yes, err := h.Query(HistoryQuery{Range: "24h", Source: TCP, Unattributed: true}, 0, true)
	if err != nil || len(yes.Entries) != 0 || len(yes.Points) != 1 || yes.Points[0].Uploaded != "7" {
		t.Fatal(yes, err)
	}
	off := false
	if _, err = h.Configure(HistoryOptions{&off, 7, h.settings.Revision}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 3, 9007199254741993, 1000))
	enableHistory(t, h)
	h.record(historySample(h, *now, 4, 9007199254741993, 1000))
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 5, 9007199254742000, 1000))
	if readHistory(t, h, 1000, false).Entries[0].Uploaded != "9007199254741000" {
		t.Fatal("disabled interval backfilled")
	}
	// Close and reopen with a genuinely new ledger; old rows remain, raw counters reset.
	path := h.owner.Name()
	h.Close()
	h.cancel = func() {}
	h.db = nil
	next, err := openHistory(path, New(), "daemon-two", false)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.now = func() time.Time { return *now }
	if len(readHistory(t, next, 1000, false).Entries) != 1 {
		t.Fatal("restart erased history")
	}
	if err = next.recordLocked(historySample(h, *now, 6, 9007199254749999, 1000)); err == nil {
		t.Fatal("old epoch accepted")
	}
	next.record(historySample(next, *now, 1, 100, 1000))
	*now = now.Add(time.Minute)
	next.record(historySample(next, *now, 2, 105, 1000))
	if readHistory(t, next, 1000, false).Entries[0].Uploaded != "9007199254741005" {
		t.Fatal("new epoch inflated")
	}
}
func TestHistoryRetentionRebinAndPrivateStore(t *testing.T) {
	h, now := historyFixture(t)
	enableHistory(t, h)
	h.record(historySample(h, *now, 1, 0, 1000))
	for i := 1; i <= 7; i++ {
		*now = now.Add(6 * time.Minute)
		h.record(historySample(h, *now, uint64(i+1), uint64(i*10), 1000))
	}
	v, err := h.Query(HistoryQuery{Range: "30d", Source: TCP}, 1000, false)
	if err != nil || v.ResolutionSeconds != 7200 || len(v.Points) > 2 || v.Entries[0].Uploaded != "70" {
		t.Fatal(v, err)
	}
	*now = now.Add(8 * 24 * time.Hour)
	h.record(historySample(h, *now, 10, 70, 1000))
	if len(readHistory(t, h, 1000, false).Entries) != 0 {
		t.Fatal("expired data readable")
	}
	var count int
	h.db.QueryRow("SELECT count(*) FROM buckets").Scan(&count)
	if count != 0 {
		t.Fatal("expired data not pruned")
	}
	if _, err = openHistory(h.owner.Name(), New(), "other", false); err == nil {
		t.Fatal("two writers")
	}
	bad := filepath.Join(filepath.Dir(h.owner.Name()), "symlink.db")
	os.Symlink(h.owner.Name(), bad)
	if _, err = openHistory(bad, New(), "other", false); err == nil {
		t.Fatal("symlink followed")
	}
	unsafe := filepath.Join(filepath.Dir(h.owner.Name()), "public.db")
	os.WriteFile(unsafe, nil, 0644)
	if _, err = openHistory(unsafe, New(), "other", false); err == nil {
		t.Fatal("public file adopted")
	}
	future := filepath.Join(filepath.Dir(h.owner.Name()), "future.db")
	db, err := sql.Open("sqlite3", future)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("PRAGMA user_version=9")
	db.Close()
	os.Chmod(future, 0600)
	if _, err = openHistory(future, New(), "other", false); err == nil {
		t.Fatal("future schema accepted")
	}
}
func TestHistorySettingsCASAndEpochCatalogBound(t *testing.T) {
	h, now := historyFixture(t)
	enableHistory(t, h)
	yes := true
	if _, err := h.Configure(HistoryOptions{&yes, 7, "1"}); err == nil {
		t.Fatal("stale settings replayed")
	}
	h.record(historySample(h, *now, 1, 0, 1000))
	tx, _ := h.db.Begin()
	for i := 0; i < HistoryMaxEpochs; i++ {
		_, err := tx.Exec("INSERT INTO epochs VALUES(?,?,?)", strings.Repeat("f", 30)+fmtHex(i), "old", now.Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
	}
	tx.Commit()
	// Epochs without buckets are intentionally pruned, so bind retained dummy rows.
	var first Entry = historySample(h, *now, 1, 0, 1000).Entries[0]
	doc, _ := json.Marshal(first)
	h.db.Exec("INSERT INTO entries VALUES(?,?,?,?)", first.ID, 1000, TCP, string(doc))
	rows, _ := h.db.Query("SELECT epoch FROM epochs")
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		h.db.Exec("INSERT INTO buckets VALUES(?,?,?,?,?,?)", now.Unix()/300*300, id, first.ID, "1", "0", 0)
	}
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 2, 1, 1000))
	if !h.limited {
		t.Fatal("epoch bound not enforced", h.lastErr)
	}
}
func fmtHex(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(i>>4)&15], digits[i&15]})
}
func TestHistoryCatalogCapacityRecoveryAndSaturatedRebin(t *testing.T) {
	h, now := historyFixture(t)
	enableHistory(t, h)
	h.record(historySample(h, *now, 1, 0, 1000))
	epoch := strings.Repeat("e", 32)
	h.db.Exec("INSERT INTO epochs VALUES(?,?,?)", epoch, "prior", now.Format(time.RFC3339Nano))
	tx, err := h.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxEntries; i++ {
		id := strings.Repeat("0", 60) + fmtHex(i>>8) + fmtHex(i&255)
		e := historySample(h, *now, 1, 0, 1000).Entries[0]
		e.ID = id
		doc, _ := json.Marshal(e)
		if _, err = tx.Exec("INSERT INTO entries VALUES(?,?,?,?)", id, 1000, TCP, string(doc)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("INSERT INTO buckets VALUES(?,?,?,?,?,?)", now.Unix()/300*300, epoch, id, "1", "0", 0); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 2, 10, 1000))
	if !h.limited {
		t.Fatal("identity catalog exceeded", h.lastErr)
	}
	*now = now.Add(8 * 24 * time.Hour)
	h.record(historySample(h, *now, 3, 20, 1000))
	if h.lastErr != nil {
		t.Fatal(h.lastErr)
	}
	if len(readHistory(t, h, 1000, false).Entries) != 0 {
		t.Fatal("expired cumulative bytes resurrected")
	}
	*now = now.Add(6 * time.Minute)
	h.record(historySample(h, *now, 4, 30, 1000))
	v := readHistory(t, h, 1000, false)
	if len(v.Entries) != 1 || v.Entries[0].Uploaded != "10" {
		t.Fatal("capacity did not recover", v)
	}
	// Multiple committed buckets/epochs rebin with exact saturation, never float64.
	id := v.Entries[0].ID
	at := (now.Unix()/7200+1)*7200 + 600
	h.db.Exec("UPDATE buckets SET up=?,at=?", decimal(^uint64(0)), at)
	h.db.Exec("INSERT INTO buckets VALUES(?,?,?,?,?,?)", at+300, h.epoch, id, "1", "0", 0)
	*now = time.Unix(at+1200, 0).UTC()
	sum, err := h.Query(HistoryQuery{Range: "30d", Source: TCP}, 1000, false)
	if err != nil || len(sum.Points) != 1 || sum.Points[0].Uploaded != "18446744073709551615" || sum.Points[0].Flags&4 == 0 {
		t.Fatal(sum, err)
	}
}

func TestHistoryDiskLimitRollbackAndRecovery(t *testing.T) {
	h, now := historyFixture(t)
	enableHistory(t, h)
	h.record(historySample(h, *now, 1, 0, 1000))
	var pages, limited int
	if err := h.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", pages)).Scan(&limited); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	s := historySample(h, *now, 2, 1, 1000)
	for i := 0; i < 256; i++ {
		e := s.Entries[0]
		e.ID = fmt.Sprintf("%064x", i+1)
		e.Application.Key = fmt.Sprintf("synthetic-%d", i)
		s.Entries = append(s.Entries, e)
	}
	h.record(s)
	if !h.limited {
		t.Fatal("SQLite full did not become explicit capacity", h.lastErr)
	}
	if len(readHistory(t, h, 1000, false).Entries) != 0 {
		t.Fatal("full transaction partially committed")
	}
	if err := h.db.QueryRow("PRAGMA max_page_count=8192").Scan(&limited); err != nil {
		t.Fatal(err)
	}
	h.record(s)
	v := readHistory(t, h, 1000, false)
	if h.lastErr != nil || len(v.Entries) != 257 {
		t.Fatal(v, h.lastErr)
	}
	for _, e := range v.Entries {
		if e.Uploaded != "1" {
			t.Fatal("recovery counted twice", e)
		}
	}
}
func TestHistoryCrashUncommittedRestart(t *testing.T) {
	if path := os.Getenv("FLOWGATE_HISTORY_CRASH_CHILD"); path != "" {
		h, err := openHistory(path, New(), "crashed-child", false)
		if err != nil {
			os.Exit(41)
		}
		tx, err := h.db.Begin()
		if err != nil {
			os.Exit(41)
		}
		if _, err = tx.Exec("UPDATE buckets SET up='999999'"); err != nil {
			os.Exit(41)
		}
		os.Exit(42)
	}
	h, now := historyFixture(t)
	enableHistory(t, h)
	h.record(historySample(h, *now, 1, 0, 1000))
	*now = now.Add(time.Minute)
	h.record(historySample(h, *now, 2, 10, 1000))
	path := h.owner.Name()
	h.Close()
	h.db = nil
	child := exec.Command(os.Args[0], "-test.run=^TestHistoryCrashUncommittedRestart$")
	child.Env = append(os.Environ(), "FLOWGATE_HISTORY_CRASH_CHILD="+path)
	err := child.Run()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatal("child did not reach uncommitted crash", err)
	}
	next, err := openHistory(path, New(), "after-crash", false)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	next.now = func() time.Time { return *now }
	v := readHistory(t, next, 1000, false)
	if len(v.Entries) != 1 || v.Entries[0].Uploaded != "10" {
		t.Fatal("uncommitted bytes survived", v)
	}
	next.record(historySample(next, *now, 1, 100, 1000))
	*now = now.Add(time.Minute)
	next.record(historySample(next, *now, 2, 125, 1000))
	if readHistory(t, next, 1000, false).Entries[0].Uploaded != "35" {
		t.Fatal("restart baseline inflated totals")
	}
}
