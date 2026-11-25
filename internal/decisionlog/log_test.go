package decisionlog

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flowgate/internal/store"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Open(path, "gen", "isolated-lab", true)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func rec(uid *uint32, at time.Time, action string) Record {
	r := Record{ID: NewRecordID(), Time: at, Generation: "gen", Mode: "isolated-lab", Kind: KindFinal, PrincipalUID: uid, Flow: &Flow{Direction: "incoming", Protocol: "tcp"}, Decision: &Decision{Action: action, Source: "rule"}, Delivery: "not_observed"}
	if uid != nil {
		r.Application = &Application{Key: fmt.Sprintf("%064x", *uid)}
	}
	return r
}
func u(v uint32) *uint32 { return &v }

// writeNow commits directly (synchronously) for deterministic tests.
func writeNow(t *testing.T, l *Log, rs ...Record) {
	t.Helper()
	if err := l.insert(l.encode(rs)); err != nil {
		t.Fatal(err)
	}
}
func query(t *testing.T, l *Log, raw string, uid uint32, admin bool) Page {
	t.Helper()
	q, err := DecodeQuery(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.Query(q, uid, admin)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMigrationAndRuleStoreIndependence(t *testing.T) {
	dir := t.TempDir()
	rules, err := store.OpenExclusive(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Close()
	l := open(t, filepath.Join(dir, "decisions.db"))
	id := l.ID()
	writeNow(t, l, rec(u(1000), time.Now(), "allow"))
	if _, err := Open(filepath.Join(dir, "decisions.db"), "g", "m", true); err == nil {
		t.Fatal("second owner accepted")
	}
	l.Close()
	// Restart persistence: same identity and records.
	l = open(t, filepath.Join(dir, "decisions.db"))
	if l.ID() != id || len(query(t, l, `{}`, 0, true).Records) != 1 {
		t.Fatal("restart lost log identity or records")
	}
	l.Close()
	// The rule database stays at its own schema version 1.
	db, _ := sql.Open("sqlite3", filepath.Join(dir, "rules.db"))
	var v int
	db.QueryRow("PRAGMA user_version").Scan(&v)
	db.Close()
	if v != 1 {
		t.Fatalf("rule database version changed: %d", v)
	}
	// Unknown versions and unversioned nonempty files are refused.
	bad := filepath.Join(dir, "future.db")
	db, _ = sql.Open("sqlite3", bad)
	db.Exec("PRAGMA user_version=7")
	db.Close()
	os.Chmod(bad, 0600)
	if _, err := Open(bad, "g", "m", true); err == nil {
		t.Fatal("future version accepted")
	}
	other := filepath.Join(dir, "other.db")
	db, _ = sql.Open("sqlite3", other)
	db.Exec("CREATE TABLE x(y)")
	db.Close()
	os.Chmod(other, 0600)
	if _, err := Open(other, "g", "m", true); err == nil {
		t.Fatal("unversioned nonempty database adopted")
	}
	public := filepath.Join(dir, "public.db")
	os.WriteFile(public, nil, 0644)
	if _, err := Open(public, "g", "m", true); err == nil {
		t.Fatal("non-private file accepted")
	}
}

func TestRecordedOutcomeLookup(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	defer l.Close()
	pending := rec(u(1000), time.Now(), "pending")
	pending.Kind, pending.RequestID = KindPending, "attempt"
	final := rec(u(1000), time.Now(), "allow")
	final.RequestID = pending.RequestID
	otherGeneration := final
	otherGeneration.ID, otherGeneration.Generation = NewRecordID(), "another run"

	writeNow(t, l, pending, otherGeneration)
	expectMissing := func(id string, uid uint32, admin bool) {
		t.Helper()
		_, err := l.Outcome(id, uid, admin)
		var qe *QueryError
		if !errors.As(err, &qe) || qe.Code != "not_found" {
			t.Fatalf("lookup %s: %v", id, err)
		}
	}
	expectMissing(pending.ID, 1000, false)
	writeNow(t, l, final)
	newer := make([]Record, 300)
	for i := range newer {
		r := rec(u(1000), time.Now(), "block")
		r.RequestID = fmt.Sprintf("other-%d", i)
		newer[i] = r
	}
	writeNow(t, l, newer...)
	got, err := l.Outcome(pending.ID, 1000, false)
	if err != nil || got.ID != final.ID || got.Decision.Action != "allow" {
		t.Fatalf("wrong final: %+v, %v", got, err)
	}
	expectMissing(pending.ID, 2000, false)
	expectMissing(final.ID, 1000, true)
	expectMissing("pruned", 1000, false)
	for i, owner := range []*uint32{u(2000), nil} {
		p, f := pending, final
		p.ID, f.ID = NewRecordID(), NewRecordID()
		p.RequestID = fmt.Sprintf("visibility-%d", i)
		f.RequestID, f.PrincipalUID = p.RequestID, owner
		writeNow(t, l, p, f)
		expectMissing(p.ID, 1000, false)
		expectMissing(p.ID, 2000, false)
		if got, err := l.Outcome(p.ID, 0, true); err != nil || got.ID != f.ID {
			t.Fatalf("administrator lookup: %+v, %v", got, err)
		}
	}
	duplicate := final
	duplicate.ID = NewRecordID()
	writeNow(t, l, duplicate)
	expectMissing(pending.ID, 0, true)
	for _, field := range []string{"generation", "request_id"} {
		p := pending
		f := final
		p.ID, f.ID = NewRecordID(), NewRecordID()
		if field == "generation" {
			p.Generation, f.Generation = "", ""
		} else {
			p.RequestID, f.RequestID = "", ""
		}
		writeNow(t, l, p, f)
		expectMissing(p.ID, 1000, true)
	}
}

func TestRetentionByAgeAndCount(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	defer l.Close()
	now := time.Now()
	l.now = func() time.Time { return now }
	writeNow(t, l, rec(u(1), now.Add(-MaxAge-time.Hour), "allow"), rec(u(1), now.Add(-MaxAge-time.Minute), "allow"), rec(u(1), now, "allow"))
	h := l.Health(true)
	if h.Retention.Removed != 2 || h.Retention.RemovedThrough != "2" || h.Oldest != "3" {
		t.Fatalf("age pruning: %+v", h)
	}
	batch := make([]Record, MaxRecords+40)
	for i := range batch {
		batch[i] = rec(u(1), now, "block")
	}
	writeNow(t, l, batch...)
	h = l.Health(true)
	if h.Retention.Removed != 2+41 || h.Oldest != "44" {
		t.Fatalf("count pruning: %+v", h)
	}
	var n int
	l.db.QueryRow("SELECT count(*) FROM decisions").Scan(&n)
	if n != MaxRecords {
		t.Fatal("retained", n)
	}
}

func TestStablePaginationWhileRecordsArrive(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	defer l.Close()
	for i := 0; i < 25; i++ {
		writeNow(t, l, rec(u(1000), time.Now(), "allow"))
	}
	first := query(t, l, `{"limit":10}`, 0, true)
	if len(first.Records) != 10 || first.Records[0].Sequence != "25" || !first.HasMore || first.NextBefore != "16" {
		t.Fatalf("%+v", first)
	}
	for i := 0; i < 7; i++ { // new arrivals must not shift older pages
		writeNow(t, l, rec(u(1000), time.Now(), "block"))
	}
	seen := map[string]bool{}
	for _, r := range first.Records {
		seen[r.Sequence] = true
	}
	cursor := first.NextBefore
	for cursor != "" {
		p := query(t, l, `{"limit":10,"before":"`+cursor+`"}`, 0, true)
		for _, r := range p.Records {
			if seen[r.Sequence] {
				t.Fatal("duplicate across pages", r.Sequence)
			}
			seen[r.Sequence] = true
		}
		cursor = p.NextBefore
	}
	if len(seen) != 25 {
		t.Fatal("skipped records", len(seen))
	}
	// Catch-up from the original head returns exactly the arrivals, oldest first.
	up := query(t, l, `{"limit":5,"after":"25"}`, 0, true)
	if len(up.Records) != 5 || up.Records[0].Sequence != "26" || !up.HasMore || up.NextAfter != "30" || up.Order != "oldest_first" {
		t.Fatalf("%+v", up)
	}
	up = query(t, l, `{"limit":5,"after":"30"}`, 0, true)
	if len(up.Records) != 2 || up.HasMore || up.NextAfter != "32" {
		t.Fatalf("%+v", up)
	}
	// Filters are server-side in both directions.
	if p := query(t, l, `{"action":"block","after":"0"}`, 0, true); len(p.Records) != 7 {
		t.Fatal("after filter", len(p.Records))
	}
	if p := query(t, l, `{"action":"allow","limit":100}`, 0, true); len(p.Records) != 25 {
		t.Fatal("before filter", len(p.Records))
	}
}

func TestPrivacyAndAdministratorVisibility(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	defer l.Close()
	mine, foreign, unknown := rec(u(1000), time.Now(), "allow"), rec(u(1001), time.Now(), "block"), rec(nil, time.Now(), "block")
	writeNow(t, l, mine, foreign, unknown)
	l.dropped = 3
	l.write(nil) // gap record
	own := query(t, l, `{}`, 1000, false)
	if own.Scope != "self" || len(own.Records) != 2 || own.Records[1].ID != mine.ID || own.Records[0].Kind != KindGap || own.Records[0].Gap.Dropped != nil {
		t.Fatalf("ordinary projection: %+v", own.Records)
	}
	if !own.Health.CountsWithheld || own.Health.Dropped != 0 {
		t.Fatal("machine counts leaked", own.Health)
	}
	all := query(t, l, `{}`, 1000, true)
	if all.Scope != "machine" || len(all.Records) != 4 || *all.Records[0].Gap.Dropped != 3 {
		t.Fatalf("administrator: %+v", all.Records)
	}
	for _, id := range []string{foreign.ID, unknown.ID, "missing"} {
		var q *QueryError
		if _, err := l.Get(id, 1000, false); !errors.As(err, &q) || q.Code != "not_found" {
			t.Fatal("foreign/unknown record visible", id, err)
		}
	}
	if r, err := l.Get(unknown.ID, 0, true); err != nil || r.PrincipalUID != nil {
		t.Fatal("administrator detail", err)
	}
}

func TestOverflowAndStorageFailureReported(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	l.Close()
	// Stand-alone log without a writer: the buffer fills deterministically.
	l2, _ := Open(filepath.Join(t.TempDir(), "e.db"), "gen", "isolated-lab", true)
	l2.sendMu.Lock()
	l2.closed = true
	close(l2.ch)
	l2.sendMu.Unlock()
	<-l2.done
	l2.ch, l2.closed = make(chan Record, 2), false
	for i := 0; i < 5; i++ {
		l2.Record(rec(u(1000), time.Now(), "allow"))
	}
	if h := l2.Health(true); h.Dropped != 3 || h.State != "degraded" || h.Buffered != 2 {
		t.Fatalf("overflow not reported: %+v", h)
	}
	batch := []Record{<-l2.ch, <-l2.ch}
	l2.failWrite = func() error { return errors.New("disk full") }
	l2.write(batch)
	h := l2.Health(true)
	if h.WriteFailures != 1 || h.LostInFailures != 2 || h.LastError != "disk full" || h.State != "degraded" {
		t.Fatalf("storage failure not reported: %+v", h)
	}
	l2.failWrite = nil
	l2.write(nil)
	p := query(t, l2, `{}`, 0, true)
	if len(p.Records) != 1 || p.Records[0].Kind != KindGap || *p.Records[0].Gap.Dropped != 5 {
		t.Fatalf("gap record missing: %+v", p.Records)
	}
	l2.db.Close()
	l2.owner.Close()
	// A log that could not open drops and reports, never blocks.
	u := Unavailable(errors.New("no space"))
	u.Record(rec(nil, time.Now(), "block"))
	if h := u.Health(true); h.State != "unavailable" || h.Dropped != 1 {
		t.Fatal(h)
	}
	if _, err := u.Query(Query{}, 0, true); err == nil {
		t.Fatal("query on unavailable log")
	}
}

func TestAsyncRecordingFlushesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	l := open(t, path)
	for i := 0; i < 300; i++ { // more than one batch
		l.Record(rec(u(1000), time.Now(), "allow"))
	}
	l.Close()
	l = open(t, path)
	defer l.Close()
	if h := l.Health(true); h.Newest != "300" {
		t.Fatal("records lost at Close", h)
	}
}

func TestQueryValidation(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "d.db"))
	defer l.Close()
	for raw, code := range map[string]string{
		`{"limit":101}`:              "invalid_request",
		`{"limit":-1}`:               "invalid_request",
		`{"before":"1","after":"2"}`: "invalid_request",
		`{"before":"abc"}`:           "invalid_cursor",
		`{"before":"0"}`:             "invalid_cursor",
		`{"after":"01"}`:             "invalid_cursor",
		`{"direction":"sideways"}`:   "invalid_request",
		`{"source":"guess"}`:         "invalid_request",
		`{"application":"x"}`:        "invalid_request",
		`{"unknown":1}`:              "invalid_request",
		`{"since":"2026-01-02T00:00:00Z","until":"2026-01-01T00:00:00Z"}`: "invalid_request",
	} {
		_, err := DecodeQuery(json.RawMessage(raw))
		var q *QueryError
		if !errors.As(err, &q) || q.Code != code {
			t.Fatal(raw, err)
		}
	}
	q, _ := DecodeQuery(json.RawMessage(`{"log_id":"other"}`))
	var qe *QueryError
	if _, err := l.Query(q, 0, true); !errors.As(err, &qe) || qe.Code != "invalid_cursor" {
		t.Fatal("foreign log_id accepted", err)
	}
	if p := query(t, l, `{"limit":0}`, 0, true); len(p.Records) != 0 || p.Health.LogID != l.ID() || len(p.Limitations) == 0 {
		t.Fatal("health-only page", p)
	}
}

// A storage stall fills a bounded queue; packet-side enqueue still completes.
// The gate makes this deterministic rather than relying on a slow filesystem.
func TestSlowFailingWriterNeverWaitsInRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	l := open(t, path)
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0 // writer goroutine only
	l.failWrite = func() error {
		calls++
		if calls == 1 {
			close(entered)
			<-release
			return errors.New("injected stalled transaction failure")
		}
		return nil
	}
	for i := 0; i < BatchSize; i++ {
		l.Record(rec(u(1000), time.Now(), "allow"))
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not enter gate")
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < BufferSize+7; i++ {
			l.Record(rec(u(1000), time.Now(), "block"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("enqueue blocked behind storage")
	}
	if h := l.Health(true); h.Buffered != BufferSize || h.Dropped != 7 {
		close(release)
		t.Fatal(h)
	}
	close(release)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = open(t, path)
	defer l.Close()
	p := query(t, l, `{"after":"0","limit":100}`, 0, true)
	if len(p.Records) == 0 || p.Records[0].Gap == nil || *p.Records[0].Gap.Dropped != BatchSize+7 {
		t.Fatal("known failed batch and overflow not persisted", p.Records)
	}
	h := l.Health(true)
	if h.Dropped != 0 || h.LostInFailures != 0 || h.WriteFailures != 0 || h.CrashLossBoundMS != nil || h.FlushIntervalMS != 1000 {
		t.Fatal("volatile health must reset; no crash loss bound", h)
	}
	if h.Newest != "1025" {
		t.Fatal("only gap plus queued records should survive", h.Newest)
	}
}

func TestQueryCorrelatesExactConnectionAndRuleVersion(t *testing.T) {
	l := open(t, filepath.Join(t.TempDir(), "decisions.db"))
	defer l.Close()
	now := time.Now()
	build := func(uid uint32, request, remote string) Record {
		r := rec(u(uid), now, "allow")
		r.Flow.Local, r.Flow.Remote = "[::1]:8000", remote
		r.RequestID = request
		r.Decision.Rule = &RuleSnapshot{ID: "app-rule", Version: "18446744073709551615"}
		return r
	}
	target := build(1000, "attempt-1", "[::1]:9000")
	writeNow(t, l, target, build(2000, "attempt-1", "[::1]:9000"),
		build(1000, "attempt-2", "[::1]:9000"), build(1000, "attempt-1", "[::1]:9001"))
	raw := `{"protocol":"tcp","local":"[0:0:0:0:0:0:0:1]:8000","remote":"[::1]:9000","request_id":"attempt-1","generation":"gen","rule_id":"app-rule","rule_version":"18446744073709551615"}`
	result := query(t, l, raw, 1000, false)
	if len(result.Records) != 1 || result.Records[0].ID != target.ID {
		t.Fatal(result.Records)
	}
	if result := query(t, l, raw, 0, true); len(result.Records) != 2 {
		t.Fatal(result.Records)
	}
	for _, invalid := range []string{`{"remote":"localhost:80"}`, `{"rule_version":"1"}`, `{"protocol":"icmp"}`} {
		if _, err := DecodeQuery(json.RawMessage(invalid)); err == nil {
			t.Fatal("accepted", invalid)
		}
	}
}
