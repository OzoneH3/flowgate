package store

import (
	"encoding/json"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupArchivesAtomically(t *testing.T) {
	s, err := OpenExclusive(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	rule := policy.Rule{Schema: 2, ID: "old", Created: now.Add(-time.Hour), Action: "block", Filter: policy.Filter{Application: "app", Revision: "old", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	expired := rule
	expired.ID = "expired"
	expired.Expires = now.Add(-expiryArchiveGrace)
	keep := rule
	keep.ID = "keep"
	keep.Filter.Revision = "current"
	keep.Disabled = true
	if err := s.Replace([]policy.Rule{rule, expired, keep}); err != nil {
		t.Fatal(err)
	}
	obsolete := func(_, _, rev string, _ uint32) bool { return rev == "old" }
	// A persistence failure must not lose either active or archived policy.
	if _, err := s.db.Exec("CREATE TRIGGER refuse_cleanup BEFORE DELETE ON rules BEGIN SELECT RAISE(ABORT, 'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.loadCurrent(now, obsolete); err == nil {
		t.Fatal("expected failed transaction")
	}
	if rules, err := s.Load(); err != nil || len(rules) != 3 {
		t.Fatal("lost rules", rules, err)
	}
	if _, err := s.db.Exec("DROP TRIGGER refuse_cleanup"); err != nil {
		t.Fatal(err)
	}
	rules, err := s.loadCurrent(now, obsolete)
	if err != nil || len(rules) != 1 || rules[0].ID != "keep" || !rules[0].Disabled {
		t.Fatal(rules, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM archived_rules").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	var doc string
	if err := s.db.QueryRow("SELECT document FROM archived_rules WHERE rule_id='old'").Scan(&doc); err != nil {
		t.Fatal(err)
	}
	var recovered policy.Rule
	if err := json.Unmarshal([]byte(doc), &recovered); err != nil || recovered.Action != "block" || recovered.Filter.Revision != "old" {
		t.Fatal(doc, err)
	}
	if _, err := s.loadCurrent(now, obsolete); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM archived_rules").Scan(&count); err != nil || count != 2 {
		t.Fatal("duplicate archives", count, err)
	}
}

func TestCleanupRequiresWriter(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.LoadCurrent(time.Now()); err == nil {
		t.Fatal("nonexclusive cleanup allowed")
	}
}

func TestCleanupTimeoutRetainsRulesAndLateResultsCannotDelete(t *testing.T) {
	s, err := OpenExclusive(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := policy.Rule{Schema: 2, ID: "keep", Created: time.Now(), Action: "allow", Filter: policy.Filter{Application: "app", Revision: "v1", UID: 1000, Direction: "outgoing", Protocol: "tcp"}}
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	release, finished := make(chan struct{}), make(chan struct{})
	start := time.Now()
	got, err := s.loadCurrent(time.Now(), func(string, string, string, uint32) bool { <-release; close(finished); return true })
	if err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("blocked startup on filesystem census")
	}
	close(release)
	<-finished
	got, err = s.Load()
	if err != nil || len(got) != 1 {
		t.Fatal("late census changed policy", got, err)
	}
}

func TestCleanupExpiryGrace(t *testing.T) {
	s, err := OpenExclusive(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	r := policy.Rule{Schema: 2, ID: "recent", Created: now.Add(-time.Hour), Expires: now.Add(-2 * time.Hour), Action: "allow", Filter: policy.Filter{Application: "app", Revision: "v1", UID: 1000, Direction: "outgoing", Protocol: "tcp"}}
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	no := func(string, string, string, uint32) bool { return false }
	got, err := s.loadCurrent(now, no)
	if err != nil || len(got) != 1 {
		t.Fatal("recent expiry was permanently removed", got, err)
	}
	got, err = s.loadCurrent(now.Add(expiryArchiveGrace), no)
	if err != nil || len(got) != 0 {
		t.Fatal("old expiry not archived", got, err)
	}
}

func TestArchiveBoundAndOversizedLegacyDatabaseRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.db")
	s, err := OpenExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	no := func(string, string, string, uint32) bool { return false }
	if _, err = s.loadCurrent(time.Now(), no); err != nil {
		t.Fatal(err)
	}
	// Emulate an old unbounded archive exceeding the former 16 MiB file guard.
	_, err = s.db.Exec("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1200) INSERT INTO archived_rules(rule_id,document,reason,archived_at) SELECT 'old',printf('%016000d',0),'expired','old' FROM n")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	st, err := os.Stat(path)
	if err != nil || st.Size() <= 16<<20 {
		t.Fatal("fixture did not exceed former cap", st, err)
	}
	s, err = OpenExclusive(path)
	if err != nil {
		t.Fatal("legacy archive prevented recovery", err)
	}
	defer s.Close()
	if _, err = s.loadCurrent(time.Now(), no); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM archived_rules").Scan(&count); err != nil || count != 512 {
		t.Fatal(count, err)
	}
	st, err = os.Stat(path)
	if err != nil || st.Size() >= 16<<20 {
		t.Fatal("archive pages were not reclaimed", st, err)
	}
}
