package store

import (
	"encoding/json"
	"flowgate/internal/policy"
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
	expired.Expires = now
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
