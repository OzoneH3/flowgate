package store

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"time"
)

// LoadCurrent archives expired and positively obsolete native rules before
// startup publishes policy. Only the exclusive daemon writer may run cleanup.
// Archived JSON stays in the private database; it is never evaluated as policy.
func (s *Store) LoadCurrent(now time.Time) ([]policy.Rule, error) {
	return s.loadCurrent(now, identity.ObsoleteNativeRevision)
}

func (s *Store) loadCurrent(now time.Time, obsolete func(string, string, string, uint32) bool) ([]policy.Rule, error) {
	if s.owner == nil {
		return nil, fmt.Errorf("rule cleanup requires exclusive writer")
	}
	rules, err := s.Load()
	if err != nil {
		return nil, err
	}
	type removed struct {
		rule   policy.Rule
		reason string
	}
	var archived []removed
	kept := make([]policy.Rule, 0, len(rules))
	for _, r := range rules {
		reason := ""
		if !r.Expires.IsZero() && !now.Before(r.Expires) {
			reason = "expired"
		} else if r.Preset == nil && !r.Filter.AllUIDs && obsolete(r.Executable, r.Filter.Application, r.Filter.Revision, r.Filter.UID) {
			reason = "replaced executable; no old process found"
		}
		if reason == "" {
			kept = append(kept, r)
		} else {
			archived = append(archived, removed{r, reason})
		}
	}
	if len(archived) == 0 {
		return kept, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("CREATE TABLE IF NOT EXISTS archived_rules (id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, document TEXT NOT NULL, reason TEXT NOT NULL, archived_at TEXT NOT NULL)"); err != nil {
		return nil, err
	}
	for _, a := range archived {
		doc, err := json.Marshal(a.rule)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec("INSERT INTO archived_rules(rule_id,document,reason,archived_at) VALUES(?,?,?,?)", a.rule.ID, string(doc), a.reason, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		if _, err = tx.Exec("DELETE FROM rules WHERE id=?", a.rule.ID); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return kept, nil
}
