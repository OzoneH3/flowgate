package store

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"log"
	"time"
)

const cleanupBudget = 250 * time.Millisecond

// Recently expired rules remain stored (but do not match) through clock corrections.
const expiryArchiveGrace = 7 * 24 * time.Hour

// LoadCurrent archives expired and positively obsolete native rules before
// startup publishes policy. Only the exclusive daemon writer may run cleanup.
// Archived JSON stays in the private database; it is never evaluated as policy.
func (s *Store) LoadCurrent(now time.Time) ([]policy.Rule, error) {
	return s.loadCurrent(now, identity.NewObsoleteNativeChecker())
}

func (s *Store) loadCurrent(now time.Time, obsolete func(string, string, string, uint32) bool) ([]policy.Rule, error) {
	if s.owner == nil {
		return nil, fmt.Errorf("rule cleanup requires exclusive writer")
	}
	rules, err := s.Load()
	if err != nil {
		return nil, err
	}
	// One worker and one total budget, not one goroutine per path. A stuck
	// remote filesystem cannot prevent READY, and a timed-out census never
	// mutates the database later. All uncertain rules are retained.
	results := make(chan map[string]bool, 1)
	cancel := make(chan struct{})
	defer close(cancel)
	go func() {
		found := map[string]bool{}
		for _, r := range rules {
			select {
			case <-cancel:
				return
			default:
			}
			if r.Preset == nil && !r.Filter.AllUIDs && obsolete(r.Executable, r.Filter.Application, r.Filter.Revision, r.Filter.UID) {
				found[r.ID] = true
			}
		}
		results <- found
	}()
	var obsoleteRules map[string]bool
	timer := time.NewTimer(cleanupBudget)
	defer timer.Stop()
	select {
	case obsoleteRules = <-results:
	case <-timer.C:
	}
	type removed struct {
		rule   policy.Rule
		reason string
	}
	var archived []removed
	kept := make([]policy.Rule, 0, len(rules))
	for _, r := range rules {
		reason := ""
		if !r.Expires.IsZero() && !now.Before(r.Expires.Add(expiryArchiveGrace)) {
			reason = "expired"
		} else if obsoleteRules[r.ID] {
			reason = "replaced executable; no old process found"
		}
		if reason == "" {
			kept = append(kept, r)
		} else {
			archived = append(archived, removed{r, reason})
		}
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
	// Preserve at least the latest complete startup batch (at most 256
	// rules, 16 KiB each). Older recovery history is bounded to 512 entries.
	pruned, err := tx.Exec("DELETE FROM archived_rules WHERE id NOT IN (SELECT id FROM archived_rules ORDER BY id DESC LIMIT 512)")
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if n, _ := pruned.RowsAffected(); n > 0 {
		if _, err := s.db.Exec("VACUUM"); err != nil {
			log.Printf("FlowGate: rule archive committed; space reclamation deferred: %v", err)
		}
	}
	return kept, nil
}
