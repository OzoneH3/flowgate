package store

import "fmt"

// Zero seconds means use the daemon's startup default.
func (s *Store) DecisionTimeout() (seconds int, revision uint64, err error) {
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS decision_timeout (
		id INTEGER PRIMARY KEY CHECK(id=1),
		seconds INTEGER NOT NULL CHECK(seconds=0 OR seconds BETWEEN 2 AND 60),
		revision INTEGER NOT NULL CHECK(revision>0)
	); INSERT OR IGNORE INTO decision_timeout VALUES(1,0,1)`)
	if err == nil {
		err = s.db.QueryRow("SELECT seconds,revision FROM decision_timeout WHERE id=1").Scan(&seconds, &revision)
	}
	return
}

func (s *Store) SaveDecisionTimeout(seconds int, expected uint64) error {
	r, err := s.db.Exec("UPDATE decision_timeout SET seconds=?,revision=revision+1 WHERE id=1 AND revision=?", seconds, expected)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("decision timeout settings changed")
	}
	return nil
}
