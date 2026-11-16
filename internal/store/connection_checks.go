package store

import "fmt"

// This independent table travels with the rule database's existing backup and
// recovery transaction. Older daemons ignore it and retain their enabled default.
func (s *Store) ConnectionChecks() (disabled bool, revision uint64, err error) {
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS connection_checks (id INTEGER PRIMARY KEY CHECK(id=1), disabled INTEGER NOT NULL CHECK(disabled IN (0,1)), revision INTEGER NOT NULL CHECK(revision>0)); INSERT OR IGNORE INTO connection_checks VALUES(1,0,1)`)
	if err != nil {
		return
	}
	err = s.db.QueryRow("SELECT disabled,revision FROM connection_checks WHERE id=1").Scan(&disabled, &revision)
	return
}
func (s *Store) SaveConnectionChecks(disabled bool, expected uint64) error {
	r, err := s.db.Exec("UPDATE connection_checks SET disabled=?,revision=revision+1 WHERE id=1 AND revision=?", disabled, expected)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("connection check settings changed")
	}
	return nil
}
