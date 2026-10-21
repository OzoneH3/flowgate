// Package store persists only remembered rules. Pending packets and Once grants
// are intentionally never serialized.
package store

import (
	"database/sql"
	"encoding/json"
	"flowgate/internal/policy"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"
)

type Store struct {
	db    *sql.DB
	owner *os.File
}

func Open(path string) (*Store, error) {
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return nil, fmt.Errorf("rule database must be a private regular file")
	}
	// Precreate without following a symlink. The caller supplies a private owned directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		f.Close()
	} else if !os.IsExist(err) {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "file:"+url.PathEscape(path)+"?_busy_timeout=2000&_synchronous=FULL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version != 0 && version != 1 {
		return fail(fmt.Errorf("unsupported rule database version %d", version))
	}
	if version == 0 {
		var n int
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&n); err != nil {
			return fail(err)
		}
		if n != 0 {
			return fail(fmt.Errorf("unversioned nonempty database"))
		}
		if _, err = db.Exec("BEGIN; CREATE TABLE rules(id TEXT PRIMARY KEY, document TEXT NOT NULL CHECK(length(document)<=16384)); PRAGMA user_version=1; COMMIT;"); err != nil {
			return fail(err)
		}
	}
	var check string
	if err = db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fail(fmt.Errorf("rule database integrity failure: %s: %v", check, err))
	}
	s := &Store{db: db}
	if _, err = s.Load(); err != nil {
		return fail(err)
	}
	return s, nil
}

// OpenExclusive is for authoritative privileged writers. Lock the database
// inode, not an independently replaceable state path; Open remains for readers
// and existing test tools. All daemon writer entrypoints use this method.
func OpenExclusive(path string) (*Store, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	owner := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		owner.Close()
		return nil, fmt.Errorf("another daemon owns this rule database: %w", err)
	}
	s, err := Open(path)
	if err != nil {
		owner.Close()
		return nil, err
	}
	s.owner = owner
	return s, nil
}
func (s *Store) Close() error {
	err := s.db.Close()
	if s.owner != nil {
		s.owner.Close()
	}
	return err
}
func (s *Store) Load() ([]policy.Rule, error) {
	rows, err := s.db.Query("SELECT id, document FROM rules ORDER BY id LIMIT 257")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.Rule{}
	for rows.Next() {
		var id, doc string
		if err = rows.Scan(&id, &doc); err != nil {
			return nil, err
		}
		if len(doc) > 16384 {
			return nil, fmt.Errorf("oversized stored rule")
		}
		var r policy.Rule
		decoder := json.NewDecoder(strings.NewReader(doc))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&r); err != nil {
			return nil, err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, fmt.Errorf("trailing stored data")
		}
		// Earlier device-dependent file stamps match again after a reboot.
		policy.MigrateRevisions(&r)
		if err = r.Validate(); err != nil {
			return nil, err
		}
		if id != r.ID || r.Created.IsZero() {
			return nil, fmt.Errorf("invalid stored rule identity/creation time")
		}
		out = append(out, r)
	}
	if len(out) > 256 {
		return nil, fmt.Errorf("too many stored rules")
	}
	return out, rows.Err()
}

// Replace commits the complete small rule set atomically, before a verdict may
// depend on it. A failed transaction leaves both policy and disk unchanged.
func (s *Store) Replace(rules []policy.Rule) error {
	if len(rules) > 256 {
		return fmt.Errorf("too many rules")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM rules"); err != nil {
		return err
	}
	for _, r := range rules {
		if err = r.Validate(); err != nil {
			return err
		}
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(b) > 16384 || r.Created.IsZero() {
			return fmt.Errorf("invalid stored rule")
		}
		if _, err = tx.Exec("INSERT INTO rules VALUES(?,?)", r.ID, string(b)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReadRules does not create state or acquire a writer; the boot guard uses only
// validated preset protocol scopes from an existing root-owned database.
func ReadRules(path string) ([]policy.Rule, error) {
	db, err := sql.Open("sqlite3", "file:"+url.PathEscape(path)+"?mode=ro&_busy_timeout=2000")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	s := &Store{db: db}
	return s.Load()
}
