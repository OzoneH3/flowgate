package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"flowgate/internal/uploadshape"
)

const maxShapingDocument = 2 << 20

// ShapingPreferences uses the same private database and writer lock as rules.
// The optional table is compatible with older readers of the rule database.
func (s *Store) ShapingPreferences() (p uploadshape.Preferences, err error) {
	_, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS shaping_preferences (
		id INTEGER PRIMARY KEY CHECK(id=1),
		document TEXT NOT NULL CHECK(length(CAST(document AS BLOB)) <= 2097152)
	)`)
	if err != nil {
		return p, err
	}
	var doc string
	err = s.db.QueryRow("SELECT document FROM shaping_preferences WHERE id=1").Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if len(doc) > maxShapingDocument {
		return p, fmt.Errorf("oversized shaping preferences")
	}
	d := json.NewDecoder(strings.NewReader(doc))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return p, err
	}
	if d.Decode(new(any)) != io.EOF {
		return p, fmt.Errorf("trailing shaping preferences data")
	}
	return p, nil
}

// SaveShapingPreferences atomically replaces the desired policy, including
// removals. On commit failure the manager keeps its previous version and policy.
func (s *Store) SaveShapingPreferences(p uploadshape.Preferences) error {
	doc, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO shaping_preferences(id, document) VALUES(1, ?)
		ON CONFLICT(id) DO UPDATE SET document=excluded.document`, string(doc))
	return err
}
