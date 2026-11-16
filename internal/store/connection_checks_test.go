package store

import (
	"path/filepath"
	"testing"
)

func TestConnectionChecksPersistentDefaultAndCAS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	d, r, err := s.ConnectionChecks()
	if err != nil || d || r != 1 {
		t.Fatal(d, r, err)
	}
	if err = s.SaveConnectionChecks(true, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveConnectionChecks(false, 1); err == nil {
		t.Fatal("stale CAS accepted")
	}
	s.Close()
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, r, err = s.ConnectionChecks()
	if err != nil || !d || r != 2 {
		t.Fatal(d, r, err)
	}
}
