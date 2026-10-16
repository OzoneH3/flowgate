package store

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableRules(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "rules-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "rules.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := policy.Rule{Schema: 2, ID: "r", Action: "allow", Created: now, Expires: now.Add(time.Second), Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "incoming", Protocol: "udp", LocalPort: 80, RemoteAddress: "127.0.0.1"}}
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err := s.Load()
	if err != nil || len(rs) != 1 || !rs[0].Expires.Equal(r.Expires) {
		t.Fatal(rs, err)
	}
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9000")
	a := identity.Attribution{Application: &identity.Application{Key: "app", Revision: "rev"}, Owners: []identity.Process{{UID: 1000}}}
	if action, _, _ := policy.Evaluate(rs, f, a, now.Add(2*time.Second)); action != "ask" {
		t.Fatal("expiry reset")
	}
	r.Expires = time.Time{}
	r.Disabled = true
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	rs, err = s.Load()
	if err != nil || !rs[0].Disabled || !rs[0].Expires.IsZero() {
		t.Fatal(rs, err)
	}
	if action, _, _ := policy.Evaluate(rs, f, a, now); action != "ask" {
		t.Fatal("disabled rule used")
	}
	bad := r
	bad.Schema = 999
	if err = s.Replace([]policy.Rule{bad}); err == nil {
		t.Fatal("unsupported rule saved")
	}
	rs, _ = s.Load()
	if len(rs) != 1 || rs[0].Schema != 2 {
		t.Fatal("failed transaction lost policy")
	}
	if _, err = s.db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if bad, err := Open(path); err == nil {
		bad.Close()
		t.Fatal("unsupported database opened")
	}
}
