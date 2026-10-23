package decisionlog

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAttributionReasonPersistedWithoutChangingPrincipalProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.db")
	l := open(t, path)
	for i, code := range []string{"", "no_socket_observed", "future_reason"} {
		r := rec(u(1000), time.Now().Add(time.Duration(i)*time.Millisecond), "block")
		r.Attribution = &Attribution{Status: "unidentified", Reason: "original evidence", ReasonCode: code}
		writeNow(t, l, r)
	}
	unknown := rec(nil, time.Now(), "block")
	unknown.Attribution = &Attribution{Status: "unidentified", Reason: "unowned evidence", ReasonCode: "multiple_candidates"}
	writeNow(t, l, unknown)
	l.Close()
	l = open(t, path)
	defer l.Close()
	if p := query(t, l, `{}`, 1001, false); len(p.Records) != 0 {
		t.Fatal("foreign principal evidence leaked")
	}
	own := query(t, l, `{}`, 1000, false)
	if len(own.Records) != 3 {
		t.Fatalf("user projection: %d", len(own.Records))
	}
	seen := map[string]bool{}
	for _, r := range own.Records {
		if r.Attribution == nil || r.Attribution.Reason != "original evidence" {
			t.Fatalf("evidence changed: %+v", r)
		}
		seen[r.Attribution.ReasonCode] = true
	}
	for _, code := range []string{"", "no_socket_observed", "future_reason"} {
		if !seen[code] {
			t.Fatalf("lost code %q", code)
		}
	}
	if p := query(t, l, `{}`, 0, true); len(p.Records) != 4 {
		t.Fatal("admin missing unowned evidence")
	}
}
