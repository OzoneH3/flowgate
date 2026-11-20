package daemon

import (
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetainedRecheckKeepsOneLinkedRequestOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, action, source string
	}{
		{"user Allow", "allow", "user"},
		{"rule Allow", "allow", "rule"},
		{"identity lost while pending", "block", "identity_changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newQueueFixture(t)
			e := x.e
			*x.now = time.Now()
			path := filepath.Join(t.TempDir(), "decisions.db")
			writer, err := decisionlog.Open(path, e.Generation, e.Mode, true)
			if err != nil {
				t.Fatal(err)
			}
			e.Decisions = writer
			defer func() {
				if e.Decisions != nil {
					e.Decisions.Close()
				}
			}()

			const uid = 1000
			p := x.proc(42, "10", uid)
			f, first := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
			e.RecordPacketOutcome(first, VerdictHeld, nil)
			affected := first
			if tc.source == "rule" {
				f, affected = x.flow(t, p, "tcp", "10.0.0.1:40002", "192.0.2.2:443", "b")
				e.RecordPacketOutcome(affected, VerdictHeld, nil)
			}
			key := f.Local.String() + ">" + f.Remote.String()
			if tc.action == "allow" {
				options := RememberOptions{Fields: &RememberFields{}}
				revision := e.Zones.Revision
				preview, err := e.PreviewDecision(e.Generation, first.ID, "allow", "persistent", "any", revision, uid, false, options)
				if err != nil {
					t.Fatal(err)
				}
				_, saved, _, settled, err := e.DecideReviewedSettled(e.Generation, first.ID, "allow", "persistent", "any", revision, preview.Token, uid, false, options)
				if err != nil {
					t.Fatal(err)
				}
				if tc.source == "rule" && (len(settled) != 1 || settled[0].ID != affected.ID || settled[0].Rule != saved.ID || settled[0].State != "allowed") {
					t.Fatalf("expected the original sibling request to be settled, got %+v", settled)
				}
				x.ended[key] = true
				for i := 0; i < 2; i++ {
					if state := e.RetainedState(affected.ID, affected.Attribution.Fingerprint); state != "drop" {
						t.Fatalf("recheck %d: verdict %q, wanted drop", i, state)
					}
				}
			} else {
				x.ended[key] = true
				if _, err := e.Decide(affected.ID, "allow", "once", uid, false); err == nil {
					t.Fatal("approved a request that lost identity while pending")
				}
			}

			err = writer.Close()
			e.Decisions = nil
			if err != nil {
				t.Fatal(err)
			}
			reader, err := decisionlog.Open(path, e.Generation, e.Mode, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			all, err := reader.Query(decisionlog.Query{}, uid, false)
			if err != nil {
				t.Fatal(err)
			}
			var pending decisionlog.Record
			for _, row := range all.Records {
				if row.Kind == decisionlog.KindPending && row.RequestID == affected.ID {
					pending = row
				}
			}
			if pending.ID == "" {
				t.Fatal("missing original pending record")
			}
			final, err := reader.Outcome(pending.ID, uid, false)
			if err != nil || final.RequestID != affected.ID || final.Decision == nil ||
				final.Decision.Action != tc.action || final.Decision.Source != tc.source {
				t.Fatalf("opening the original pending record: %+v, %v", final, err)
			}
			page, err := reader.Query(decisionlog.Query{Action: "block", Source: "identity_changed"}, uid, false)
			if err != nil || len(page.Records) != 1 {
				t.Fatalf("expected one visible recheck Block: %+v, %v", page.Records, err)
			}
			block := page.Records[0]
			if block.Revalidation == nil || block.Decision.Reason == "" {
				t.Fatalf("rejection evidence missing: %+v", block)
			}
			if tc.action == "allow" && (block.ID == final.ID || block.RequestID != "" ||
				block.RelatedRequestID != affected.ID || !strings.Contains(block.Decision.Reason, "no visible matching socket")) {
				t.Fatalf("expected a separate recheck with the original request and reason: %+v, %+v", block, block.Decision)
			}
			if tc.action == "block" && (block.ID != final.ID || block.RelatedRequestID != "") {
				t.Fatal("a request that first lost identity while pending must finalize as Block")
			}
			var queryErr *decisionlog.QueryError
			if _, err := reader.Outcome(pending.ID, uid+1, false); !errors.As(err, &queryErr) || queryErr.Code != "not_found" {
				t.Fatalf("foreign caller could resolve the pending record: %v", err)
			}
			foreign, err := reader.Query(decisionlog.Query{Action: "block", Source: "identity_changed"}, uid+1, false)
			if err != nil || len(foreign.Records) != 0 {
				t.Fatalf("foreign caller's audit records: %+v, %v", foreign.Records, err)
			}
		})
	}
}

func TestRetainedRecheckPreservesChangedBindingEvidence(t *testing.T) {
	for _, gone := range []bool{false, true} {
		e, f, a, _ := fixture()
		e.Timeout = time.Minute
		a.Sockets = []identity.Socket{{Inode: 1, Cookie: "original"}}
		v := e.Observe(f, "original")
		if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil {
			t.Fatal(err)
		}
		if gone {
			*a = identity.Attribution{Status: "unidentified", Reason: "no visible matching socket"}
		} else {
			a.Sockets = []identity.Socket{{Inode: 2, Cookie: "replacement"}}
			a.Fingerprint = "replacement"
		}
		if got := e.RetainedState(v.ID, v.Attribution.Fingerprint); got != "drop" {
			t.Fatal(got)
		}
		for _, event := range e.events {
			if event.ID != v.ID {
				continue
			}
			if event.Revalidation == nil {
				t.Fatal("retained rejection lost recheck evidence")
			}
			found := false
			for _, change := range event.Revalidation.Changes {
				if change.Field == "socket_inode_cookie" {
					found = true
				}
			}
			if !found {
				t.Fatal("socket replacement/closure not reported", event.Revalidation)
			}
			record := e.baseRecord(event, "final")
			if record.Revalidation == nil {
				t.Fatal("decision log omitted recheck")
			}
		}
	}
}

func TestRetainedRecheckDeadlineDoesNotClaimIdentityChanged(t *testing.T) {
	e, f, a, now := fixture()
	e.Timeout = time.Minute
	v := e.Observe(f, "original")
	if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	current := *a
	e.Resolve = func(identity.Flow) identity.Attribution { *now = now.Add(time.Hour); return current }
	if got := e.RetainedState(v.ID, v.Attribution.Fingerprint); got != "drop" {
		t.Fatal(got)
	}
	for _, event := range e.events {
		if event.ID == v.ID && event.Revalidation != nil {
			t.Fatal("deadline incorrectly reported as identity change")
		}
	}
}
