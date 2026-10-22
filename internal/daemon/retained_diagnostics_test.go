package daemon

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

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
