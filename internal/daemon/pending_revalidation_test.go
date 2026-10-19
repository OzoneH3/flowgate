package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestRememberPreviewClosedSocketFinalizesOriginalNotReplacement(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	f.Protocol = "tcp"
	f.Direction = "outgoing"
	a.Sockets = []identity.Socket{{Inode: 1, Cookie: "original"}}
	a.VisibilityComplete = true
	v := e.Observe(f, "original")
	// Process/application identity remains the same; only the socket is replaced.
	a.Sockets = []identity.Socket{{Inode: 2, Cookie: "replacement"}}
	a.Fingerprint = "new-socket"
	_, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{}})
	if err == nil || !strings.Contains(err.Error(), "socket inode/cookie") {
		t.Fatal(err)
	}
	events := e.List(1000, false)
	if len(events) != 1 || events[0].State != "expired" || events[0].Revalidation == nil || events[0].Revalidation.Code != "connection_ended" {
		t.Fatal(events)
	}
	if len(e.rules) != 0 {
		t.Fatal("preview failure saved a rule")
	}
	if _, err = e.Decide(v.ID, "allow", "once", 1000, false); err == nil {
		t.Fatal("dead request admitted")
	}
	if _, err = e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false); err == nil {
		t.Fatal("ended review refreshed")
	}
	fresh := e.Observe(f, "replacement")
	if fresh.ID == v.ID || fresh.State != "awaiting-decision" {
		t.Fatal(fresh)
	}
	p, err := e.PreviewDecision(e.Generation, fresh.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Rule.Filter.Process.IsZero() || p.Rule.Filter.NetworkZone != "" || p.Rule.Filter.Protocol != "*" {
		t.Fatal("application-only Any scope changed", p)
	}
	if _, _, _, err = e.DecideReviewed(e.Generation, fresh.ID, "allow", "persistent", "any", e.Zones.Revision, p.Token, 1000, false, RememberOptions{Fields: &RememberFields{}}); err != nil {
		t.Fatal(err)
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("old packet received replacement approval")
	}
}
func TestRememberPreviewExecutableChangeReportsExactField(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	a.Owners[0].PID = 10
	a.Owners[0].ExecutableRevision = "old"
	v := e.Observe(f, "socket")
	a.Owners = append([]identity.Process{}, a.Owners...)
	a.Owners[0].ExecutableRevision = "new"
	a.Fingerprint = "new"
	if _, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false); err == nil {
		t.Fatal("changed identity accepted")
	}
	for _, c := range e.List(1000, false)[0].Revalidation.Changes {
		if c.Field == "process[10].executable_revision" && c.Before == "old" && c.After == "new" {
			return
		}
	}
	t.Fatal("exact executable change omitted")
}

func TestRememberPreviewDeadlineIsNotCalledIdentityChange(t *testing.T) {
	e, f, a, now := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "original")
	current := *a
	e.Resolve = func(identity.Flow) identity.Attribution { *now = now.Add(2 * time.Minute); return current }
	_, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatal(err)
	}
	for _, event := range e.events {
		if event.ID == v.ID && (event.State != "expired" || event.Revalidation != nil) {
			t.Fatal(event)
		}
	}
}

func TestRememberReviewedSocketClosedBeforeCommitDoesNotSave(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	writes := 0
	e.SaveRules = func([]policy.Rule) error { writes++; return nil }
	a.Sockets = []identity.Socket{{Inode: 1, Cookie: "original"}}
	v := e.Observe(f, "original")
	p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{}})
	if err != nil {
		t.Fatal(err)
	}
	*a = identity.Attribution{Status: "unidentified", Reason: "no visible matching socket"}
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.Token, 1000, false, RememberOptions{Fields: &RememberFields{}}); err == nil {
		t.Fatal("dead socket committed")
	}
	if writes != 0 || len(e.rules) != 0 {
		t.Fatal("closed request wrote a rule")
	}
	if status, err := e.DecisionStatus(e.Generation, p.Token, 1000, false); err != nil || status.State == "committed" {
		t.Fatal(status, err)
	}
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("dead packet approved")
	}
}
