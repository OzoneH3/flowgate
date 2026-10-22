package daemon

import (
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestEditorRejectsOlderScopeWhileTemporaryOverrideIsLive(t *testing.T) {
	e, _, _, now := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	old := policy.Rule{Schema: 2, ID: "persistent", Version: 1, Created: now.Add(-time.Hour), Executable: "/opt/tool", Action: "block", Filter: policy.Filter{Application: "key", Revision: "v1", UID: 1000, Direction: "incoming", Protocol: "tcp", RemoteAddress: "*"}}
	temporary := old
	temporary.ID = "temporary"
	temporary.Created = *now
	temporary.Filter.Revision = "v2"
	temporary.Expires = now.Add(time.Hour)
	temporary.Action = "allow"
	if err := e.SetRules([]policy.Rule{old, temporary}); err != nil {
		t.Fatal(err)
	}
	candidate := old
	candidate.Action = "ask"
	if _, _, err := e.EditRule(old.ID, "", &old.Version, candidate, 1000, false, true); err == nil || !strings.Contains(err.Error(), "duplicate scope") {
		t.Fatal("expected live override conflict", err)
	}
	if got := e.Rules(1000, false); len(got) != 2 || got[0].Action != "block" {
		t.Fatal("rejected edit mutated policy", got)
	}
}
