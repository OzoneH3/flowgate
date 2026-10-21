package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"testing"
	"time"
)

func TestRootScopeMigrationAndPreview(t *testing.T) {
	e := New(time.Second)
	uid := uint32(1000)
	e.AdministratorUID = &uid
	a := identity.Application{Kind: "native", Executable: "/usr/bin/tool", Revision: "v1"}
	a.Key = identity.ApplicationKey(uid, a)
	r := policy.Rule{ID: "saved", Version: 1, Schema: 2, Executable: a.Executable, Created: time.Now(), Action: "allow", Filter: policy.Filter{Application: a.Key, Revision: a.Revision, UID: uid, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	var saved []policy.Rule
	e.SaveRules = func(rs []policy.Rule) error { saved = append([]policy.Rule{}, rs...); return nil }
	if err := e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 || saved[0].RootApplication != identity.ApplicationKey(0, a) || saved[0].Version != 2 {
		t.Fatal("migration not persisted", saved)
	}
	if err := e.SetRules(saved); err != nil {
		t.Fatal(err)
	}
	rootApp := a
	rootApp.Key = identity.ApplicationKey(0, a)
	flow, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:1234", "1.2.3.4:443")
	event := e.ObserveResolved(flow, "test", identity.Attribution{Status: "directly-associated", VisibilityComplete: true, Application: &rootApp, Owners: []identity.Process{{UID: 0, Application: rootApp}}, Fingerprint: "root"})
	if event.State != "allowed" {
		t.Fatal("root connection prompted despite migrated rule", event.State, event.Reason)
	}
	if e.rules[0].Version != 2 {
		t.Fatal("migration repeated")
	}
	next := r
	next.ID = "new"
	next.Filter.Direction = "incoming"
	reviewed, sentence, err := e.reviewRuleLocked(next, time.Now(), false)
	if err != nil || reviewed.RootApplication == "" {
		t.Fatal(sentence, err)
	}
	summary := summaryFor(PolicyIdentity{identity.ApplicationKey(0, a), a.Revision, 0}, "outgoing", "daemon-monitor", nil, e.rules, time.Now())
	if summary.Action != "allow" {
		t.Fatal("root policy view omits shared rule", summary)
	}
	e.SaveRules = func([]policy.Rule) error { return fmt.Errorf("disk failure") }
	if err := e.SetRules([]policy.Rule{r}); err == nil {
		t.Fatal("migration failure ignored")
	}
	if e.rules[0].RootApplication == "" {
		t.Fatal("failed migration replaced active policy")
	}
	foreign := r
	foreign.Filter.UID = 970
	foreign.Filter.Application = identity.ApplicationKey(970, a)
	if e.rootScope(foreign).RootApplication != "" {
		t.Fatal("service account shared")
	}
}
