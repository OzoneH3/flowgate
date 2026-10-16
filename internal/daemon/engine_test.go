package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
	"time"
)

func fixture() (*Engine, identity.Flow, *identity.Attribution, *time.Time) {
	e := New(2 * time.Second)
	now := time.Unix(100, 0)
	e.Now = func() time.Time { return now }
	app := identity.Application{Key: "app", Revision: "rev"}
	a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000, Start: "10"}}, Fingerprint: "one"}
	e.Resolve = func(identity.Flow) identity.Attribution { return a }
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9000")
	return e, f, &a, &now
}
func TestDecisionLifecycle(t *testing.T) {
	e, f, a, now := fixture()
	v := e.Observe(f, "udp")
	if v.State != "awaiting-decision" {
		t.Fatal(v)
	}
	if e.Observe(f, "udp").ID != v.ID {
		t.Fatal("retransmit not deduplicated")
	}
	if _, err := e.Decide(v.ID, "allow", "once", 1001, false); err == nil {
		t.Fatal("cross-user allowed")
	}
	a.Fingerprint = "replacement"
	if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err == nil {
		t.Fatal("identity replacement accepted")
	}
	v = e.Observe(f, "udp")
	*now = now.Add(3 * time.Second)
	if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err == nil {
		t.Fatal("stale accepted")
	}
	v = e.Observe(f, "udp")
	if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	if e.Observe(f, "udp").State != "allowed" {
		t.Fatal("lost decision")
	}
	*now = now.Add(31 * time.Second)
	if e.Observe(f, "udp").State != "awaiting-decision" {
		t.Fatal("UDP once did not expire")
	}
}
func TestBounds(t *testing.T) {
	e, f, _, now := fixture()
	e.Max = 3
	for i := 0; i < 20; i++ {
		e.Observe(f, string(rune('a'+i)))
	}
	if len(e.List(1000, false)) != 3 {
		t.Fatal("unbounded state")
	}
	*now = now.Add(20 * time.Second)
	if len(e.List(1000, false)) != 0 {
		t.Fatal("expired history retained")
	}
	e.Max = 256
	for i := 0; i < 100; i++ {
		e.Observe(f, string(rune(i)))
	}
	if len(e.List(1000, false)) != 20 {
		t.Fatal("rate bound failed")
	}
}
func TestRuleExpiryAndInvalidation(t *testing.T) {
	e, f, _, now := fixture()
	r := policy.Rule{ID: "r", Action: "allow", Expires: now.Add(time.Second), Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Protocol: "udp", Direction: "incoming"}}
	if err := e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if e.Observe(f, "udp").State != "allowed" {
		t.Fatal("rule not used")
	}
	*now = now.Add(1500 * time.Millisecond)
	if e.Observe(f, "udp").State != "awaiting-decision" {
		t.Fatal("expired cached rule used")
	}
	r.Action = "block"
	r.Expires = time.Time{}
	e.SetRules([]policy.Rule{r})
	if e.Observe(f, "udp").State != "blocked" {
		t.Fatal("old cached decision used")
	}
}
func TestSharedOwnerDenied(t *testing.T) {
	e, f, a, _ := fixture()
	a.Application = nil
	a.Owners = append(a.Owners, identity.Process{UID: 1000})
	v := e.Observe(f, "udp")
	if v.State != "blocked" {
		t.Fatal("ambiguous owner prompted")
	}
}

func TestRetainedIdentityAndRuleInvalidation(t *testing.T) {
	e, f, a, _ := fixture()
	v := e.Observe(f, "udp")
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "pending" {
		t.Fatal("not pending")
	}
	e.Decide(v.ID, "allow", "once", 1000, false)
	a.Fingerprint = "changed"
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("replacement released")
	}
	v = e.Observe(f, "new")
	e.Decide(v.ID, "allow", "once", 1000, false)
	e.SetRules(nil)
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "drop" {
		t.Fatal("invalidated packet released")
	}
}

func TestUnrelatedRememberedDecisionPreservesRetainedAllow(t *testing.T) {
	e, f, _, _ := fixture()
	v := e.Observe(f, "one")
	e.Decide(v.ID, "allow", "application", 1000, false)
	other, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:81", "127.0.0.1:9000")
	v2 := e.Observe(other, "two")
	e.Decide(v2.ID, "block", "application", 1000, false)
	if e.RetainedState(v.ID, v.Attribution.Fingerprint) != "allow" {
		t.Fatal("unrelated decision discarded approved retained packet")
	}
}

func TestScopePreviews(t *testing.T) {
	e, f, _, _ := fixture()
	v := e.Observe(f, "udp")
	if len(v.ScopePreviews) != 2 || !strings.Contains(v.ScopePreviews["application"], "local service port 80; any remote source port") || !strings.Contains(v.ScopePreviews["application"], "one hour (memory only)") {
		t.Fatal(v.ScopePreviews)
	}
	f.Direction = "outgoing"
	v = e.Observe(f, "udp")
	if !strings.Contains(v.ScopePreviews["application"], "remote service port 9000; any local source port") {
		t.Fatal(v.ScopePreviews)
	}
}
