package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"testing"
	"time"
)

func appPolicyDraft(direction, action string) ObservedDraft {
	zero := uint16(0)
	expiry := time.Time{}
	return ObservedDraft{Direction: direction, Protocol: "*", Action: action, RemoteAddress: "*", LocalPort: &zero, RemotePort: &zero, Expires: &expiry, ApplicationPolicy: true}
}

// NetLimiter Blocker: Application → Out → Allow means all outgoing connections of
// that application. An existing remembered single-destination rule must neither
// become the setter's target nor be widened or deleted.
func TestApplicationSetterNeverEditsScopedRule(t *testing.T) {
	a, _, _, _ := observedAPI(t)
	uid := uint32(os.Getuid())
	// 1. A remembered single-destination rule (as left by a prompt).
	scoped := observedDraft("outgoing")
	scoped.Action, scoped.Protocol, scoped.RemoteAddress = "allow", "udp", "173.194.160.2"
	port := uint16(443)
	scoped.RemotePort = &port
	sp := requirePreview(t, a, scoped)
	if r := callResponse(a.path, saveRequest(a, sp, scoped)); r.Error != "" {
		t.Fatal(r)
	}
	// 2. Application → Out → Allow creates the whole-application rule.
	d := appPolicyDraft("outgoing", "allow")
	p := requirePreview(t, a, d)
	if p.Replaces != nil || p.Rule.ID == sp.Rule.ID || p.Rule.Filter.Protocol != "*" || p.Rule.Filter.RemoteAddress != "*" || p.Rule.Filter.RemotePort != 0 || p.Rule.Filter.NetworkZone != "" {
		t.Fatalf("setter targeted/derived from the scoped rule: %+v", p)
	}
	if r := callResponse(a.path, saveRequest(a, p, d)); r.Error != "" {
		t.Fatal(r)
	}
	// 3. Application → Out → Deny updates that same rule in place.
	deny := appPolicyDraft("outgoing", "block")
	dp := requirePreview(t, a, deny)
	if dp.Replaces == nil || dp.Replaces.ID != p.Rule.ID || dp.Rule.ID != p.Rule.ID || dp.Rule.Version != 2 {
		t.Fatalf("existing application rule not updated in place: %+v", dp)
	}
	if r := callResponse(a.path, saveRequest(a, dp, deny)); r.Error != "" {
		t.Fatal(r)
	}
	rules := a.e.Rules(uid, false)
	if len(rules) != 2 {
		t.Fatalf("want scoped + application rule, got %d", len(rules))
	}
	for _, r := range rules {
		if r.ID == sp.Rule.ID && (r.Version != 1 || r.Filter != sp.Rule.Filter || r.Action != "allow") {
			t.Fatal("scoped rule changed", r)
		}
		if r.ID == p.Rule.ID && (r.Action != "block" || r.Version != 2) {
			t.Fatal("application rule not updated", r)
		}
	}
	// 4. Rule Status data: whole-application rule separate from scoped rules; In untouched.
	view := callResponse(a.path, Request{Version: 1, Operation: "policy-view", Generation: a.e.Generation}).PolicyView
	out := view.Applications[0].Outgoing
	if out.ApplicationRule == nil || out.ApplicationRule.ID != p.Rule.ID || out.ApplicationRule.Kind != "application" || out.ScopedRules != 1 || view.Applications[0].Incoming.ApplicationRule != nil {
		t.Fatalf("policy view: %+v", out)
	}
	// 5. A stale update (rule changed after preview) is refused, never blind.
	allow := appPolicyDraft("outgoing", "allow")
	stale := requirePreview(t, a, allow)
	again := requirePreview(t, a, appPolicyDraft("outgoing", "allow"))
	if r := callResponse(a.path, saveRequest(a, again, appPolicyDraft("outgoing", "allow"))); r.Error != "" {
		t.Fatal(r)
	}
	if r := callResponse(a.path, saveRequest(a, stale, allow)); r.ErrorCode != "policy_conflict" {
		t.Fatalf("stale update accepted: %+v", r)
	}
	// 6. A non-canonical draft cannot claim application_policy.
	bad := appPolicyDraft("outgoing", "allow")
	bad.Protocol = "tcp"
	if r := callResponse(a.path, previewRequest(a, bad)); r.ErrorCode != "invalid_request" {
		t.Fatalf("scoped application_policy accepted: %+v", r)
	}
}

// After a rule covering waiting requests is published they settle through the
// normal identity/policy path; uncovered ones keep their own deadline; Once
// never fans out.
func TestPolicyChangeSettlesCoveredPendingOnly(t *testing.T) {
	e, f, a, now := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	covered := e.Observe(f, "udp")
	other, _ := identity.ParseFlow("tcp", "incoming", "127.0.0.1:81", "127.0.0.1:9001")
	uncovered := e.Observe(other, "tcp")
	if covered.State != "awaiting-decision" || uncovered.State != "awaiting-decision" || covered.RequestGroup == "" {
		t.Fatal("setup", covered, uncovered)
	}
	twin, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.1:9002")
	if v := e.Observe(twin, "udp"); v.RequestGroup != covered.RequestGroup || v.ID == covered.ID {
		t.Fatal("equivalent repeated requests not grouped", v.RequestGroup, covered.RequestGroup)
	}
	// Once on one request does not decide its equivalent twin.
	if _, err := e.Decide(covered.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	if e.Observe(twin, "udp").State != "awaiting-decision" {
		t.Fatal("Once fanned out to an equivalent request")
	}
	// An application-wide UDP incoming Allow covers the twin but not the TCP request.
	r := policy.Rule{Schema: 2, ID: "user:app", Version: 1, Priority: 100, Action: "allow", Filter: policy.Filter{Application: a.Application.Key, Revision: a.Application.Revision, UID: 1000, Direction: "incoming", Protocol: "udp", RemoteAddress: "*"}}
	if err := e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	twinEvent := e.Observe(twin, "udp")
	if twinEvent.State != "allowed" || twinEvent.Rule != "user:app" {
		t.Fatalf("covered request not settled by rule: %+v", twinEvent)
	}
	if e.RetainedState(twinEvent.ID, twinEvent.Attribution.Fingerprint) != "allow" {
		t.Fatal("held packet of settled request not released")
	}
	if v := e.Observe(other, "tcp"); v.ID != uncovered.ID || v.State != "awaiting-decision" {
		t.Fatalf("uncovered request dropped or changed: %+v", v)
	}
}

// Remember chooses which properties the rule keeps (source application always).
func TestRememberFieldsWidenOnlyChosenProperties(t *testing.T) {
	e, f, _, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{}})
	if err != nil {
		t.Fatal(err)
	}
	g := p.Rule.Filter
	if g.Application != "app" || g.UID != 1000 || g.Direction != "incoming" || g.Protocol != "*" || g.RemoteAddress != "*" || g.LocalPort != 0 || ruleKind(g) != "application" || p.Summary == "" {
		t.Fatalf("application remember: %+v %q", g, p.Summary)
	}
	// Submitting different fields than reviewed is refused.
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.Token, 1000, false); err == nil {
		t.Fatal("decision with different remember fields accepted")
	}
	if _, saved, _, err := e.DecideReviewed(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.Token, 1000, false, RememberOptions{Fields: &RememberFields{}}); err != nil || saved.Filter != g {
		t.Fatal(err, saved)
	}
	// Destination-only remember keeps the address, any port/protocol; temporary duration bound.
	v2 := e.Observe(f, "udp")
	if v2.State != "allowed" {
		t.Fatal("application remember did not cover the following request", v2.State)
	}
	other, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:5000", "192.0.2.9:443")
	v3 := e.Observe(other, "tcp")
	p3, err := e.PreviewDecision(e.Generation, v3.ID, "block", "application", "any", e.Zones.Revision, 1000, false, RememberOptions{Fields: &RememberFields{Address: true}, DurationSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	h := p3.Rule.Filter
	if h.RemoteAddress != "192.0.2.9" || h.RemotePort != 0 || h.Protocol != "*" || p3.DurationSeconds != 600 || !p3.Rule.Expires.Equal(e.Now().Add(10*time.Minute)) {
		t.Fatalf("destination remember: %+v", p3)
	}
	if _, err := e.PreviewDecision(e.Generation, v3.ID, "block", "application", "any", e.Zones.Revision, 1000, false, RememberOptions{DurationSeconds: 5}); err == nil {
		t.Fatal("out-of-range duration accepted")
	}
}

// A waiting request whose attempt ended (identity gone) is finalized at
// re-evaluation instead of lingering as an undecidable prompt.
func TestPolicyChangeExpiresEndedAttempts(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	v := e.Observe(f, "udp")
	a.Fingerprint = "socket closed and reused"
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	for _, x := range e.List(1000, false) {
		if x.ID == v.ID && x.State == "awaiting-decision" {
			t.Fatal("ended attempt still actionable after policy change")
		}
	}
}

// Remember "Process" (NetLimiter dialog option) binds the remembered rule to the
// requesting instance; refused without one verified owner or with a zone.
func TestRememberProcessBindsRequestingInstance(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	opts := RememberOptions{Fields: &RememberFields{Process: true}}
	if _, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, opts); err == nil {
		t.Fatal("process remember without a verified single owner accepted")
	}
	self, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Skip("own process identity unavailable:", err)
	}
	a.VisibilityComplete, a.Owners = true, []identity.Process{self}
	a.Application = &self.Application
	self.UID = 1000
	a.Owners[0].UID = 1000
	v2 := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v2.ID, "allow", "persistent", "any", e.Zones.Revision, 1000, false, opts)
	if err != nil {
		t.Skip("process binding unsupported in this environment:", err)
	}
	if p.Rule.Filter.Process.IsZero() || p.Rule.Filter.Process.PID != os.Getpid() || p.Rule.Filter.RemoteAddress != "*" {
		t.Fatalf("process remember not bound to the requesting instance: %+v", p.Rule.Filter)
	}
	if _, err := e.PreviewDecision(e.Generation, v2.ID, "allow", "persistent", "local", e.Zones.Revision, 1000, false, opts); err == nil {
		t.Fatal("process remember with zone accepted")
	}
}
