package daemon

import (
	"encoding/json"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func summaryFixture(t *testing.T) (*Engine, identity.Flow, *identity.Attribution, *time.Time) {
	t.Helper()
	e, f, a, now := fixture()
	a.Application.Kind = "native"
	e.Mode = "daemon-monitor"
	e.Activity = func() identity.ActivitySnapshot {
		return identity.ActivitySnapshot{Sequence: 19, Collected: *now, Complete: true, Processes: map[string]identity.ActivityProcess{"7:10": {ID: "7:10", Start: "10", UID: 1000, Application: *a.Application}}, Rows: []identity.ActivityRow{{ID: "ns-cookie", Owners: []string{"7:10"}, OwnershipCategory: "visible-holder", Socket: identity.Socket{UID: 1000}}}}
	}
	return e, f, a, now
}
func viewFor(t *testing.T, e *Engine, h *EnforcementStatus) PolicyView {
	t.Helper()
	v, err := e.PolicyView(e.Generation, "", 1000, false, h)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestPolicyViewConfiguredClasses(t *testing.T) {
	e, _, _, now := summaryFixture(t)
	broad := func(id, protocol, action string) policy.Rule {
		return policy.Rule{Schema: 2, ID: id, Version: 3, Action: action, Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "incoming", Protocol: protocol, RemoteAddress: "*"}}
	}
	tcp, udp := broad("tcp", "tcp", "allow"), broad("udp", "udp", "allow")
	for _, tc := range []struct {
		name, class, action string
		rules               []policy.Rule
	}{
		{"absent", "absent", "", nil}, {"protocol scoped", "scoped", "", []policy.Rule{tcp}}, {"uniform", "uniform", "allow", []policy.Rule{tcp, udp}},
		{"mixed disjoint", "mixed", "", []policy.Rule{tcp, broad("udp", "udp", "block")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.SetRules(tc.rules); err != nil {
				t.Fatal(err)
			}
			v := viewFor(t, e, nil)
			p := v.Applications[0].Incoming
			if p.Configured != tc.class || p.Action != tc.action || p.Enforcement.Covered || p.Enforcement.State != "stopped" || p.RuntimeDefault.Known {
				t.Fatal(p)
			}
			if !p.Default.Known || p.Default.Action != "ask" {
				t.Fatal(p)
			}
			if v.Applications[0].Outgoing.Configured != "absent" {
				t.Fatal("directions merged")
			}
		})
	}
	disabled := tcp
	disabled.Disabled = true
	expired := udp
	expired.Expires = now.Add(-time.Second)
	e.SetRules([]policy.Rule{disabled, expired})
	p := viewFor(t, e, nil).Applications[0].Incoming
	if p.Configured != "inactive_only" || p.Disabled != 1 || p.Expired != 1 || p.Active != 0 {
		t.Fatal(p)
	}
	tcp.Filter.RemoteAddress = "127.0.0.2"
	tcp.Filter.LocalPort = 80
	udp.Filter.RemotePort = 53
	e.SetRules([]policy.Rule{tcp, udp})
	if p := viewFor(t, e, nil).Applications[0].Incoming; p.Configured != "scoped" || p.Action != "" {
		t.Fatal(p)
	}
	other := tcp
	other.ID = "block"
	other.Action = "block"
	other.Priority = 10
	e.SetRules([]policy.Rule{tcp, other})
	if p := viewFor(t, e, nil).Applications[0].Incoming; p.Configured != "mixed" || !p.OverlappingActions {
		t.Fatal(p)
	}
	e.Mode = "host-enforcement"
	h := &EnforcementStatus{State: "active", Profile: "incoming"}
	v := viewFor(t, e, h)
	if !v.Applications[0].Incoming.Enforcement.Covered || v.Applications[0].Outgoing.Enforcement.Covered || v.Applications[0].Outgoing.Enforcement.State != "bypassed" || v.Applications[0].Outgoing.RuntimeDefault.Action != "allow" {
		t.Fatal(v)
	}
	// Stored outgoing Block remains configured, never effective under incoming-only.
	outgoing := tcp
	outgoing.ID = "outgoing-block"
	outgoing.Action = "block"
	outgoing.Filter.Direction = "outgoing"
	if err := e.SetRules([]policy.Rule{outgoing}); err != nil {
		t.Fatal(err)
	}
	out := viewFor(t, e, h).Applications[0].Outgoing
	if out.Active != 1 || out.Rules[0].Action != "block" || out.Enforcement.Covered || out.RuntimeDefault.Action != "allow" {
		t.Fatal(out)
	}
	h.State = "degraded"
	if p := viewFor(t, e, h).Applications[0].Incoming; p.Enforcement.Covered || p.RuntimeDefault.Known {
		t.Fatal(p)
	}
}
func TestPolicyViewAssociationsAndPrivacy(t *testing.T) {
	e, _, a, now := summaryFixture(t)
	s := e.Activity()
	s.Processes["other:2"] = identity.ActivityProcess{ID: "other:2", Start: "2", UID: 0, Application: identity.Application{Key: "service", Revision: "r", Kind: "native"}}
	s.Rows = append(s.Rows, identity.ActivityRow{ID: "foreign", Owners: []string{"other:2"}, OwnershipCategory: "visible-holder"}, identity.ActivityRow{ID: "shared", Owners: []string{"7:10", "7:10"}, OwnershipCategory: "shared", DisplayApplication: a.Application, Socket: identity.Socket{UID: 1000}}, identity.ActivityRow{ID: "display", DisplayApplication: a.Application, Socket: identity.Socket{UID: 1000}})
	e.Activity = func() identity.ActivitySnapshot { return s }
	v := viewFor(t, e, nil)
	if len(v.Applications) != 1 || len(v.Rows) != 3 {
		t.Fatal(v)
	}
	for _, r := range v.Rows {
		if r.DecisionAuthority {
			t.Fatal("display identity became authority")
		}
		if r.RowID != "ns-cookie" && (r.Status != "unavailable" || r.ApplicationRef != "") {
			t.Fatal(r)
		}
	}
	admin, err := e.PolicyView(e.Generation, "", 1000, true, nil)
	if err != nil || len(admin.Applications) != 2 {
		t.Fatal(admin, err)
	}
	// No foreign rule detail or even policy token invalidation on foreign changes.
	before := v.Snapshot.Token
	foreign := policy.Rule{ID: "secret-service", Version: 1, Action: "block", Filter: policy.Filter{Application: "service", Revision: "r", UID: 0, Direction: "incoming", Protocol: "tcp"}}
	e.SetRules([]policy.Rule{foreign})
	after := viewFor(t, e, nil)
	if before != after.Snapshot.Token {
		t.Fatal("foreign edit leaked through token")
	}
	encoded, _ := json.Marshal(after)
	if strings.Contains(string(encoded), "secret-service") {
		t.Fatal("foreign rule leak")
	}
	*now = now.Add(time.Minute)
	if v := viewFor(t, e, nil); v.ActivityAvailable || len(v.Applications) != 0 {
		t.Fatal("stale identity summarized")
	}
}
func TestPolicyExplanationAgreesWithoutVerdictEffects(t *testing.T) {
	e, f, a, now := summaryFixture(t)
	e.Mode = "host-enforcement"
	e.SaveRules = func([]policy.Rule) error { return nil }
	rules := []policy.Rule{
		{Schema: 2, ID: "z", Version: ^uint64(0), Action: "allow", Priority: 5, Filter: policy.Remembered(f, *a)},
		{Schema: 2, ID: "a", Version: 2, Action: "block", Priority: 5, Filter: policy.Remembered(f, *a)},
	}
	e.SetRules(rules)
	event := e.Observe(f, "fixture")
	before, _ := json.Marshal(e.events)
	h := &EnforcementStatus{State: "active", Profile: "incoming"}
	r, err := e.PolicyExplain(e.Generation, "", []string{event.ID}, 1000, false, h)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Contexts[0]
	action, winner, ids := policy.Evaluate(rules, f, *a, *now)
	if p.ConfiguredAction != action || p.SelectedRule != winner || p.HistoricalDecision || !p.Enforcement.Covered {
		t.Fatal(p)
	}
	got := []string{}
	for _, r := range p.Matching {
		got = append(got, r.ID)
	}
	if !reflect.DeepEqual(got, ids) || p.Matching[1].Version != "18446744073709551615" {
		t.Fatal(p)
	}
	after, _ := json.Marshal(e.events)
	if string(before) != string(after) {
		t.Fatal("explanation changed pending/cache/verdict state")
	}
	e.SetRules(nil)
	event = e.Observe(f, "once")
	e.Decide(event.ID, "allow", "once", 1000, false)
	r, err = e.PolicyExplain(e.Generation, "", []string{event.ID}, 1000, false, h)
	if err != nil || r.Contexts[0].ConfiguredAction != "ask" {
		t.Fatal(r, err)
	}
	if e.events[f.Key()+"|once"].State != "allowed" {
		t.Fatal("current stored default overwritten cached once decision")
	}
	*now = now.Add(time.Minute)
	before, _ = json.Marshal(e.events)
	e.PolicyExplain(e.Generation, "", []string{event.ID}, 1000, false, h)
	after, _ = json.Marshal(e.events)
	if string(before) != string(after) {
		t.Fatal("explanation expired event as side effect")
	}
	// Shared/unsafe recorded association is not turned into a guessed application.
	a.Application = nil
	unknown := e.Observe(f, "unsafe")
	r, _ = e.PolicyExplain(e.Generation, "", []string{unknown.ID}, 1000, true, h)
	if r.Contexts[0].SelectedRule != "unsafe-attribution" || r.Contexts[0].Identity != nil {
		t.Fatal(r)
	}
	hidden, _ := e.PolicyExplain(e.Generation, "", []string{unknown.ID, "missing"}, 1000, false, h)
	if hidden.Contexts[0].Status != hidden.Contexts[1].Status || hidden.Contexts[0].Reason != hidden.Contexts[1].Reason {
		t.Fatal("unauthorized context oracle")
	}
}
func TestPolicyTokensEditsExpiryAndExactSequence(t *testing.T) {
	e, _, _, now := summaryFixture(t)
	r := policy.Rule{ID: "lease", Version: 1, Action: "allow", Expires: now.Add(time.Second), Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "incoming", Protocol: "tcp"}}
	e.SetRules([]policy.Rule{r})
	e.policyReadSequence = 1 << 53
	first := viewFor(t, e, nil)
	second := viewFor(t, e, nil)
	if first.Snapshot.Token != second.Snapshot.Token || first.Snapshot.Sequence != "9007199254740993" || second.Snapshot.Sequence != "9007199254740994" || first.Snapshot.ValidUntil == nil {
		t.Fatal(first.Snapshot, second.Snapshot)
	}
	*now = now.Add(2 * time.Second)
	if _, err := e.PolicyView(e.Generation, first.Snapshot.Token, 1000, false, nil); err == nil {
		t.Fatal("expired snapshot accepted")
	}
	current := viewFor(t, e, nil)
	if current.Snapshot.Token == first.Snapshot.Token {
		t.Fatal("expiry did not invalidate token")
	}
	if _, err := e.PolicyView("old", "", 1000, false, nil); err == nil {
		t.Fatal("old generation accepted")
	}
	e.SaveRules = func([]policy.Rule) error { return nil }
	changeListedRule(e, "lease", "disable", 1000, false)
	edited := viewFor(t, e, nil)
	if edited.Snapshot.Token == current.Snapshot.Token {
		t.Fatal("edit did not invalidate")
	}
	version := uint64(2)
	e.DeleteRule(e.Generation, "lease", &version, 1000, false)
	if deleted := viewFor(t, e, nil); deleted.Snapshot.Token == edited.Snapshot.Token || deleted.Applications[0].Incoming.Configured != "absent" {
		t.Fatal(deleted)
	}
}
func TestPolicySnapshotConcurrentQueriesAndEdits(t *testing.T) {
	e, _, _, _ := summaryFixture(t)
	e.SaveRules = func([]policy.Rule) error { return nil }
	r := policy.Rule{ID: "rule", Version: 1, Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "incoming", Protocol: "tcp"}}
	e.SetRules([]policy.Rule{r})
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				v, err := e.PolicyView(e.Generation, "", 1000, false, nil)
				if err != nil {
					t.Error(err)
					return
				}
				p := v.Applications[0].Incoming
				if p.Rules[0].Active == p.Rules[0].Disabled {
					t.Error("incoherent active flag")
				}
				if _, err := strconv.ParseUint(v.Snapshot.Sequence, 10, 64); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		if err := changeListedRule(e, "rule", []string{"disable", "enable"}[i%2], 1000, false); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func TestPolicyContractAuthenticatedNativeActivity(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		t.Skip("real ownership fixture requires disposable PID/network namespace; run scripts/lab.sh")
	}

	if os.Getuid() == 0 {
		t.Skip("real ordinary Unix peer required")
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	collector := (&identity.ActivityCollector{})
	snapshot := collector.Collect()
	var target identity.ActivityRow
	var process identity.ActivityProcess
	for _, row := range snapshot.Rows {
		if row.Socket.Protocol == "udp" && row.Socket.Local.String() == listener.LocalAddr().String() && len(row.Owners) == 1 {
			target = row
			process = snapshot.Processes[row.Owners[0]]
			break
		}
	}
	if target.ID == "" || process.UID != uint32(os.Getuid()) {
		t.Fatal("real owned fixture missing")
	}
	var event Event
	api := newDeleteAPI(t, func(e *Engine, s *store.Store) {
		e.Mode = "daemon-monitor"
		e.Now = time.Now
		e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "stopped"} }
		e.Activity = func() identity.ActivitySnapshot { return snapshot }
		flow, _ := identity.ParseFlow("udp", "incoming", listener.LocalAddr().String(), "127.0.0.2:39000")
		app := process.Application
		attribution := identity.Attribution{Application: &app, Owners: []identity.Process{{PID: process.PID, Start: process.Start, UID: process.UID}}, Fingerprint: "fixture-recorded-context"}
		e.Resolve = func(identity.Flow) identity.Attribution { return attribution }
		rule := policy.Rule{ID: "fixture-scoped", Version: ^uint64(0), Schema: 2, Created: time.Now(), Action: "block", Priority: 100, Filter: policy.Remembered(flow, attribution)}
		foreign := rule
		foreign.ID = "foreign-private-rule"
		foreign.Filter.UID = process.UID + 1
		if err := s.Replace([]policy.Rule{rule, foreign}); err != nil {
			t.Fatal(err)
		}
		if err := e.SetRules([]policy.Rule{rule, foreign}); err != nil {
			t.Fatal(err)
		}
		event = e.Observe(flow, "recorded-context-not-wire-traffic")
	})
	before, _ := api.s.Load()
	beforeEvents, _ := json.Marshal(api.e.events)
	r, err := Call(api.path, Request{Version: 1, Operation: "policy-view", Generation: api.e.Generation})
	if err != nil || r.PeerUID != uint32(os.Getuid()) || r.PolicyView == nil {
		t.Fatal(r, err)
	}
	var app *ApplicationPolicy
	for i := range r.PolicyView.Applications {
		if r.PolicyView.Applications[i].Identity.Key == process.Application.Key {
			app = &r.PolicyView.Applications[i]
		}
	}
	if app == nil || app.Incoming.Configured != "scoped" || app.Incoming.Rules[0].Version != "18446744073709551615" || app.Incoming.Enforcement.State != "stopped" {
		t.Fatal(app)
	}
	blob, _ := json.MarshalIndent(r, "", "  ")
	if strings.Contains(string(blob), "foreign-private-rule") {
		t.Fatal("foreign policy exposure")
	}
	artifactDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(artifactDir, "policy-api-example.json"), blob, 0600); err != nil {
		t.Fatal(err)
	}
	explanation, err := Call(api.path, Request{Version: 1, Operation: "policy-explain", Generation: api.e.Generation, ExpectedPolicyToken: r.PolicyView.Snapshot.Token, EventIDs: []string{event.ID}})
	if err != nil || explanation.PolicyExplanations.Contexts[0].ConfiguredAction != "block" || explanation.PolicyExplanations.Contexts[0].HistoricalDecision {
		t.Fatal(explanation, err)
	}
	exblob, _ := json.MarshalIndent(explanation, "", "  ")
	if err := os.WriteFile(filepath.Join(artifactDir, "policy-explanation-api-example.json"), exblob, 0600); err != nil {
		t.Fatal(err)
	}
	roPath := filepath.Join(filepath.Dir(api.path), "readonly")
	ro, err := Serve(roPath, api.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	for _, op := range []string{"policy-view", "policy-explain"} {
		denied := callResponse(roPath, Request{Version: 1, Operation: op, Generation: api.e.Generation, EventIDs: []string{event.ID}})
		if denied.ErrorCode != "primary_required" || denied.PolicyView != nil || denied.PolicyExplanations != nil {
			t.Fatal(denied)
		}
	}
	after, _ := api.s.Load()
	afterEvents, _ := json.Marshal(api.e.events)
	if !reflect.DeepEqual(before, after) || string(beforeEvents) != string(afterEvents) {
		t.Fatal("read changed stored/effective or verdict state")
	}
	t.Logf("real UID%d authenticated Unix API, native UDP Activity, SQLite Block configured inactive, exact uint64 refs; recorded-context explanation, companion denial; no enforcement", os.Getuid())
}
func TestPolicyAPIEditsInvalidateSnapshots(t *testing.T) {
	api := newDeleteAPI(t)
	request := Request{Version: 1, Operation: "policy-view", Generation: api.e.Generation}
	before, err := Call(api.path, request)
	if err != nil {
		t.Fatal(err)
	}
	changed := callResponse(api.path, api.editRequest())
	if changed.Error != "" {
		t.Fatal(changed)
	}
	request.ExpectedPolicyToken = before.PolicyView.Snapshot.Token
	assertCode(t, callResponse(api.path, request), "policy_conflict")
	current, _ := Call(api.path, Request{Version: 1, Operation: "policy-view", Generation: api.e.Generation})
	q := api.deleteRequest()
	v := uint64(2)
	q.ExpectedVersion = &v
	if removed := callResponse(api.path, q); removed.Error != "" {
		t.Fatal(removed)
	}
	request.ExpectedPolicyToken = current.PolicyView.Snapshot.Token
	assertCode(t, callResponse(api.path, request), "policy_conflict")
	request.Generation = "old"
	assertCode(t, callResponse(api.path, request), "generation_conflict")
	tooMany := make([]string, 9)
	for i := range tooMany {
		tooMany[i] = strconv.Itoa(i)
	}
	assertCode(t, callResponse(api.path, Request{Version: 1, Operation: "policy-explain", Generation: api.e.Generation, EventIDs: tooMany}), "invalid_request")
}

func TestPolicyMetadataFailureDoesNotChangeSnapshot(t *testing.T) {
	api := newDeleteAPI(t, func(e *Engine, _ *store.Store) {
		e.SaveRules = func([]policy.Rule) error { return errors.New("fixture transaction failure") }
	})
	q := Request{Version: 1, Operation: "policy-view", Generation: api.e.Generation}
	before, err := Call(api.path, q)
	if err != nil {
		t.Fatal(err)
	}
	assertCode(t, callResponse(api.path, api.editRequest()), "persistence_failed")
	q.ExpectedPolicyToken = before.PolicyView.Snapshot.Token
	after, err := Call(api.path, q)
	if err != nil || after.PolicyView.Snapshot.Token != before.PolicyView.Snapshot.Token {
		t.Fatal("failed save published policy metadata", after, err)
	}
	rules, err := api.s.Load()
	if err != nil || len(rules) != 1 || rules[0].Action != "allow" {
		t.Fatal(rules, err)
	}
}
func TestPolicyMetadataBounds(t *testing.T) {
	e, _, _, _ := summaryFixture(t)
	r := policy.Rule{ID: strings.Repeat("x", 260*1024), Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "incoming", Protocol: "tcp"}}
	if err := e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.PolicyView(e.Generation, "", 1000, false, nil); err == nil {
		t.Fatal("unbounded policy metadata accepted")
	}
	if _, err := e.PolicyExplain(e.Generation, "", []string{"x", "x"}, 1000, false, nil); err == nil {
		t.Fatal("duplicate contexts accepted")
	}
}

// A rule bound to an interface/local address/peer service is not whole-
// application coverage, even with any remote address and ports.
func TestPolicyViewConstrainedRulesAreScopedNotUniform(t *testing.T) {
	a := PolicyIdentity{Key: "app", Revision: "rev", UID: 974}
	now := time.Now()
	rule := func(id, proto string, edit func(*policy.Filter)) policy.Rule {
		r := policy.Rule{Schema: 5, ID: id, Version: 1, Action: "allow", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 974, Direction: "incoming", Protocol: proto, RemoteAddress: "*"}}
		edit(&r.Filter)
		return r
	}
	for name, edit := range map[string]func(*policy.Filter){
		"interface":     func(f *policy.Filter) { f.InterfaceName = "lo" },
		"local address": func(f *policy.Filter) { f.LocalAddress = "127.0.0.53" },
		"peer service":  func(f *policy.Filter) { f.PeerService = policy.PeerService{Application: "peer", Revision: "r", UID: 1} },
	} {
		s := summaryFor(a, "incoming", "daemon-monitor", nil, []policy.Rule{rule("t", "tcp", edit), rule("u", "udp", edit)}, now)
		if s.Configured != "scoped" {
			t.Fatalf("%s-bound rules summarised as %q", name, s.Configured)
		}
	}
	plain := func(*policy.Filter) {}
	if s := summaryFor(a, "incoming", "daemon-monitor", nil, []policy.Rule{rule("t", "tcp", plain), rule("u", "udp", plain)}, now); s.Configured != "uniform" {
		t.Fatalf("unconstrained rules: %q", s.Configured)
	}
}
