package daemon

import (
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func endpointDraftFixture() EndpointDraft {
	zero := time.Time{}
	return EndpointDraft{Action: "allow", RemoteAddress: "192.0.2.40", RemotePort: 8445, Expires: &zero}
}
func endpointEngine(t *testing.T) (*Engine, *time.Time, *[]policy.Rule) {
	t.Helper()
	e := New(time.Minute)
	now := time.Unix(1000, 0).UTC()
	e.Now = func() time.Time { return now }
	var disk []policy.Rule
	e.SaveRules = func(r []policy.Rule) error { disk = append([]policy.Rule{}, r...); return nil }
	return e, &now, &disk
}
func requireEndpointPreview(t *testing.T, e *Engine, d EndpointDraft) EndpointPreview {
	t.Helper()
	v, err := e.PreviewEndpointRule(e.Generation, d, 1000, true, &EnforcementStatus{State: "active", Profile: "both"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestEndpointPreviewSaveAtomicReplayAndDeletion(t *testing.T) {
	e, now, disk := endpointEngine(t)
	d := endpointDraftFixture()
	p := requireEndpointPreview(t, e, d)
	if p.Rule.Schema != 7 || !p.Rule.NetworkEndpoint || !p.Rule.Filter.AllUIDs || p.Rule.Filter.UID != 0 || !strings.Contains(p.ScopePreview, "overrides application Deny/Ask") || !strings.Contains(p.ScopePreview, "already admitted TCP") || len(e.rules) != 0 {
		t.Fatal(p)
	}
	for _, bad := range []struct {
		gen, token string
		d          EndpointDraft
		uid        uint32
		admin      bool
		code       string
	}{
		{"old", p.Token, d, 1000, true, "generation_conflict"}, {e.Generation, p.Token, d, 1000, false, "forbidden"}, {e.Generation, p.Token, d, 1001, true, "preview_expired"}, {e.Generation, "missing", d, 1000, true, "preview_expired"}, {e.Generation, p.Token, func() EndpointDraft { x := d; x.RemotePort++; return x }(), 1000, true, "preview_mismatch"},
	} {
		_, _, _, err := e.SaveEndpointRule(bad.gen, bad.token, bad.d, bad.uid, bad.admin)
		var typed *RuleMutationError
		if !errors.As(err, &typed) || typed.Code != bad.code {
			t.Fatalf("%s: %v", bad.code, err)
		}
	}
	original := e.SaveRules
	e.SaveRules = func([]policy.Rule) error { return errors.New("disk failure") }
	if _, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true); err == nil || len(e.rules) != 0 || len(*disk) != 0 {
		t.Fatal("failed write published", err)
	}
	e.SaveRules = original
	r, _, replay, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true)
	if err != nil || replay || !reflect.DeepEqual(r, p.Rule) || len(*disk) != 1 {
		t.Fatal(r, replay, err)
	}
	if _, _, replay, err = e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true); err != nil || !replay || len(*disk) != 1 {
		t.Fatal(replay, err)
	}
	if _, err = e.PreviewEndpointRule(e.Generation, d, 1000, true, nil); err == nil {
		t.Fatal("duplicate endpoint allowed")
	}
	if _, err = e.DeleteRule(e.Generation, r.ID, &r.Version, 1000, false); err == nil {
		t.Fatal("ordinary user deleted machine permission")
	}
	// Expiry does not remove admin inventory/conditional delete authority.
	e.mu.Lock()
	e.rules[0].Expires = *now
	e.mu.Unlock()
	if _, err = e.DeleteRule(e.Generation, r.ID, &r.Version, 1000, true); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true); err == nil {
		t.Fatal("deleted preview revived")
	}
}
func TestEndpointPreviewBoundsAndCanonicalization(t *testing.T) {
	e, now, _ := endpointEngine(t)
	d := endpointDraftFixture()
	for _, addr := range []string{"*", "example.invalid", "192.0.2.0/24", "127.0.0.1", "::1", "224.0.0.1", "fe80::1%test", "0.0.0.0"} {
		x := d
		x.RemoteAddress = addr
		if _, err := e.PreviewEndpointRule(e.Generation, x, 1000, true, nil); err == nil {
			t.Fatal("bad endpoint", addr)
		}
	}
	for _, x := range []EndpointDraft{{Action: "allow", RemoteAddress: d.RemoteAddress, RemotePort: 8445}, {Action: "ask", RemoteAddress: d.RemoteAddress, RemotePort: 8445, Expires: d.Expires}, {Action: "allow", RemoteAddress: d.RemoteAddress, Expires: d.Expires}} {
		if _, err := e.PreviewEndpointRule(e.Generation, x, 1000, true, nil); err == nil {
			t.Fatal("incomplete draft accepted", x)
		}
	}
	x := d
	x.RemoteAddress = "::ffff:192.0.2.40"
	p := requireEndpointPreview(t, e, x)
	if p.Rule.Filter.RemoteAddress != d.RemoteAddress {
		t.Fatal(p)
	}
	// Semantically identical mapped and plain addresses bind to one canonical scope.
	if _, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true); err != nil {
		t.Fatal(err)
	}
	e2, now2, _ := endpointEngine(t)
	p = requireEndpointPreview(t, e2, d)
	*now2 = now2.Add(30 * time.Second)
	if _, _, _, err := e2.SaveEndpointRule(e2.Generation, p.Token, d, 1000, true); err == nil {
		t.Fatal("expired preview saved")
	}
	for _, at := range []time.Time{*now, now.Add(366 * 24 * time.Hour)} {
		x := d
		x.Expires = &at
		if _, err := e.PreviewEndpointRule(e.Generation, x, 1000, true, nil); err == nil {
			t.Fatal("bad expiry")
		}
	}
	e3, _, _ := endpointEngine(t)
	for i := 0; i < 16; i++ {
		requireEndpointPreview(t, e3, d)
	}
	if _, err := e3.PreviewEndpointRule(e3.Generation, d, 1000, true, nil); err == nil {
		t.Fatal("unbounded previews")
	}
}
func TestEndpointPolicyConflictAndGenericMutationRefusal(t *testing.T) {
	e, _, _ := endpointEngine(t)
	d := endpointDraftFixture()
	p := requireEndpointPreview(t, e, d)
	e.mu.Lock()
	e.rules = append(e.rules, policy.Rule{ID: "concurrent"})
	e.mu.Unlock()
	if _, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true); err == nil {
		t.Fatal("stale policy saved")
	}
	e.mu.Lock()
	e.rules = nil
	e.mu.Unlock()
	r, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	c := r
	c.NetworkEndpoint = false
	c.Schema = 4
	c.Filter.NetworkZone = "local"
	if _, _, err = e.EditRule(r.ID, "", &r.Version, c, 1000, true, true); err == nil {
		t.Fatal("stripped endpoint authority")
	}
	for _, action := range []string{"enable", "disable", "delete"} {
		if e.ChangeRule(r.ID, action, 1000, true) == nil {
			t.Fatal("legacy change handled endpoint", action)
		}
	}
	if _, _, err = e.EditRule("", "", nil, r, 1000, true, true); err == nil {
		t.Fatal("generic endpoint creation")
	}
	if _, _, err = e.CreateRuleFromBasis(r.ID, c, 1000, true, true); err == nil {
		t.Fatal("endpoint basis used for application")
	}
}
func TestEndpointOverridesOnceLeasesAndApplicationRules(t *testing.T) {
	for _, leaseAction := range []string{"allow", "block"} {
		t.Run(leaseAction, func(t *testing.T) {
			x := newWhileFixture(t, leaseAction)
			d := endpointDraftFixture()
			d.RemoteAddress = "192.0.2.1"
			d.RemotePort = 443
			if leaseAction == "allow" {
				d.Action = "block"
			}
			p := requireEndpointPreview(t, x.e, d)
			r, _, _, err := x.e.SaveEndpointRule(x.e.Generation, p.Token, d, 1000, true)
			if err != nil {
				t.Fatal(err)
			}
			f := outFlow(t, "tcp", "192.0.2.1:443")
			for _, token := range []string{"first", "new"} {
				v := x.e.Observe(f, token)
				want := "allowed"
				if d.Action == "block" {
					want = "blocked"
				}
				if v.State != want || v.Rule != r.ID || !strings.Contains(v.Permission, "all users and programs") {
					t.Fatal("Once or lease overrode endpoint", v)
				}
			}
			// The same endpoint admits/refuses fresh unowned observations, with no app identity minted.
			x.e.Resolve = func(identity.Flow) identity.Attribution {
				return identity.Attribution{Status: "unidentified", ReasonCode: identity.ReasonNoUserspaceOwnerObserved}
			}
			v := x.e.Observe(f, "unowned")
			if v.Rule != r.ID || v.Attribution.Application != nil {
				t.Fatal(v)
			}
		})
	}
}
func TestEndpointAPIAdminReadOnlyAndPersistence(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("administrator socket API exercised in privileged guest; ordinary peer has separate case")
	}
	a := newDeleteAPI(t, func(e *Engine, s *store.Store) { e.Mode = "host-enforcement" })
	d := endpointDraftFixture()
	q := Request{Version: 1, Operation: "endpoint-rule-preview", Generation: a.e.Generation, EndpointDraft: &d}
	v := callResponse(a.path, q)
	if v.Error != "" || v.EndpointPreview == nil || !slices.Contains(v.Capabilities, NetworkEndpointCapability) {
		t.Fatal(v)
	}
	q.Operation = "endpoint-rule-save"
	q.PreviewToken = v.EndpointPreview.Token
	saved := callResponse(a.path, q)
	if saved.Error != "" || saved.SavedRule == nil || !saved.SavedRule.NetworkEndpoint {
		t.Fatal(saved)
	}
	rs, err := a.s.Load()
	if err != nil || len(rs) != 2 {
		t.Fatal(rs, err)
	}
	restarted := New(time.Minute)
	if err = restarted.SetRules(rs); err != nil {
		t.Fatal(err)
	}
	f := outFlow(t, "tcp", "192.0.2.40:8445")
	restarted.Resolve = func(identity.Flow) identity.Attribution { return identity.Attribution{} }
	if got := restarted.Observe(f, "test"); got.State != "allowed" || got.Rule != saved.SavedRule.ID {
		t.Fatal(got)
	}
	readonlyPath := a.path + "ro"
	l, err := Serve(readonlyPath, a.e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	response := callResponse(readonlyPath, q)
	if response.ErrorCode != "read_only" || slices.Contains(response.Capabilities, NetworkEndpointCapability) {
		t.Fatal(response)
	}
	// Saved rule remains inspectable on a read-only endpoint, without a write capability.
	inventory := callResponse(readonlyPath, Request{Version: 1, Operation: "list"})
	found := false
	for _, r := range inventory.Rules {
		found = found || r.NetworkEndpoint
	}
	if !found {
		t.Fatal("read-only inventory lost endpoint", inventory.Error)
	}
}
func TestEndpointAPIOrdinaryPeerRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run under ordinary UID in validation guest")
	}
	a := newDeleteAPI(t)
	d := endpointDraftFixture()
	q := Request{Version: 1, Operation: "endpoint-rule-preview", Generation: a.e.Generation, EndpointDraft: &d}
	r := callResponse(a.path, q)
	if r.ErrorCode != "forbidden" || slices.Contains(r.Capabilities, NetworkEndpointCapability) || r.EndpointPreview != nil {
		t.Fatal(r)
	}
}
func TestEndpointExplanationAndInventory(t *testing.T) {
	e, now, _ := endpointEngine(t)
	p := requireEndpointPreview(t, e, endpointDraftFixture())
	r, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, endpointDraftFixture(), 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	if e.targetStateLocked(r).TargetScope != "network-endpoint" || e.ruleRefLocked(r, *now).TargetScope != "network-endpoint" || r.FollowsUpdates() {
		t.Fatal("endpoint became app")
	}
	v, err := e.PolicyView(e.Generation, "", 1000, true, nil)
	if err != nil || len(v.NetworkEndpoints) != 1 {
		t.Fatal(v, err)
	}
	if len(zoneFallbackIDs([]policy.Rule{r}, 1000)) != 0 {
		t.Fatal("endpoint was zone fallback")
	}
	e.Resolve = func(identity.Flow) identity.Attribution { return identity.Attribution{} }
	event := e.Observe(outFlow(t, "tcp", "192.0.2.40:8445"), "test")
	explained, err := e.PolicyExplain(e.Generation, "", []string{event.ID}, 1000, true, nil)
	if err != nil || len(explained.Contexts) != 1 || explained.Contexts[0].SelectedRule != r.ID || explained.Contexts[0].Identity != nil {
		t.Fatal(explained, err)
	}
}

func TestEndpointAuthorityDoesNotCallOwnershipCollectors(t *testing.T) {
	e, now, _ := endpointEngine(t)
	d := endpointDraftFixture()
	p := requireEndpointPreview(t, e, d)
	r, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, d, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.Resolve = func(identity.Flow) identity.Attribution { calls++; return identity.Attribution{} }
	e.TryResolve = func(identity.Flow) (identity.Attribution, bool) { calls++; return identity.Attribution{}, false }
	f := outFlow(t, "tcp", "192.0.2.40:8445")
	v := e.Observe(f, "direct")
	fast, ok := e.TryObserve(f, "nonblocking")
	if !ok || calls != 0 || v.State != "allowed" || fast.State != "allowed" || v.Rule != r.ID || fast.Rule != r.ID {
		t.Fatal("endpoint depended on ownership collectors", calls, v, fast)
	}
	for _, event := range []Event{v, fast} {
		if event.Attribution.Application != nil || len(event.Attribution.Owners) != 0 || event.Attribution.VisibilityComplete || event.Attribution.ReasonCode != identity.ReasonAttributionNotRequired {
			t.Fatal("network policy fabricated owner evidence", event)
		}
	}
	// Disabling, expiry and deletion immediately restore normal resolution for
	// subsequent attempts; no cached independent authority survives removal.
	e.mu.Lock()
	e.rules[0].Expires = *now
	e.mu.Unlock()
	v = e.Observe(f, "expired")
	if calls != 1 || v.State != "blocked" || v.Rule != "unsafe-attribution" {
		t.Fatal("expired early rule survived", calls, v)
	}
	e.mu.Lock()
	e.rules[0].Expires = time.Time{}
	e.rules[0].Disabled = true
	e.mu.Unlock()
	if _, ok = e.TryObserve(f, "disabled"); ok || calls != 2 {
		t.Fatal("disabled rule survived", calls, ok)
	}
	e.mu.Lock()
	e.rules = nil
	e.mu.Unlock()
	if _, ok = e.TryObserve(f, "deleted"); ok || calls != 3 {
		t.Fatal("removed rule survived", calls, ok)
	}
	// A different destination never uses the independent authority.
	if err = e.SetRules([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if _, ok = e.TryObserve(outFlow(t, "tcp", "192.0.2.41:8445"), "other"); ok || calls != 4 {
		t.Fatal("scope widened", calls, ok)
	}
}

func TestEndpointHistoryDedupKeepsFreshPolicyAndFixedWindow(t *testing.T) {
	e, now, _ := endpointEngine(t)
	*now = time.Now()
	p := requireEndpointPreview(t, e, endpointDraftFixture())
	r, _, _, err := e.SaveEndpointRule(e.Generation, p.Token, endpointDraftFixture(), 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("../../.workspace/tmp", "endpoint-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "decisions.db")
	l, err := decisionlog.Open(path, e.Generation, e.Mode, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e.Decisions = l
	f := outFlow(t, "tcp", "192.0.2.40:8445")
	first := e.Observe(f, "generation-one")
	second := e.Observe(f, "generation-one")
	if first.ID != second.ID {
		t.Fatal("history identity changed during fixed logging window")
	}
	// Simulate two observations before the first queue outcome is recorded.
	e.RecordPacketOutcome(first, VerdictAccepted, nil)
	e.RecordPacketOutcome(second, VerdictAccepted, nil)
	e.mu.Lock()
	e.rules[0].Action = "block"
	e.rules[0].Version++
	version := e.rules[0].Version
	e.mu.Unlock()
	changed := e.Observe(f, "generation-one")
	if changed.State != "blocked" || changed.ID == first.ID {
		t.Fatal("history reused old policy", changed)
	}
	e.RecordPacketOutcome(changed, VerdictDropped, nil)
	*now = now.Add(e.Timeout + time.Second)
	nextWindow := e.Observe(f, "generation-one")
	if nextWindow.ID == changed.ID {
		t.Fatal("history window extended on retransmission")
	}
	e.RecordPacketOutcome(nextWindow, VerdictDropped, nil)
	if _, err = e.DeleteRule(e.Generation, r.ID, &version, 1000, true); err != nil {
		t.Fatal(err)
	}
	e.Resolve = func(identity.Flow) identity.Attribution { return identity.Attribution{} }
	removed := e.Observe(f, "generation-one")
	if removed.Rule != "unsafe-attribution" || removed.State != "blocked" {
		t.Fatal("deleted endpoint authority reused", removed)
	}
	e.RecordPacketOutcome(removed, VerdictDropped, nil)
	got := records(t, e, l, path)
	finals := []decisionlog.Record{}
	for _, v := range got {
		if v.Kind == decisionlog.KindFinal {
			finals = append(finals, v)
		}
	}
	if len(finals) != 4 {
		t.Fatalf("wanted one final per policy/window, got %d: %+v", len(finals), finals)
	}
	if finals[0].Application != nil || finals[0].Decision.Rule == nil || finals[0].Decision.Rule.TargetScope != "network-endpoint" {
		t.Fatal("network history fabricated application or lost scope", finals[0])
	}
}
