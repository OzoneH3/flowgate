package daemon

import (
	"encoding/json"
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRememberZonePreviewCommitReceipt(t *testing.T) {
	e, f, _, now := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", "local", e.Zones.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rule.Schema != 4 || p.Rule.Filter.NetworkZone != "local" || p.Rule.Filter.Application != "app" || p.Rule.Filter.Protocol != "udp" || p.Rule.Filter.LocalPort != 80 || p.Rule.Filter.RemoteAddress != "127.0.0.1" {
		t.Fatal(p)
	}
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "block", "application", "local", e.Zones.Revision, p.Token, 1000, false); err == nil {
		t.Fatal("action changed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, r, _, err := e.DecideReviewed(e.Generation, v.ID, "allow", "application", "local", e.Zones.Revision, p.Token, 1000, false); err != nil || r.ID != p.Rule.ID {
				t.Errorf("commit %v", err)
			}
		}()
	}
	wg.Wait()
	if len(e.rules) != 1 || e.rules[0].Filter.NetworkZone != "local" {
		t.Fatal(e.rules)
	}
	*now = now.Add(time.Minute)
	e.List(1000, false) // event eviction does not erase receipt
	receipt, err := e.DecisionStatus(e.Generation, p.Token, 1000, false)
	if err != nil || receipt.State != "committed" || receipt.SavedRule.ID != p.Rule.ID {
		t.Fatal(receipt, err)
	}
	if _, err = e.DecisionStatus(e.Generation, p.Token, 2000, true); err == nil {
		t.Fatal("foreign receipt")
	}
	if _, err = e.DeleteRule(e.Generation, p.Rule.ID, &p.Rule.Version, 1000, false); err != nil {
		t.Fatal(err)
	}
	if r, err := e.DecisionStatus(e.Generation, p.Token, 1000, false); err != nil || r.State != "committed" {
		t.Fatal("historical receipt lost after deletion", err)
	}
	*now = now.Add(5 * time.Minute)
	if _, err = e.DecisionStatus(e.Generation, p.Token, 1000, false); err == nil {
		t.Fatal("expired receipt")
	}
}
func TestRememberZoneStaleAndUnknown(t *testing.T) {
	for _, test := range []string{"wrongzone", "unknown", "revision", "identity", "expired", "expired-during-resolve", "generation", "foreign", "persist", "once", "flowchanged"} {
		t.Run(test, func(t *testing.T) {
			e, f, a, now := fixture()
			e.Timeout = time.Minute
			e.SaveRules = func([]policy.Rule) error { return nil }
			zone := "local"
			if test == "unknown" {
				f.Remote = netip.MustParseAddrPort("10.99.0.2:9000")
			}
			v := e.Observe(f, "udp")
			if test == "wrongzone" {
				zone = "internet"
			}
			p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", zone, e.Zones.Revision, 1000, false)
			if test == "wrongzone" || test == "unknown" {
				if err == nil {
					t.Fatal("nonmatching zone offered")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			generation, revision, scope, uid := e.Generation, e.Zones.Revision, "application", uint32(1000)
			switch test {
			case "revision":
				e.Zones, _ = identity.NewNetworkZones([]string{"10.0.0.0/8"}, nil)
			case "identity":
				a.Fingerprint = "changed"
			case "expired":
				*now = now.Add(31 * time.Second)
			case "expired-during-resolve":
				e.Resolve = func(identity.Flow) identity.Attribution { *now = now.Add(31 * time.Second); return *a }
			case "generation":
				generation = "old"
			case "foreign":
				uid = 2000
			case "persist":
				e.SaveRules = func([]policy.Rule) error { return errors.New("disk stalled/failed") }
			case "once":
				scope = "once"
			case "flowchanged":
				for _, x := range e.events {
					x.Flow.NetworkScope.Reason = "changed"
				}
			}
			if _, _, _, err = e.DecideReviewed(generation, v.ID, "allow", scope, zone, revision, p.Token, uid, false); err == nil {
				t.Fatal("stale/unsafe committed")
			}
			if len(e.rules) != 0 {
				t.Fatal("failure published rule")
			}
		})
	}
	e, f, _, _ := fixture()
	f.Remote = netip.MustParseAddrPort("10.99.0.2:9000")
	v := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v.ID, "block", "application", "any", e.Zones.Revision, 1000, false)
	if err != nil || p.Rule.Schema != 2 || p.Rule.Filter.NetworkZone != "" {
		t.Fatal("unknown Any unavailable", err)
	}
}

func TestRememberZoneAPICompatibilityAndAuthorization(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "decision-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	ro := path + "r"
	e, f, _, _ := fixture()
	e.SaveRules = func([]policy.Rule) error { return nil }
	v := e.Observe(f, "udp")
	l, err := Serve(path, e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	monitor, err := Serve(ro, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	q := Request{Version: 1, Operation: "decision-preview", Generation: e.Generation, ID: v.ID, Action: "allow", Scope: "application", NetworkZone: "local", ZoneRevision: e.Zones.Revision}
	if _, err = Call(ro, q); err == nil {
		t.Fatal("read-only preview")
	}
	p, err := Call(path, q)
	if err != nil || p.DecisionPreview == nil {
		t.Fatal(p, err)
	}
	q.Operation = "decide"
	if _, err = Call(path, q); err == nil {
		t.Fatal("unreviewed zone silently became Any")
	}
	q.PreviewToken = p.DecisionPreview.Token
	r, err := Call(path, q)
	if err != nil || r.SavedRule == nil || r.SavedRule.Filter.NetworkZone != "local" {
		t.Fatal(r, err)
	}
	status, err := Call(path, Request{Version: 1, Operation: "decision-status", Generation: e.Generation, PreviewToken: q.PreviewToken})
	if err != nil || status.DecisionReceipt.State != "committed" {
		t.Fatal(status, err)
	}
	if _, err = Call(ro, Request{Version: 1, Operation: "decision-status", Generation: e.Generation, PreviewToken: q.PreviewToken}); err == nil {
		t.Fatal("monitor token query")
	}
	// Legacy callers retain Once and Any semantics; no schema4 migration.
	f.Local = netip.MustParseAddrPort("127.0.0.1:81")
	legacy := e.Observe(f, "new")
	r, err = Call(path, Request{Version: 1, Operation: "decide", ID: legacy.ID, Action: "block", Scope: "application"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range e.rules {
		if rule.Filter.LocalPort == 81 {
			found = true
			if rule.Schema != 2 || rule.Filter.NetworkZone != "" {
				t.Fatal("legacy widened/migrated", rule)
			}
		}
	}
	if !found {
		t.Fatal("legacy rule missing")
	}
}
func TestRememberZoneDecisionSnapshot(t *testing.T) {
	e, f, _, now := fixture()
	*now = time.Now()
	e.SaveRules = func([]policy.Rule) error { return nil }
	dir, err := os.MkdirTemp("../../.workspace/tmp", "decision-log-zone-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "log.db")
	l, err := decisionlog.Open(path, e.Generation, "test", true)
	if err != nil {
		t.Fatal(err)
	}
	e.Decisions = l
	v := e.Observe(f, "udp")
	p, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", "local", e.Zones.Revision, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "allow", "application", "local", e.Zones.Revision, p.Token, 1000, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = e.DecideReviewed(e.Generation, v.ID, "allow", "application", "local", e.Zones.Revision, p.Token, 1000, false); err != nil {
		t.Fatal(err)
	}
	rs := records(t, e, l, path)
	if len(rs) != 1 {
		t.Fatalf("replayed log/decision: %d", len(rs))
	}
	raw, _ := json.Marshal(rs[0])
	if !strings.Contains(string(raw), `"network_zone":"local"`) {
		t.Fatal(string(raw))
	}
}
