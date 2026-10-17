package daemon

import (
	"encoding/json"
	"flowgate/internal/decisionlog"
	"flowgate/internal/policy"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// records closes the log (flushing it) and returns every record oldest first.
func records(t *testing.T, e *Engine, l *decisionlog.Log, path string) []decisionlog.Record {
	t.Helper()
	l.Close()
	r, err := decisionlog.Open(path, "reader", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	q, _ := decisionlog.DecodeQuery(json.RawMessage(`{"after":"0","limit":100}`))
	p, err := r.Query(q, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	return p.Records
}
func TestRuleDecisionKeepsDecisionTimeSnapshotAcrossEditAndDelete(t *testing.T) {
	e, f, _, now := fixture()
	*now = time.Now() // retention is relative to wall time; the shared fixture starts in 1970
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.db")
	l, err := decisionlog.Open(path, e.Generation, e.Mode, true)
	if err != nil {
		t.Fatal(err)
	}
	e.Decisions = l
	e.SaveRules = func([]policy.Rule) error { return nil }
	rule := policy.Rule{ID: "r1", Version: 7, Schema: 2, Created: *now, Priority: 1, Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", Direction: "incoming", Protocol: "udp", UID: 1000, RemoteAddress: "*"}}
	if err := e.SetRules([]policy.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	v := e.Observe(f, "udp")
	e.RecordPacketOutcome(v, VerdictDropped, nil)
	// Retransmission / later datagrams of the same lease: cached, not re-recorded.
	for i := 0; i < 3; i++ {
		e.RecordPacketOutcome(e.Observe(f, "udp"), VerdictDropped, nil)
	}
	*now = now.Add(3 * time.Second) // cached lease expired: same flow re-evaluated
	e.RecordPacketOutcome(e.Observe(f, "udp"), VerdictDropped, nil)
	if err := e.ChangeRule("r1", "disable", 1000, false); err != nil {
		t.Fatal(err)
	}
	if err := e.ChangeRule("r1", "delete", 1000, false); err != nil {
		t.Fatal(err)
	}
	rs := records(t, e, l, path)
	if len(rs) != 1 {
		t.Fatalf("want one final decision, got %d", len(rs))
	}
	d := rs[0]
	if d.Kind != "final" || d.Decision.Source != "rule" || d.Decision.Action != "block" || d.Verdict.State != VerdictDropped || d.Delivery != "not_observed" {
		t.Fatalf("%+v %+v", d.Decision, d.Verdict)
	}
	if d.Decision.Rule == nil || d.Decision.Rule.ID != "r1" || d.Decision.Rule.Version != "7" || d.Decision.Rule.Disabled {
		t.Fatalf("decision-time rule snapshot lost: %+v", d.Decision.Rule)
	}
	if *d.PrincipalUID != 1000 || d.Flow.Direction != "incoming" || d.Flow.Family != "ipv4" || d.Application.Key != "app" {
		t.Fatalf("evidence: %+v %+v", d.Flow, d.Application)
	}
}

func TestPendingUserTimeoutAndPolicyChangeRecords(t *testing.T) {
	e, f, a, now := fixture()
	*now = time.Now() // retention is relative to wall time; the shared fixture starts in 1970
	path := filepath.Join(t.TempDir(), "decisions.db")
	l, _ := decisionlog.Open(path, e.Generation, e.Mode, true)
	e.Decisions = l
	e.SaveRules = func([]policy.Rule) error { return nil }
	// 1: Ask -> held -> user Allow once.
	v := e.Observe(f, "udp")
	e.RecordPacketOutcome(v, VerdictHeld, nil)
	e.RecordPacketOutcome(e.Observe(f, "udp"), VerdictHeld, nil) // second datagram, same request
	if _, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	e.RecordPacketOutcome(e.Observe(f, "udp"), VerdictAccepted, nil) // later datagram under the lease
	// 2: fresh request remembered as an application rule.
	*now = now.Add(31 * time.Second)
	v2 := e.Observe(f, "udp")
	e.RecordPacketOutcome(v2, VerdictHeld, nil)
	if _, err := e.Decide(v2.ID, "block", "application", 1000, false); err != nil {
		t.Fatal(err)
	}
	// 3: another flow times out.
	*now = now.Add(2 * time.Hour) // remembered rule expired
	v3 := e.Observe(f, "udp")
	e.RecordPacketOutcome(v3, VerdictHeld, nil)
	*now = now.Add(3 * time.Second)
	e.List(1000, false)
	// 4: a pending request discarded by a policy replacement.
	v4 := e.Observe(f, "udp")
	e.RecordPacketOutcome(v4, VerdictHeld, nil)
	e.SetRules(nil)
	// 5: identity changed before decision.
	v5 := e.Observe(f, "udp")
	e.RecordPacketOutcome(v5, VerdictHeld, nil)
	a.Fingerprint = "replaced"
	e.Decide(v5.ID, "allow", "once", 1000, false)
	rs := records(t, e, l, path)
	type want struct{ kind, action, source, scope, request string }
	exp := []want{
		{"pending", "pending", "default_ask", "", v.ID}, {"final", "allow", "user", "once", v.ID},
		{"pending", "pending", "default_ask", "", v2.ID}, {"final", "block", "user", "application", v2.ID},
		{"pending", "pending", "default_ask", "", v3.ID}, {"final", "block", "timeout", "", v3.ID},
		{"pending", "pending", "default_ask", "", v4.ID}, {"final", "block", "policy_change", "", v4.ID},
		{"pending", "pending", "default_ask", "", v5.ID}, {"final", "block", "identity_changed", "", v5.ID},
	}
	if len(rs) != len(exp) {
		for _, r := range rs {
			t.Log(r.Kind, r.Decision.Action, r.Decision.Source, r.RequestID)
		}
		t.Fatalf("got %d records, want %d", len(rs), len(exp))
	}
	for i, w := range exp {
		r := rs[i]
		if r.Kind != w.kind || r.Decision.Action != w.action || r.Decision.Source != w.source || r.Decision.Scope != w.scope || r.RequestID != w.request {
			t.Fatalf("record %d: %+v %+v", i, r.Kind, r.Decision)
		}
	}
	if rs[0].Verdict.State != VerdictHeld || rs[1].Verdict.State != "deferred" || *rs[1].Decision.DecidedByUID != 1000 {
		t.Fatal("verdict/decider evidence", rs[0].Verdict, rs[1].Verdict)
	}
	if rs[3].Decision.Rule == nil || rs[3].Decision.Rule.ID != "user:"+v2.ID || rs[3].Decision.Rule.Version != "1" {
		t.Fatalf("remembered rule snapshot: %+v", rs[3].Decision.Rule)
	}
}

func TestShutdownFinalizesPendingAndCapacityCollapses(t *testing.T) {
	e, f, _, now := fixture()
	*now = time.Now() // retention is relative to wall time; the shared fixture starts in 1970
	path := filepath.Join(t.TempDir(), "decisions.db")
	l, _ := decisionlog.Open(path, e.Generation, e.Mode, true)
	e.Decisions = l
	v := e.Observe(f, "udp")
	e.RecordPacketOutcome(v, VerdictHeld, nil)
	e.Max = 1
	for i := 0; i < 5; i++ { // repeated capacity refusals of one flow: one record
		c := e.Observe(f, "other")
		e.RecordPacketOutcome(c, VerdictDropped, nil)
	}
	e.FinalizePending()
	rs := records(t, e, l, path)
	if len(rs) != 3 || rs[1].Decision.Source != "capacity" || rs[2].Decision.Source != "shutdown" || rs[2].RequestID != v.ID {
		for _, r := range rs {
			t.Log(r.Kind, r.Decision.Source)
		}
		t.Fatal("unexpected records", len(rs))
	}
}

func TestMonitorModeRecordsNoDecisions(t *testing.T) {
	e, _, _, now := fixture()
	*now = time.Now() // retention is relative to wall time; the shared fixture starts in 1970
	e.Mode = "daemon-monitor"
	path := filepath.Join(t.TempDir(), "decisions.db")
	l, _ := decisionlog.Open(path, e.Generation, e.Mode, false)
	e.Decisions = l
	e.SaveRules = func([]policy.Rule) error { return nil }
	e.SetRules([]policy.Rule{{ID: "r", Version: 1, Schema: 2, Created: time.Unix(1, 0), Action: "allow", Filter: policy.Filter{Application: "app", Revision: "rev", Direction: "incoming", Protocol: "tcp", UID: 1000, RemoteAddress: "*"}}})
	e.ChangeRule("r", "disable", 1000, true)
	e.List(1000, true)
	e.FinalizePending()
	if rs := records(t, e, l, path); len(rs) != 0 {
		t.Fatalf("monitor mode fabricated %d decisions", len(rs))
	}
}

func TestDecisionLogAPIOnReadOnlyEndpoint(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "dlog-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	e, f, a, now := fixture()
	*now = time.Now()
	uid := uint32(os.Getuid())
	a.Owners[0].UID = uid
	dbPath := filepath.Join(t.TempDir(), "decisions.db")
	l, _ := decisionlog.Open(dbPath, e.Generation, "isolated-lab", true)
	e.Decisions = l
	v := e.Observe(f, "udp")
	e.RecordPacketOutcome(v, VerdictHeld, nil)
	a.Owners[0].UID = uid + 1 // a foreign principal's request
	g := f
	g.Remote = netip.AddrPortFrom(g.Remote.Addr(), 9001)
	e.RecordPacketOutcome(e.Observe(g, "udp"), VerdictHeld, nil)
	l.Close()
	// History survives the daemon restart; the reader is a non-recording owner.
	e.Decisions, err = decisionlog.Open(dbPath, "next-generation", "daemon-monitor", false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Decisions.Close()
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	srv, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	r, err := Call(path, Request{Version: 1, Operation: "decision-log", DecisionQuery: json.RawMessage(`{"limit":10}`)})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range r.Capabilities {
		found = found || c == DecisionLogCapability
	}
	p := r.DecisionLog
	if !found || p == nil || len(p.Records) != 1 || p.Records[0].RequestID != v.ID || p.Scope != "self" || p.Health.Recording || p.Health.LogID == "" {
		t.Fatalf("ordinary read-only peer: %+v", r)
	}
	if _, err = Call(path, Request{Version: 1, Operation: "decision-log-get", DecisionID: p.Records[0].ID}); err != nil {
		t.Fatal(err)
	}
	for q, code := range map[string]string{`{"limit":500}`: "invalid_request", `{"before":"x"}`: "invalid_cursor", `{"log_id":"stale"}`: "invalid_cursor"} {
		if r, _ := Call(path, Request{Version: 1, Operation: "decision-log", DecisionQuery: json.RawMessage(q)}); r.ErrorCode != code {
			t.Fatal(q, r.ErrorCode, r.Error)
		}
	}
	if r, _ := Call(path, Request{Version: 1, Operation: "decision-log-get", DecisionID: "missing"}); r.ErrorCode != "not_found" {
		t.Fatal(r.ErrorCode)
	}
}
