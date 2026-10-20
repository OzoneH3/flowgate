package daemon

import (
	"encoding/json"
	"errors"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type whileFixture struct {
	e       *Engine
	a       *identity.Attribution
	now     *time.Time
	alive   *bool
	saves   *int
	request Event
}

func whileOwner(pid int, start string, uid uint32) identity.Process {
	return identity.Process{PID: pid, ThreadGroup: pid, Start: start, UID: uid, BootID: "boot", PIDNS: "pid:[1]", MountNS: "mnt:[1]", NetNS: "net:[1]", Executable: "/opt/app"}
}

func whileAttribution(p identity.Process, key, rev, exe string) identity.Attribution {
	app := identity.Application{Key: key, Name: "app", Kind: "native", Executable: exe, Revision: rev}
	return identity.Attribution{Application: &app, VisibilityComplete: true, Owners: []identity.Process{p}, Fingerprint: fmt.Sprint(key, rev, exe, p.PID, p.Start, p.BootID, p.UID)}
}

func outFlow(t *testing.T, proto, remote string) identity.Flow {
	t.Helper()
	f, err := identity.ParseFlow(proto, "outgoing", "10.0.0.1:40000", remote)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// newWhileFixture observes one outgoing TCP request and decides it For a while.
func newWhileFixture(t *testing.T, action string) whileFixture {
	t.Helper()
	e := New(time.Minute)
	now := time.Unix(1000, 0)
	e.Now = func() time.Time { return now }
	a := whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/app")
	e.Resolve = func(identity.Flow) identity.Attribution { return a }
	saves := 0
	e.SaveRules = func([]policy.Rule) error { saves++; return nil }
	alive := true
	e.instanceRunning = func(pid int, start string) bool { return alive && pid == 42 && start == "10" }
	v := e.Observe(outFlow(t, "tcp", "192.0.2.1:443"), "first")
	if v.State != "awaiting-decision" || v.ScopePreviews[ForAWhileScope] == "" {
		t.Fatal("first connection must prompt and offer For a while", v.State, v.ScopePreviews)
	}
	d, err := e.Decide(v.ID, action, ForAWhileScope, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Lease == nil || d.Lease.Seconds != 15 || !d.Lease.Until.Equal(now.Add(15*time.Second)) || d.Rule != "once:"+v.ID {
		t.Fatalf("decided request must carry the lease and a Once verdict: %+v", d)
	}
	return whileFixture{e: e, a: &a, now: &now, alive: &alive, saves: &saves, request: d}
}

func pendingCount(e *Engine) int {
	n := 0
	for _, v := range e.List(0, true) {
		if v.State == "awaiting-decision" {
			n++
		}
	}
	return n
}

func TestForAWhileAllowCoversSameProcessSameDirection(t *testing.T) {
	x := newWhileFixture(t, "allow")
	lease := x.request.Lease.ID
	*x.now = x.now.Add(5 * time.Second)
	for i, f := range []identity.Flow{outFlow(t, "tcp", "198.51.100.7:80"), outFlow(t, "udp", "198.51.100.8:53")} {
		v := x.e.Observe(f, "next")
		if v.State != "allowed" || v.Rule != "while:"+lease || !strings.Contains(v.Reason, "For a while (allow) for process 42 until") {
			t.Fatalf("connection %d not admitted by the lease: %+v", i, v)
		}
	}
	if pendingCount(x.e) != 0 {
		t.Fatal("lease-covered connection created a prompt")
	}
	if len(x.e.Rules(0, true)) != 0 || *x.saves != 0 {
		t.Fatal("For a while must not create or persist a rule", x.e.Rules(0, true), *x.saves)
	}
	if rules, states := x.e.RuleInventory(0, true); len(rules) != 0 || len(states) != 0 {
		t.Fatal("lease visible in rule inventory")
	}
}

func TestForAWhileExactProcessInstanceOnly(t *testing.T) {
	cases := map[string]func(*identity.Attribution){
		"sibling pid": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(43, "10", 1000), "app", "rev", "/opt/app")
		},
		"relaunched": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(42, "11", 1000), "app", "rev", "/opt/app")
		},
		"other uid": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(42, "10", 1001), "app", "rev", "/opt/app")
		},
		"other app": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(42, "10", 1000), "other", "rev", "/opt/app")
		},
		"other revision": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(42, "10", 1000), "app", "rev2", "/opt/app")
		},
		"other exe": func(a *identity.Attribution) {
			*a = whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/other")
		},
		"other boot": func(a *identity.Attribution) {
			p := whileOwner(42, "10", 1000)
			p.BootID = "b2"
			*a = whileAttribution(p, "app", "rev", "/opt/app")
		},
		"two owners": func(a *identity.Attribution) {
			a.Owners = append(a.Owners, whileOwner(43, "10", 1000))
			a.Fingerprint = "two"
		},
		"partial visible": func(a *identity.Attribution) { a.VisibilityComplete = false; a.Fingerprint = "partial" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			x := newWhileFixture(t, "allow")
			mutate(x.a)
			// Prompts again (or, without a single principal, is refused as unsafe);
			// never decided by the lease.
			if v := x.e.Observe(outFlow(t, "tcp", "198.51.100.7:80"), "next"); v.State == "allowed" || strings.HasPrefix(v.Rule, "while:") || (v.State != "awaiting-decision" && v.Rule != "unsafe-attribution") {
				t.Fatalf("%s inherited the lease: %+v", name, v)
			}
		})
	}
	t.Run("other direction", func(t *testing.T) {
		x := newWhileFixture(t, "allow")
		f, _ := identity.ParseFlow("tcp", "incoming", "10.0.0.1:8080", "192.0.2.9:50000")
		if v := x.e.Observe(f, "in"); v.State != "awaiting-decision" {
			t.Fatal("outgoing lease covered an incoming connection", v)
		}
	})
}

func TestForAWhileExpiresAfterFixedDuration(t *testing.T) {
	x := newWhileFixture(t, "allow")
	*x.now = x.now.Add(ForAWhileDuration - time.Millisecond)
	if v := x.e.Observe(outFlow(t, "tcp", "198.51.100.7:80"), "a"); v.State != "allowed" {
		t.Fatal("lease ended early", v)
	}
	if len(x.e.ProcessLeases(1000, false)) != 1 {
		t.Fatal("live lease not listed")
	}
	*x.now = x.now.Add(time.Millisecond)
	if v := x.e.Observe(outFlow(t, "tcp", "198.51.100.7:81"), "b"); v.State != "awaiting-decision" {
		t.Fatal("expired lease still applied", v)
	}
	if len(x.e.ProcessLeases(0, true)) != 0 || len(x.e.processLeases) != 0 {
		t.Fatal("expired lease not pruned")
	}
}

func TestForAWhileConfiguredRuleWinsAndAskRuleIsFilled(t *testing.T) {
	x := newWhileFixture(t, "allow")
	base := policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}
	block := base
	block.RemotePort = 80
	ask := base
	ask.RemotePort = 81
	if err := x.e.SetRules([]policy.Rule{
		{ID: "deny80", Version: 1, Schema: 2, Priority: 100, Action: "block", Created: *x.now, Filter: block},
		{ID: "ask81", Version: 1, Schema: 2, Priority: 100, Action: "ask", Created: *x.now, Filter: ask},
	}); err != nil {
		t.Fatal(err)
	}
	if v := x.e.Observe(outFlow(t, "tcp", "198.51.100.7:80"), "a"); v.State != "blocked" || v.Rule != "deny80" {
		t.Fatal("configured Block did not override the Allow lease", v)
	}
	if v := x.e.Observe(outFlow(t, "tcp", "198.51.100.7:81"), "b"); v.State != "allowed" || !strings.HasPrefix(v.Rule, "while:") {
		t.Fatal("lease did not fill a stored Ask prompt", v)
	}
}

func TestForAWhileDenyBlocksCurrentAndLaterConnections(t *testing.T) {
	x := newWhileFixture(t, "block")
	if x.request.State != "blocked" {
		t.Fatal(x.request)
	}
	if x.e.RetainedState(x.request.ID, x.request.Attribution.Fingerprint) != "drop" {
		t.Fatal("held packets of the denied request admitted")
	}
	v := x.e.Observe(outFlow(t, "udp", "198.51.100.8:53"), "b")
	if v.State != "blocked" || v.Rule != "while:"+x.request.Lease.ID {
		t.Fatal("Deny lease did not block", v)
	}
	if pendingCount(x.e) != 0 {
		t.Fatal("Deny lease left a prompt")
	}
}

func TestForAWhileRefusedWithoutSingleVerifiedOwner(t *testing.T) {
	for name, mutate := range map[string]func(*identity.Attribution){
		// A runtime-table principal held by two visible processes is promptable
		// but has no single owning process.
		"two owners": func(a *identity.Attribution) {
			a.Owners = append(a.Owners, whileOwner(43, "10", 1000))
			a.Table = &identity.TableEvidence{UID: 1000, Owners: []identity.WindowsOwner{{PID: 7, Image: "app.exe"}}}
		},
		"partial":       func(a *identity.Attribution) { a.VisibilityComplete = false },
		"no start time": func(a *identity.Attribution) { a.Owners[0].Start = "" },
		"no boot id":    func(a *identity.Attribution) { a.Owners[0].BootID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			e := New(time.Minute)
			now := time.Unix(1000, 0)
			e.Now = func() time.Time { return now }
			a := whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/app")
			mutate(&a)
			e.Resolve = func(identity.Flow) identity.Attribution { return a }
			v := e.Observe(outFlow(t, "tcp", "192.0.2.1:443"), "first")
			if v.State != "awaiting-decision" {
				t.Fatal("attribution not promptable", v.State, v.Rule)
			}
			if _, ok := v.ScopePreviews[ForAWhileScope]; ok {
				t.Fatal("For a while offered without a single verified owner")
			}
			_, err := e.Decide(v.ID, "allow", ForAWhileScope, 1000, false)
			var typed *RuleMutationError
			if !errors.As(err, &typed) || typed.Code != "process_scope_unavailable" {
				t.Fatal("expected process_scope_unavailable", err)
			}
			if pendingCount(e) != 1 || len(e.processLeases) != 0 {
				t.Fatal("refusal decided the request or created a lease")
			}
		})
	}
}

func TestForAWhileStaleAndProcessExit(t *testing.T) {
	x := newWhileFixture(t, "allow")
	if _, err := x.e.Decide(x.request.ID, "allow", ForAWhileScope, 1000, false); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatal("decided request accepted a second decision", err)
	}
	// A request that timed out cannot be decided For a while either.
	*x.a = whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/app")
	f, _ := identity.ParseFlow("tcp", "incoming", "10.0.0.1:22", "203.0.113.5:50000")
	v := x.e.Observe(f, "late")
	if v.State != "awaiting-decision" {
		t.Fatal(v)
	}
	*x.now = x.now.Add(2 * time.Minute)
	var typed *RuleMutationError
	if _, err := x.e.Decide(v.ID, "allow", ForAWhileScope, 1000, false); err == nil || (errors.As(err, &typed) && typed.Code != "stale_decision") {
		t.Fatal("expired request decided", err)
	}

	y := newWhileFixture(t, "allow")
	*y.alive = false
	if len(y.e.ProcessLeases(0, true)) != 0 {
		t.Fatal("lease of an exited process still listed")
	}
	if v := y.e.Observe(outFlow(t, "tcp", "198.51.100.7:80"), "a"); v.State != "awaiting-decision" {
		t.Fatal("lease of an exited process applied", v)
	}
}

func TestForAWhileListAuthorization(t *testing.T) {
	x := newWhileFixture(t, "allow")
	own := x.e.ProcessLeases(1000, false)
	if len(own) != 1 || own[0].PID != 42 || own[0].Start != "10" || own[0].Action != "allow" || own[0].Direction != "outgoing" || own[0].EventID != x.request.ID || own[0].RemainingMS != 15000 || own[0].Application != "app" || own[0].Executable != "/opt/app" {
		t.Fatalf("owner view: %+v", own)
	}
	if len(x.e.ProcessLeases(1001, false)) != 0 {
		t.Fatal("other user sees the lease")
	}
	if len(x.e.ProcessLeases(1001, true)) != 1 {
		t.Fatal("administrator does not see the lease")
	}
	b, _ := json.Marshal(x.request)
	if !strings.Contains(string(b), `"lease":{"id":"`+x.request.Lease.ID+`","until":`) {
		t.Fatal("event JSON lacks lease", string(b))
	}
}

func TestForAWhileDecisionLog(t *testing.T) {
	e := New(time.Minute)
	now := time.Now()
	e.Now = func() time.Time { return now }
	a := whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/app")
	e.Resolve = func(identity.Flow) identity.Attribution { return a }
	path := filepath.Join(t.TempDir(), "decisions.db")
	l, err := decisionlog.Open(path, e.Generation, e.Mode, true)
	if err != nil {
		t.Fatal(err)
	}
	e.Decisions = l
	v := e.Observe(outFlow(t, "tcp", "192.0.2.1:443"), "first")
	e.RecordPacketOutcome(v, VerdictHeld, nil)
	d, err := e.Decide(v.ID, "allow", ForAWhileScope, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	n := e.Observe(outFlow(t, "udp", "192.0.2.1:53"), "second")
	e.RecordPacketOutcome(n, VerdictAccepted, nil)
	var user, lease bool
	for _, r := range records(t, e, l, path) {
		if r.Kind != decisionlog.KindFinal {
			continue
		}
		switch r.Decision.Source {
		case "user":
			user = r.Decision.Scope == ForAWhileScope && r.Decision.LeaseID == d.Lease.ID && r.RequestID == v.ID
		case ForAWhileSource:
			lease = r.Decision.LeaseID == d.Lease.ID && r.Decision.Action == "allow" && r.RequestID == n.ID
		}
	}
	if !user || !lease {
		t.Fatal("decision log lacks for-a-while records", user, lease)
	}
	q, err := decisionlog.DecodeQuery(json.RawMessage(`{"source":"for_a_while"}`))
	if err != nil || q.Source != ForAWhileSource {
		t.Fatal("for_a_while source not queryable", err)
	}
}

func TestForAWhileSettlesWaitingRequestsOfSameProcess(t *testing.T) {
	e := New(time.Minute)
	now := time.Unix(1000, 0)
	e.Now = func() time.Time { return now }
	a := whileAttribution(whileOwner(42, "10", 1000), "app", "rev", "/opt/app")
	e.Resolve = func(identity.Flow) identity.Attribution { return a }
	first := e.Observe(outFlow(t, "tcp", "192.0.2.1:443"), "a")
	second := e.Observe(outFlow(t, "udp", "192.0.2.2:53"), "b")
	in, _ := identity.ParseFlow("tcp", "incoming", "10.0.0.1:8080", "192.0.2.9:50000")
	incoming := e.Observe(in, "c")
	d, err := e.Decide(first.ID, "allow", ForAWhileScope, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if e.RetainedState(second.ID, second.Attribution.Fingerprint) != "allow" || e.RetainedState(incoming.ID, incoming.Attribution.Fingerprint) != "pending" {
		t.Fatal("waiting request of the same process/direction not settled, or other direction settled")
	}
	for _, v := range e.List(0, true) {
		if v.ID == second.ID && v.Rule != "while:"+d.Lease.ID {
			t.Fatal("settled by something other than the lease", v.Rule)
		}
	}
}

func TestWineTableNeverLeasesTheBrokerProcess(t *testing.T) {
	p := whileOwner(42, "10", 1000)
	a := whileAttribution(p, "game", "revision", "/games/a.exe")
	a.Table = &identity.TableEvidence{UID: 1000, Owners: []identity.WindowsOwner{{PID: 7, Created: 1, Image: `Z:\games\a.exe`}}}
	if _, err := leaseOwner(a); err == nil {
		t.Fatal("game Windows owner silently became a wineserver process lease")
	}
}
