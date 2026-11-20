package daemon

import (
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// queueFixture: one verified owning process per flow, chosen by the flow's
// remote endpoint; flows whose socket "ended" resolve without an owner.
type queueFixture struct {
	e      *Engine
	now    *time.Time
	owners map[string]identity.Attribution // remote endpoint -> attribution
	ended  map[string]bool
	alive  map[string]bool // pid:start -> running
	live   map[int]identity.Process
}

func newQueueFixture(t *testing.T) *queueFixture {
	t.Helper()
	x := &queueFixture{owners: map[string]identity.Attribution{}, ended: map[string]bool{}, alive: map[string]bool{}, live: map[int]identity.Process{}}
	e := New(time.Minute)
	now := time.Unix(5000, 0)
	e.Now = func() time.Time { return now }
	e.SaveRules = func([]policy.Rule) error { return nil }
	e.verifyRetained = func(identity.Application, uint32, string) error { return nil }
	e.Resolve = func(f identity.Flow) identity.Attribution {
		key := f.Local.String() + ">" + f.Remote.String()
		if x.ended[key] {
			return identity.Attribution{Status: "unavailable", Reason: "no visible matching socket", Fingerprint: "gone:" + key}
		}
		return x.owners[key]
	}
	e.instanceRunning = func(pid int, start string) bool { return x.alive[pid2(pid, start)] }
	e.inspectProcess = func(pid int) (identity.Process, error) {
		p, ok := x.live[pid]
		if !ok {
			return identity.Process{}, errors.New("no such process")
		}
		return p, nil
	}
	x.e, x.now = e, &now
	return x
}

func pid2(pid int, start string) string { return fmt.Sprintf("%d:%s", pid, start) }

// proc registers a running process instance with its verified application.
func (x *queueFixture) proc(pid int, start string, uid uint32) identity.Process {
	p := whileOwner(pid, start, uid)
	p.Application = identity.Application{Key: "app", Name: "app", Kind: "native", Executable: "/opt/app", Revision: "rev"}
	x.alive[pid2(pid, start)] = true
	x.live[pid] = p
	return p
}

func (x *queueFixture) exit(p identity.Process) {
	delete(x.alive, pid2(p.PID, p.Start))
	delete(x.live, p.PID)
}

// flow observes one outgoing connection of p from local source port lport.
func (x *queueFixture) flow(t *testing.T, p identity.Process, proto, local, remote, token string) (identity.Flow, Event) {
	t.Helper()
	f, err := identity.ParseFlow(proto, "outgoing", local, remote)
	if err != nil {
		t.Fatal(err)
	}
	a := whileAttribution(p, "app", "rev", "/opt/app")
	a.Fingerprint += "|" + local + ">" + remote
	x.owners[local+">"+remote] = a
	return f, x.e.Observe(f, token)
}

func settledIDs(s []SettledRequest) map[string]SettledRequest {
	out := map[string]SettledRequest{}
	for _, v := range s {
		out[v.ID] = v
	}
	return out
}

func stateOf(e *Engine, id string) string {
	for _, v := range e.List(0, true) {
		if v.ID == id {
			return v.State
		}
	}
	return ""
}

func TestOnceSettlesNothingAndRetransmissionsNeverRePrompt(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	tcp, first := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "seq-1")
	_, second := x.flow(t, p, "tcp", "10.0.0.1:40002", "198.51.100.2:8443", "seq-2") // distinct connection and destination, same presentation group
	udp, datagram := x.flow(t, p, "udp", "10.0.0.1:40003", "192.0.2.1:53", "udp")
	if first.State != "awaiting-decision" || second.State != "awaiting-decision" || first.RequestGroup != second.RequestGroup {
		t.Fatal("distinct connections must be separate requests in one group", first, second)
	}
	// Retransmitted SYN (same sequence token) and further datagrams while pending.
	if x.e.Observe(tcp, "seq-1").ID != first.ID || x.e.Observe(udp, "udp").ID != datagram.ID {
		t.Fatal("retransmission created a new pending request")
	}
	d, settled, err := x.e.DecideSettled(first.ID, "allow", "once", 0, 1000, false)
	if err != nil || d.State != "allowed" || len(settled) != 0 {
		t.Fatal("Once must settle nothing else", err, d.State, settled)
	}
	for _, at := range []time.Duration{time.Second, 3 * time.Second, 29 * time.Second} {
		*x.now = time.Unix(5000, 0).Add(at)
		if v := x.e.Observe(tcp, "seq-1"); v.ID != first.ID || v.State != "allowed" {
			t.Fatalf("SYN retransmit at +%s re-prompted or lost the Once admission: %+v", at, v)
		}
	}
	if stateOf(x.e, second.ID) != "awaiting-decision" || stateOf(x.e, datagram.ID) != "awaiting-decision" {
		t.Fatal("Once covered another connection")
	}
	d, _, err = x.e.DecideSettled(datagram.ID, "allow", "once", 0, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		*x.now = x.now.Add(time.Second)
		if v := x.e.Observe(udp, "udp"); v.ID != datagram.ID || v.State != "allowed" {
			t.Fatal("datagram inside the 30 s Once lease re-prompted", v)
		}
	}
	n := 0
	for _, v := range x.e.List(0, true) {
		if v.State == "awaiting-decision" {
			n++
		}
	}
	if n != 1 {
		t.Fatal("expected only the distinct second connection pending", n)
	}
}

func TestRememberAndForAWhileReportSettledRequests(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	sib := x.proc(43, "10", 1000)
	_, first := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	_, covered := x.flow(t, p, "tcp", "10.0.0.1:40002", "192.0.2.1:443", "b")
	_, sibling := x.flow(t, sib, "tcp", "10.0.0.2:40003", "192.0.2.1:443", "c")
	_, elsewhere := x.flow(t, p, "tcp", "10.0.0.1:40004", "192.0.2.9:443", "d")
	_, settled, err := x.e.DecideSettled(first.ID, "allow", "application", 0, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	s := settledIDs(settled)
	if len(s) != 2 || s[covered.ID].State != "allowed" || s[sibling.ID].State != "allowed" || !strings.HasPrefix(s[covered.ID].Rule, "user:") {
		t.Fatalf("Remember must settle exactly the covered requests: %+v", settled)
	}
	if stateOf(x.e, elsewhere.ID) != "awaiting-decision" {
		t.Fatal("uncovered destination settled")
	}

	// For a while Deny: same process + direction settles (blocked); sibling stays.
	y := newQueueFixture(t)
	p = y.proc(42, "10", 1000)
	sib = y.proc(43, "10", 1000)
	_, first = y.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	_, other := y.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.5:53", "udp")
	_, sibling = y.flow(t, sib, "tcp", "10.0.0.2:40003", "192.0.2.1:443", "c")
	d, settled, err := y.e.DecideSettled(first.ID, "block", ForAWhileScope, 0, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	s = settledIDs(settled)
	if len(s) != 1 || s[other.ID].State != "blocked" || s[other.ID].Rule != "while:"+d.Lease.ID {
		t.Fatalf("For a while must settle the same-process request only: %+v", settled)
	}
	if stateOf(y.e, sibling.ID) != "awaiting-decision" {
		t.Fatal("sibling settled by another process's lease")
	}
}

func TestStoredAskStillPromptsAfterOnce(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	x.e.rules = []policy.Rule{{ID: "ask-1", Version: 1, Schema: 2, Action: "ask", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}}
	_, a := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	_, b := x.flow(t, p, "tcp", "10.0.0.1:40002", "192.0.2.1:443", "b")
	if a.AskRule == nil || b.AskRule == nil {
		t.Fatal("stored Ask did not prompt", a, b)
	}
	if _, settled, err := x.e.DecideSettled(a.ID, "allow", "once", 0, 1000, false); err != nil || len(settled) != 0 || stateOf(x.e, b.ID) != "awaiting-decision" {
		t.Fatal("Once on an Ask prompt settled another Ask prompt", err, settled)
	}
}

func TestUDPApplicationAskOnceRetainedAndLaterDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, direction, address, action, retained string
		reprompt                                             bool
	}{
		{"outbound UDP Allow Once", "udp", "outgoing", "*", "allow", "drop", false},
		{"outbound UDP Block Once", "udp", "outgoing", "*", "block", "drop", false},
		{"inbound UDP Allow Once", "udp", "incoming", "*", "allow", "allow", false},
		{"inbound UDP Block Once", "udp", "incoming", "*", "block", "drop", true},
		{"default Ask Allow Once", "udp", "outgoing", "", "allow", "allow", false},
		{"default Ask Block Once", "udp", "incoming", "", "block", "drop", false},
		{"address-scoped Ask", "udp", "outgoing", "192.0.2.1", "allow", "allow", false},
		{"outbound TCP Allow Once", "tcp", "outgoing", "*", "allow", "allow", false},
		{"inbound TCP Block Once", "tcp", "incoming", "*", "block", "drop", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newQueueFixture(t)
			p := x.proc(42, "10", 1000)
			f, err := identity.ParseFlow(tc.protocol, tc.direction, "10.0.0.1:40001", "192.0.2.1:443")
			if err != nil {
				t.Fatal(err)
			}
			a := whileAttribution(p, "app", "rev", "/opt/app")
			x.owners[f.Local.String()+">"+f.Remote.String()] = a
			if tc.address != "" {
				x.e.rules = []policy.Rule{{ID: "ask", Version: 1, Schema: 2, Action: "ask", Executable: "/opt/app",
					Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: tc.direction, Protocol: "*", RemoteAddress: tc.address}}}
			}
			pending := x.e.Observe(f, "first")
			if got := x.e.RetainedState(pending.ID, a.Fingerprint); got != "pending" {
				t.Fatalf("before decision: %s", got)
			}
			if _, err := x.e.Decide(pending.ID, tc.action, "once", 1000, false); err != nil {
				t.Fatal(err)
			}
			if got := x.e.RetainedState(pending.ID, a.Fingerprint); got != tc.retained {
				t.Fatalf("held packet: got %s, want %s", got, tc.retained)
			}
			state := map[string]string{"allow": "allowed", "block": "blocked"}[tc.action]
			later := x.e.Observe(f, "first")
			if tc.reprompt {
				if later.ID == pending.ID || later.State != "awaiting-decision" || later.AskRule == nil || later.AskRule.ID != "ask" {
					t.Fatal("later inbound datagram did not reach a new request under the original Ask", later)
				}
				if _, err := x.e.Decide(later.ID, "allow", "once", 1000, false); err != nil {
					t.Fatal(err)
				}
				if x.e.RetainedState(later.ID, a.Fingerprint) != "allow" || x.e.RetainedState(pending.ID, a.Fingerprint) != "drop" {
					t.Fatal("answering the new request did not admit only its held datagram")
				}
			} else if later.ID != pending.ID || later.State != state {
				t.Fatal("same socket did not retain the Once decision", later)
			}
			if f.Direction == "outgoing" {
				f.Local = netip.AddrPortFrom(f.Local.Addr(), f.Local.Port()+1)
			} else {
				f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
			}
			x.owners[f.Local.String()+">"+f.Remote.String()] = a
			if fresh := x.e.Observe(f, "fresh"); fresh.ID == pending.ID || fresh.State != "awaiting-decision" ||
				(tc.address != "" && (fresh.AskRule == nil || fresh.AskRule.ID != "ask")) {
				t.Fatal("fresh socket did not reach the original Ask", fresh)
			}
		})
	}
}

func TestPreviousRevisionRulesAreDisplayOnly(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	base := policy.Filter{Application: "app", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}
	mk := func(id, rev, action string, mod func(*policy.Rule)) policy.Rule {
		f := base
		f.Revision = rev
		r := policy.Rule{ID: id, Version: 3, Schema: 2, Action: action, Filter: f}
		if mod != nil {
			mod(&r)
		}
		return r
	}
	x.e.rules = []policy.Rule{
		mk("old-allow", "rev-old", "allow", nil),
		mk("old-disabled", "rev-old", "allow", func(r *policy.Rule) { r.Disabled = true }),
		mk("old-incoming", "rev-old", "allow", func(r *policy.Rule) { r.Filter.Direction = "incoming" }),
		mk("old-other-user", "rev-old", "allow", func(r *policy.Rule) { r.Filter.UID = 1001 }),
		mk("old-expired", "rev-old", "allow", func(r *policy.Rule) { r.Expires = time.Unix(4000, 0) }),
		mk("other-app", "rev-old", "allow", func(r *policy.Rule) { r.Filter.Application = "other" }),
	}
	_, v := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	if v.State != "awaiting-decision" {
		t.Fatal("a rule for an earlier revision was applied", v)
	}
	var row Event
	for _, r := range x.e.List(1000, false) {
		if r.ID == v.ID {
			row = r
		}
	}
	if len(row.PreviousRevisionRules) != 1 || row.PreviousRevisionRules[0] != (RevisionRuleRef{ID: "old-allow", Version: 3, Action: "allow", Revision: "rev-old"}) {
		t.Fatalf("previous revision rules: %+v", row.PreviousRevisionRules)
	}
	// A rule for the current revision is not reported (it would decide the request).
	x.e.rules = append(x.e.rules, mk("current-ask", "rev", "ask", nil))
	for _, r := range x.e.List(1000, false) {
		for _, ref := range r.PreviousRevisionRules {
			if ref.ID == "current-ask" {
				t.Fatal("current revision reported as previous")
			}
		}
	}
}

// endedFixture: a pending request whose socket has ended while its process
// keeps running, plus a second waiting request of the same process.
func endedFixture(t *testing.T) (*queueFixture, identity.Process, Event, Event) {
	t.Helper()
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	_, ended := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	_, queued := x.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.7:53", "udp")
	x.ended["10.0.0.1:40001>192.0.2.1:443"] = true
	return x, p, ended, queued
}

func TestForAWhileFromEndedRequestCreatesLeaseOnly(t *testing.T) {
	x, p, ended, queued := endedFixture(t)
	src := x.e.List(1000, false)
	for _, r := range src {
		if r.ID == ended.ID && (r.RequestRule == nil || !r.RequestRule.ProcessLeaseAvailable || r.RequestRule.PID != 42) {
			t.Fatalf("live process not reported lease-capable: %+v", r.RequestRule)
		}
	}
	l, settled, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "block", 0, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if l.PID != 42 || l.Start != "10" || l.Action != "block" || l.Direction != "outgoing" || l.EventID != ended.ID || l.Seconds != 15 || !l.Until.Equal(x.now.Add(15*time.Second)) {
		t.Fatalf("lease: %+v", l)
	}
	if s := settledIDs(settled); len(s) != 1 || s[queued.ID].State != "blocked" || s[queued.ID].Rule != "while:"+l.ID {
		t.Fatalf("queued same-process request not settled by the Deny lease: %+v", settled)
	}
	// The ended request stays ended, is never delivered and no rule exists.
	if st := stateOf(x.e, ended.ID); st != "expired" {
		t.Fatal("ended request state", st)
	}
	if x.e.RetainedState(ended.ID, ended.Attribution.Fingerprint) != "drop" || len(x.e.rules) != 0 {
		t.Fatal("ended request released or rule created")
	}
	if !strings.Contains(endedLeaseSentence(l), "This ended request was not delivered") {
		t.Fatal(endedLeaseSentence(l))
	}
	// New TCP+UDP attempts of the same process are blocked without prompting.
	for i, proto := range []string{"tcp", "udp"} {
		_, v := x.flow(t, p, proto, "10.0.0.1:4101"+strconv.Itoa(i), "198.51.100.1:80", "n")
		if v.State != "blocked" || v.Rule != "while:"+l.ID {
			t.Fatal("same live process not covered", proto, v)
		}
	}
	// Sibling and relaunched instance prompt independently.
	sib := x.proc(43, "10", 1000)
	if _, v := x.flow(t, sib, "tcp", "10.0.0.2:41020", "198.51.100.1:80", "s"); v.State != "awaiting-decision" {
		t.Fatal("sibling covered", v)
	}
	again := x.proc(42, "11", 1000)
	if _, v := x.flow(t, again, "tcp", "10.0.0.1:41030", "198.51.100.1:80", "r"); v.State != "awaiting-decision" {
		t.Fatal("relaunched PID covered", v)
	}
	// Expiry: the original live process prompts again.
	*x.now = x.now.Add(15 * time.Second)
	if _, v := x.flow(t, p, "tcp", "10.0.0.1:41040", "198.51.100.1:80", "x"); v.State != "awaiting-decision" {
		t.Fatal("lease outlived 15 s", v)
	}
	// One lease per ended request.
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "allow", 0, 1000, false); code(err) != "request_decided" {
		t.Fatal("second lease from the same ended request", err)
	}
}

func code(err error) string {
	var typed *RuleMutationError
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

func TestForAWhileFromEndedRequestRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*queueFixture, identity.Process)
		want   string
	}{
		"process exited": {func(x *queueFixture, p identity.Process) { x.exit(p) }, "process_ended"},
		"pid reused": {func(x *queueFixture, p identity.Process) {
			x.exit(p)
			x.proc(42, "99", 1000)
		}, "process_ended"},
		"executable replaced": {func(x *queueFixture, p identity.Process) {
			q := x.live[42]
			q.Application.Revision = "rev-new"
			x.live[42] = q
		}, "process_scope_unavailable"},
		"exec other binary": {func(x *queueFixture, p identity.Process) {
			q := x.live[42]
			q.Application.Executable, q.Application.Key = "/bin/sleep", "sleep"
			x.live[42] = q
		}, "process_scope_unavailable"},
		"namespace changed": {func(x *queueFixture, p identity.Process) {
			q := x.live[42]
			q.MountNS = "mnt:[2]"
			x.live[42] = q
		}, "process_scope_unavailable"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			x, p, ended, queued := endedFixture(t)
			c.mutate(x, p)
			_, settled, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "block", 0, 1000, false)
			if code(err) != c.want || settled != nil {
				t.Fatal(err, settled)
			}
			if len(x.e.processLeases) != 0 || stateOf(x.e, queued.ID) != "awaiting-decision" {
				t.Fatal("refusal created a lease or settled a request")
			}
			if name == "process exited" {
				for _, r := range x.e.List(1000, false) {
					if r.ID == ended.ID && (r.RequestRule == nil || r.RequestRule.ProcessLeaseAvailable || r.RequestRule.ProcessState != "ended") {
						t.Fatalf("exited process still reported lease-capable: %+v", r.RequestRule)
					}
				}
				// Remember (request rule) still saves for future launches.
				pv, err := x.e.PreviewRequestRule(x.e.Generation, ended.ID, "block", "persistent", "any", x.e.Zones.Revision, 1000, false, appOnly())
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := x.e.SaveRequestRule(x.e.Generation, pv.Token, ended.ID, "block", "persistent", "any", x.e.Zones.Revision, 1000, false, appOnly()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	x, _, ended, queued := endedFixture(t)
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, queued.ID, "block", 0, 1000, false); code(err) != "request_pending" {
		t.Fatal("live pending request accepted", err)
	}
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "block", 0, 1001, false); code(err) != "forbidden" {
		t.Fatal("other principal", err)
	}
	if _, _, err := x.e.ForAWhileFromRequest("old", ended.ID, "block", 0, 1000, false); code(err) != "generation_conflict" {
		t.Fatal(err)
	}
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, ended.ID, "block", 20, 1000, false); code(err) != "invalid_request" {
		t.Fatal("invalid duration", err)
	}
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, "unknown", "block", 0, 1000, false); code(err) != "request_unavailable" {
		t.Fatal(err)
	}
	// A request that was decided is not "ended": no lease from it.
	_, decided := x.flow(t, x.live[42], "tcp", "10.0.0.1:40009", "192.0.2.3:443", "z")
	if _, err := x.e.Decide(decided.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	x.ended["10.0.0.1:40009>192.0.2.3:443"] = true
	if _, _, err := x.e.ForAWhileFromRequest(x.e.Generation, decided.ID, "block", 0, 1000, false); code(err) != "request_decided" {
		t.Fatal("decided request accepted", err)
	}
	// Incomplete socket-holder visibility: never a process lease.
	y := newQueueFixture(t)
	p1 := y.proc(42, "10", 1000)
	f, _ := identity.ParseFlow("tcp", "outgoing", "10.0.0.1:40001", "192.0.2.1:443")
	shared := whileAttribution(p1, "app", "rev", "/opt/app")
	shared.VisibilityComplete = false
	y.owners["10.0.0.1:40001>192.0.2.1:443"] = shared
	v := y.e.Observe(f, "a")
	y.ended["10.0.0.1:40001>192.0.2.1:443"] = true
	if _, _, err := y.e.ForAWhileFromRequest(y.e.Generation, v.ID, "block", 0, 1000, false); code(err) != "process_scope_unavailable" {
		t.Fatal("shared socket accepted", err)
	}
}

func TestForAWhileDurations(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	_, first := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "a")
	_, queued := x.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.5:53", "udp")
	for _, bad := range []int64{1, 14, 16, 120, 7200, -15} {
		if _, _, err := x.e.DecideSettled(first.ID, "block", ForAWhileScope, bad, 1000, false); code(err) != "invalid_request" {
			t.Fatal("invalid duration accepted", bad, err)
		}
	}
	if _, _, err := x.e.DecideSettled(first.ID, "block", "once", 60, 1000, false); code(err) != "invalid_request" {
		t.Fatal("duration accepted for Once", err)
	}
	if stateOf(x.e, first.ID) != "awaiting-decision" || len(x.e.processLeases) != 0 {
		t.Fatal("refused duration changed state")
	}
	start := *x.now
	d, settled, err := x.e.DecideSettled(first.ID, "block", ForAWhileScope, 3600, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Lease.Seconds != 3600 || !d.Lease.Until.Equal(start.Add(time.Hour)) || !strings.Contains(d.Permission, "1 hour") {
		t.Fatalf("lease %+v %q", d.Lease, d.Permission)
	}
	if s := settledIDs(settled); s[queued.ID].State != "blocked" {
		t.Fatal("queued request not settled at creation", settled)
	}
	if ls := x.e.ProcessLeases(1000, false); len(ls) != 1 || ls[0].Seconds != 3600 || ls[0].RemainingMS != 3600*1000 {
		t.Fatalf("listed lease %+v", ls)
	}
	port := 41000
	next := func(proc identity.Process, proto string) Event {
		port++
		_, v := x.flow(t, proc, proto, "10.0.0.1:"+itoa(port), "198.51.100.1:80", "t")
		return v
	}
	for _, at := range []time.Duration{time.Second, 30 * time.Minute, time.Hour - time.Second} {
		*x.now = start.Add(at)
		for _, proto := range []string{"tcp", "udp"} {
			if v := next(p, proto); v.State != "blocked" || v.Rule != "while:"+d.Lease.ID {
				t.Fatalf("+%s %s not blocked by the 1 h lease: %+v", at, proto, v)
			}
		}
		if v := next(x.proc(43, "10", 1000), "tcp"); v.State != "awaiting-decision" {
			t.Fatal("sibling covered at", at)
		}
		if v := next(x.proc(42, "12", 1000), "tcp"); v.State != "awaiting-decision" {
			t.Fatal("relaunched instance covered at", at)
		}
		x.proc(42, "10", 1000) // the original instance is live again in the fixture map
	}
	*x.now = start.Add(time.Hour)
	if v := next(p, "tcp"); v.State != "awaiting-decision" {
		t.Fatal("lease outlived 1 h", v)
	}
	// Ends early when the process exits; a restart (new engine) has no lease.
	*x.now = start.Add(2 * time.Hour)
	_, again := x.flow(t, p, "tcp", "10.0.0.1:42000", "192.0.2.1:443", "b")
	if _, _, err := x.e.DecideSettled(again.ID, "allow", ForAWhileScope, 600, 1000, false); err != nil {
		t.Fatal(err)
	}
	x.exit(p)
	if ls := x.e.ProcessLeases(1000, false); len(ls) != 0 {
		t.Fatal("lease of exited process still listed", ls)
	}
	if len(New(time.Minute).ProcessLeases(0, true)) != 0 {
		t.Fatal("lease survived restart")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestQueueReconcileAPIFields(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "qr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, _ := filepath.Abs(filepath.Join(dir, "s"))
	x, p, ended, queued := endedFixture(t)
	uid := uint32(os.Getuid())
	// Re-own the fixture requests by the caller.
	for k, a := range x.owners {
		for i := range a.Owners {
			a.Owners[i].UID = uid
		}
		x.owners[k] = a
	}
	for _, r := range x.e.requestRules {
		r.UID = uid
		if r.Owner != nil {
			r.Owner.UID = uid
		}
	}
	for _, v := range x.e.events {
		for i := range v.Attribution.Owners {
			v.Attribution.Owners[i].UID = uid
		}
	}
	q := x.live[42]
	q.UID = uid
	x.live[42] = q
	_ = p
	l, err := Serve(path, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	list, err := Call(path, Request{Version: 1, Operation: "list"})
	if err != nil {
		t.Fatal(err)
	}
	has := func(c string) bool {
		for _, x := range list.Capabilities {
			if x == c {
				return true
			}
		}
		return false
	}
	if !has(QueueReconcileCapability) || !has(RequestForAWhileCapability) || !has(ForAWhileDurationsCapability) || len(list.ForAWhileDurations) != 6 || list.ForAWhileDurations[5] != 3600 {
		t.Fatal("capabilities/durations not advertised", list.Capabilities, list.ForAWhileDurations)
	}
	r, _ := Call(path, Request{Version: 1, Operation: "request-for-a-while", Generation: x.e.Generation, ID: ended.ID, Action: "block", DurationSeconds: 60})
	if r.Error != "" || r.ProcessLease == nil || r.ProcessLease.Seconds != 60 || !r.RequestEnded || r.Decision != nil || len(r.Settled) != 1 || r.Settled[0].ID != queued.ID || r.Settled[0].State != "blocked" {
		t.Fatalf("request-for-a-while response: %+v", r)
	}
	if !strings.Contains(r.ScopePreview, "This ended request was not delivered") || !strings.Contains(r.ScopePreview, "1 minute") {
		t.Fatal(r.ScopePreview)
	}
	r, _ = Call(path, Request{Version: 1, Operation: "decide", Generation: x.e.Generation, ID: ended.ID, Action: "allow", Scope: "once", DurationSeconds: 60})
	if r.ErrorCode != "preview_required" {
		t.Fatal("duration on Once accepted", r.ErrorCode, r.Error)
	}
}

// A rule change must not make an already answered Once flow prompt again
// (observed with real receivers: the 7 s SYN retransmit of a Deny-once
// connection after an unrelated rule-delete created a new request).
func TestOnceAnswersSurviveUnrelatedPolicyChange(t *testing.T) {
	x := newQueueFixture(t)
	p := x.proc(42, "10", 1000)
	tcp, denied := x.flow(t, p, "tcp", "10.0.0.1:40001", "192.0.2.1:443", "seq-1")
	udp, allowed := x.flow(t, p, "udp", "10.0.0.1:40002", "192.0.2.1:53", "udp")
	if _, err := x.e.Decide(denied.ID, "block", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	if _, err := x.e.Decide(allowed.ID, "allow", "once", 1000, false); err != nil {
		t.Fatal(err)
	}
	// An unrelated rule is deleted (the same reset path as any rule change).
	unrelated := policy.Rule{ID: "user:other", Version: 1, Schema: 2, Action: "allow", Filter: policy.Filter{Application: "other", Revision: "r", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	x.e.rules = []policy.Rule{unrelated}
	if _, err := x.e.DeleteRule(x.e.Generation, unrelated.ID, &unrelated.Version, 1000, false); err != nil {
		t.Fatal(err)
	}
	*x.now = x.now.Add(7 * time.Second)
	if v := x.e.Observe(tcp, "seq-1"); v.ID != denied.ID || v.State != "blocked" {
		t.Fatal("retransmitted SYN of a denied Once flow re-prompted after a policy change", v)
	}
	if v := x.e.Observe(udp, "udp"); v.ID != allowed.ID || v.State != "allowed" {
		t.Fatal("datagram of an allowed Once tuple re-prompted after a policy change", v)
	}
	// A configured Block for this application still wins over the Once grant.
	block := policy.Rule{ID: "user:block", Version: 1, Schema: 2, Action: "block", Filter: policy.Filter{Application: "app", Revision: "rev", UID: 1000, Direction: "outgoing", Protocol: "*", RemoteAddress: "*"}}
	x.e.mu.Lock()
	x.e.rules = []policy.Rule{block}
	x.e.resetCachedLocked("rule saved")
	x.e.mu.Unlock()
	if v := x.e.Observe(udp, "udp"); v.State != "blocked" || v.Rule != "user:block" {
		t.Fatal("configured Block did not supersede a Once grant", v)
	}
	if x.e.RetainedState(allowed.ID, allowed.Attribution.Fingerprint) != "drop" {
		t.Fatal("retained Once admission released despite configured Block")
	}
	for _, v := range x.e.List(0, true) {
		if v.State == "awaiting-decision" {
			t.Fatal("answered flow prompted again", v)
		}
	}
}
