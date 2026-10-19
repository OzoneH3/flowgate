package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A fake same-host world: the server (cupsd-like, UID 0) listens on [::1]:631;
// local clients connect from ephemeral ports. Each client socket has its own
// cookie; Resolve and LocalPeer answer from this table only.
type pairWorld struct {
	e       *Engine
	now     *time.Time
	clients map[uint16]*identity.Process // source port -> client process (nil: exited)
	cookies map[uint16]string
	server  identity.Process
	srvFP   string
}

const pairServer = "[::1]:631"

func pairApp(p identity.Process) *identity.Application {
	app := identity.Application{Key: p.Executable, Name: p.Executable[strings.LastIndex(p.Executable, "/")+1:], Kind: "native", Executable: p.Executable, Revision: "rev"}
	return &app
}

func newPairWorld(t *testing.T) *pairWorld {
	t.Helper()
	w := &pairWorld{e: New(time.Minute), clients: map[uint16]*identity.Process{}, cookies: map[uint16]string{}}
	now := time.Unix(5000, 0)
	w.now = &now
	w.e.Now = func() time.Time { return *w.now }
	w.server = identity.Process{PID: 764, Start: "11", UID: 0, BootID: "b", Executable: "/usr/bin/cupsd"}
	w.srvFP = "server-1"
	w.e.Resolve = func(f identity.Flow) identity.Attribution {
		if f.Direction == "incoming" {
			s := w.server
			s.Application = *pairApp(s)
			return identity.Attribution{Application: pairApp(s), VisibilityComplete: true, Status: "directly-associated", Owners: []identity.Process{s}, Sockets: []identity.Socket{{Protocol: f.Protocol, Local: f.Local, State: 10, Inode: 9, Cookie: "listener"}}, Fingerprint: w.srvFP}
		}
		c := w.clients[f.Local.Port()]
		if c == nil {
			return identity.Attribution{Status: "unidentified", Reason: "no visible matching socket"}
		}
		p := *c
		p.Application = *pairApp(p)
		return identity.Attribution{Application: pairApp(p), VisibilityComplete: true, Status: "directly-associated", Owners: []identity.Process{p}, Sockets: []identity.Socket{{Protocol: f.Protocol, Local: f.Local, Remote: f.Remote, State: 2, Inode: uint32(f.Local.Port()), Cookie: w.cookies[f.Local.Port()]}}, Fingerprint: fmt.Sprint("client-", c.PID, "-", f.Local.Port())}
	}
	w.e.LocalPeer = func(f identity.Flow) *identity.LocalPeer {
		if f.Direction == "outgoing" {
			o := identity.LocalPeerOwner{PID: w.server.PID, Start: w.server.Start, UID: 0, Executable: w.server.Executable, Application: *pairApp(w.server)}
			return &identity.LocalPeer{State: "verified", Role: "server", Reason: "verified", Owner: &o, Socket: &identity.LocalPeerSocket{Kind: "listener", Protocol: f.Protocol, Local: f.Remote, Cookie: "listener", Inode: 9}}
		}
		c := w.clients[f.Remote.Port()]
		if c == nil {
			return &identity.LocalPeer{State: "unknown", Role: "client", Reason: identity.LocalClientClosed}
		}
		o := identity.LocalPeerOwner{PID: c.PID, Start: c.Start, UID: c.UID, Executable: c.Executable, Application: *pairApp(*c)}
		return &identity.LocalPeer{State: "verified", Role: "client", Reason: "verified", Owner: &o, Socket: &identity.LocalPeerSocket{Kind: "client", Protocol: f.Protocol, Local: f.Remote, Remote: f.Local, Cookie: w.cookies[f.Remote.Port()], Inode: uint32(f.Remote.Port())}}
	}
	return w
}

func (w *pairWorld) client(port uint16, pid int, exe string) {
	w.clients[port] = &identity.Process{PID: pid, Start: fmt.Sprint(pid * 3), UID: 1000, BootID: "b", Executable: exe}
	w.cookies[port] = fmt.Sprintf("cookie-%d", port)
}

func pairFlow(direction string, client uint16) identity.Flow {
	c := netip.AddrPortFrom(netip.MustParseAddr("::1"), client)
	s := netip.MustParseAddrPort(pairServer)
	f := identity.Flow{Protocol: "tcp", Direction: direction, Local: c, Remote: s, NetNS: "net:[1]"}
	if direction == "incoming" {
		f.Local, f.Remote = s, c
	}
	return f
}

func (w *pairWorld) event(id string) Event {
	for _, v := range w.e.List(0, true) {
		if v.ID == id {
			return v
		}
	}
	return Event{}
}

func TestLocalPairExactTupleCorrelatesBothRequests(t *testing.T) {
	w := newPairWorld(t)
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	if out.State != "awaiting-decision" || out.LocalPeer == nil || out.LocalPeer.Role != "server" || out.LocalPeer.Owner.PID != 764 {
		t.Fatalf("outgoing local request must name the server: %+v", out.LocalPeer)
	}
	if _, err := w.e.Decide(out.ID, "allow", "once", 0, true); err != nil {
		t.Fatal(err)
	}
	in := w.e.Observe(pairFlow("incoming", 44104), "777")
	if in.State != "awaiting-decision" || in.LocalPeer.State != "verified" || in.LocalPeer.Owner.PID != 1001 || in.LocalPeer.CorrelatedEventID != out.ID {
		t.Fatalf("incoming side must reference its outgoing side: %+v", in.LocalPeer)
	}
	if got := w.event(out.ID).LocalPeer.CorrelatedEventID; got != in.ID {
		t.Fatalf("outgoing side must reference the incoming side, got %q", got)
	}
	b, _ := json.Marshal(w.event(in.ID))
	for _, want := range []string{`"local_peer":{"state":"verified","role":"client"`, `"correlated_event_id":"` + out.ID, `"cookie":"cookie-44104"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("event JSON lacks %s: %s", want, b)
		}
	}
}

func TestLocalPairMismatchedTupleOrAttemptNotCorrelated(t *testing.T) {
	w := newPairWorld(t)
	w.client(46838, 1001, "/opt/game/rundll32.exe")
	w.client(44104, 2002, "/usr/bin/lp")
	out := w.e.Observe(pairFlow("outgoing", 46838), "1")
	w.e.Decide(out.ID, "allow", "once", 0, true)
	// Same server port, different source port (another connection): never paired.
	other := w.e.Observe(pairFlow("incoming", 44104), "1")
	if other.LocalPeer.CorrelatedEventID != "" || other.LocalPeer.Owner.PID != 2002 {
		t.Fatalf("different source port must not correlate: %+v", other.LocalPeer)
	}
	// Same tuple, different SYN (another attempt): not paired either.
	again := w.e.Observe(pairFlow("incoming", 46838), "2")
	if again.LocalPeer.CorrelatedEventID != "" {
		t.Fatal("different TCP attempt must not correlate")
	}
	if w.event(out.ID).LocalPeer.CorrelatedEventID != "" {
		t.Fatal("outgoing side must stay unpaired")
	}
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID, other.ID}, "allow", "once", 0, 0, true); code(err) != "not_a_pair" {
		t.Fatalf("non-pair must be refused: %v", err)
	}
	if other.State != "awaiting-decision" || w.event(other.ID).State != "awaiting-decision" {
		t.Fatal("refusal must leave the request pending")
	}
}

func TestLocalPairConcurrentClientsEachTheirOwn(t *testing.T) {
	w := newPairWorld(t)
	w.client(50001, 3001, "/opt/a/GameA.exe")
	w.client(50002, 3002, "/opt/b/GameB.exe")
	oa := w.e.Observe(pairFlow("outgoing", 50001), "10")
	ob := w.e.Observe(pairFlow("outgoing", 50002), "20")
	w.e.Decide(oa.ID, "allow", "once", 0, true)
	w.e.Decide(ob.ID, "allow", "once", 0, true)
	ib := w.e.Observe(pairFlow("incoming", 50002), "20")
	ia := w.e.Observe(pairFlow("incoming", 50001), "10")
	if ia.LocalPeer.CorrelatedEventID != oa.ID || ib.LocalPeer.CorrelatedEventID != ob.ID || ia.LocalPeer.Owner.PID != 3001 || ib.LocalPeer.Owner.PID != 3002 {
		t.Fatalf("clients crossed: %+v / %+v", ia.LocalPeer, ib.LocalPeer)
	}
}

func TestLocalPairShortLivedClientUnknown(t *testing.T) {
	w := newPairWorld(t)
	in := w.e.Observe(pairFlow("incoming", 40000), "5")
	if in.LocalPeer == nil || in.LocalPeer.State != "unknown" || in.LocalPeer.Owner != nil || in.LocalPeer.Reason != "Local client unknown: the client socket closed before it could be identified" {
		t.Fatalf("vanished client must be unknown: %+v", in.LocalPeer)
	}
}

func TestDecidePairBeforeIncomingAdmitsOnlyThatConnection(t *testing.T) {
	w := newPairWorld(t)
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	w.client(44105, 1001, "/opt/game/rundll32.exe")
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", ForAWhileScope, 0, 0, true); code(err) != "pair_scope_unavailable" {
		t.Fatalf("For a while cannot cover a not-yet-requested side: %v", err)
	}
	r, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", "once", 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 1 || r.Events[0].State != "allowed" || r.IncomingAdmission == nil || r.IncomingAdmission.Outcome != "pair" || r.IncomingAdmission.Server.PID != 764 {
		t.Fatalf("result must report both sides: %+v", r)
	}
	if !strings.Contains(r.IncomingAdmission.Sentence, "Incoming to cupsd on [::1]:631: Allowed once") {
		t.Fatal(r.IncomingAdmission.Sentence)
	}
	// Exactly this connection's incoming SYN is answered; another source port or SYN prompts.
	other := w.e.Observe(pairFlow("incoming", 44105), "777")
	retry := w.e.Observe(pairFlow("incoming", 44104), "778")
	in := w.e.Observe(pairFlow("incoming", 44104), "777")
	if other.State != "awaiting-decision" || retry.State != "awaiting-decision" {
		t.Fatal("admission must not cover another connection")
	}
	if in.State != "allowed" || in.Rule != "once:"+in.ID || in.LocalPeer.CorrelatedEventID != out.ID || !strings.Contains(in.Reason, "verified local pair") {
		t.Fatalf("incoming side of the pair must be allowed: %+v", in)
	}
	if w.e.RetainedState(in.ID, in.Attribution.Fingerprint) != "allow" {
		t.Fatal("pair admission must hold for retained packets")
	}
}

func TestDecidePairAdmissionRequiresSameServer(t *testing.T) {
	w := newPairWorld(t)
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", "once", 0, 0, true); err != nil {
		t.Fatal(err)
	}
	w.srvFP = "server-restarted"
	in := w.e.Observe(pairFlow("incoming", 44104), "777")
	if in.State != "awaiting-decision" || in.LocalPeer.CorrelatedEventID != out.ID {
		t.Fatalf("a changed server must be asked explicitly, still shown as the pair: %+v", in)
	}
}

func TestDecidePairConfiguredBlockIsReported(t *testing.T) {
	w := newPairWorld(t)
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	if err := w.e.SetRules([]policy.Rule{{ID: "deny-cupsd", Version: 1, Schema: 2, Created: time.Unix(1, 0), Action: "block", Filter: policy.Filter{Application: "/usr/bin/cupsd", Revision: "rev", Direction: "incoming", Protocol: "tcp", UID: 0, RemoteAddress: "*"}}}); err != nil {
		t.Fatal(err)
	}
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	r, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", "once", 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.IncomingAdmission.Outcome != "rule" || r.IncomingAdmission.ConfiguredAction != "block" || r.IncomingAdmission.ConfiguredRule != "deny-cupsd" || !strings.Contains(r.Sentence, "incoming side is denied by deny-cupsd") {
		t.Fatalf("a second denial must never be hidden: %+v %s", r.IncomingAdmission, r.Sentence)
	}
	if in := w.e.Observe(pairFlow("incoming", 44104), "777"); in.State != "blocked" || in.LocalPeer.CorrelatedEventID != out.ID {
		t.Fatalf("configured Block decides the incoming side: %+v", in)
	}
}

// Both requests pending at once (e.g. the outgoing side retried after a
// restart of the queue): one decision answers both or neither.
func bothPending(t *testing.T, w *pairWorld) (Event, Event) {
	t.Helper()
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	in := w.e.Observe(pairFlow("incoming", 44104), "777")
	if out.State != "awaiting-decision" || in.State != "awaiting-decision" || in.LocalPeer.CorrelatedEventID != out.ID {
		t.Fatalf("setup: %+v %+v", out.State, in.LocalPeer)
	}
	return out, in
}

func TestDecidePairAtomicBothSides(t *testing.T) {
	w := newPairWorld(t)
	out, in := bothPending(t, w)
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", "once", 0, 0, true); code(err) != "pair_changed" {
		t.Fatalf("an existing incoming side must be included: %v", err)
	}
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{in.ID}, "allow", "once", 0, 0, true); code(err) != "not_a_pair" {
		t.Fatalf("incoming alone is not a pair: %v", err)
	}
	if _, _, err := w.e.DecidePair("old", []string{out.ID, in.ID}, "allow", "once", 0, 0, true); code(err) != "generation_conflict" {
		t.Fatal(err)
	}
	// Server identity changed: refused, and NOTHING is decided on the client side.
	w.srvFP = "server-restarted"
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID, in.ID}, "allow", "once", 0, 0, true); err == nil {
		t.Fatal("changed server must refuse the pair")
	}
	if w.event(out.ID).State != "awaiting-decision" {
		t.Fatal("pair decision must be atomic: client side was decided alone")
	}
	w2 := newPairWorld(t)
	out, in = bothPending(t, w2)
	r, settled, err := w2.e.DecidePair(w2.e.Generation, []string{in.ID, out.ID}, "block", "once", 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Events) != 2 || r.Events[0].State != "blocked" || r.Events[1].State != "blocked" || settled == nil {
		t.Fatalf("both verdicts must be returned: %+v", r.Events)
	}
	if w2.event(out.ID).State != "blocked" || w2.event(in.ID).State != "blocked" {
		t.Fatal("both sides must be decided")
	}
}

func TestDecidePairOneSideDecidedDecidesTheOther(t *testing.T) {
	w := newPairWorld(t)
	out, in := bothPending(t, w)
	if _, err := w.e.Decide(out.ID, "allow", "once", 0, true); err != nil {
		t.Fatal(err)
	}
	r, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID, in.ID}, "allow", ForAWhileScope, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Events[0].State != "allowed" || r.Events[1].State != "allowed" || r.Events[1].Lease == nil {
		t.Fatalf("pending side decided, decided side reported: %+v", r.Events)
	}
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID, in.ID}, "allow", "once", 0, 0, true); code(err) != "stale_decision" {
		t.Fatal("nothing left to decide", err)
	}
}

func TestDecidePairAuthorization(t *testing.T) {
	w := newPairWorld(t)
	w.client(44104, 1001, "/opt/game/rundll32.exe")
	out := w.e.Observe(pairFlow("outgoing", 44104), "777")
	// The client's user may not answer root's cupsd incoming side.
	if _, _, err := w.e.DecidePair(w.e.Generation, []string{out.ID}, "allow", "once", 0, 1000, false); code(err) != "forbidden" {
		t.Fatalf("server side of another principal: %v", err)
	}
	if w.event(out.ID).State != "awaiting-decision" {
		t.Fatal("refusal must not decide the client side")
	}
}
