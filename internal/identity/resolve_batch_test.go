package identity

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func batchFlow(proto, local, remote string) Flow {
	return Flow{Protocol: proto, Direction: "outgoing", Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), NetNS: NetNS()}
}

// Deterministic holder model: PIDs 10/20 hold sockets 1/2; socket 3 is held by
// both (shared); socket 4 has no holder. Inspect of model PIDs fails in this
// process, so every held socket is "incomplete" for Resolve and ResolveBatch
// alike: the comparison exercises the failure/visibility class, not success.
func batchHolderModel(t *testing.T) *censusProc {
	t.Helper()
	f := &censusProc{
		groups:  map[int]map[int]*censusTask{10: {10: {start: "100", table: 1}}, 20: {20: {start: "200", table: 2}}, 30: {30: {start: "300", table: 3}}},
		tables:  map[int]map[int]string{1: {3: "socket:[1]", 4: "socket:[3]"}, 2: {5: "socket:[2]", 6: "socket:[3]"}, 3: {7: "pipe:[9]"}},
		statErr: map[int]error{}, fdErr: map[int]error{}, hidden: map[int]bool{}, now: time.Unix(0, 0),
	}
	saved := holderSource
	holderSource = f.proc
	t.Cleanup(func() { holderSource = saved })
	return f
}

func batchSockets() []Socket {
	return []Socket{
		{Protocol: "tcp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:40001"), Remote: netip.MustParseAddrPort("203.0.113.9:443"), Inode: 1, Cookie: "0000000000000001"},
		{Protocol: "tcp", Family: unix.AF_INET6, Local: netip.MustParseAddrPort("[2001:db8::1]:40002"), Remote: netip.MustParseAddrPort("[2001:db8::2]:443"), Inode: 2, Cookie: "0000000000000002"},
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:40003"), Remote: netip.MustParseAddrPort("203.0.113.9:53"), Inode: 3, Cookie: "0000000000000003"},
		{Protocol: "udp", Family: unix.AF_INET, Local: netip.MustParseAddrPort("192.0.2.10:40004"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), Inode: 4, Cookie: "0000000000000004"},
	}
}

func TestResolveBatchEmptyInputPerformsNoDumpOrCensus(t *testing.T) {
	m := &dumpModel{sockets: batchSockets()}
	m.install(t)
	called := false
	saved := holderSource
	holderSource = func() holderProc { called = true; return saved() }
	t.Cleanup(func() { holderSource = saved })
	if out := ResolveBatch(nil); len(out) != 0 || len(m.full) != 0 || called {
		t.Fatalf("empty input did work: dumps=%d census=%v", len(m.full), called)
	}
}

func TestResolveBatchRefusesMoreThanLimitWithoutWork(t *testing.T) {
	m := &dumpModel{sockets: batchSockets()}
	m.install(t)
	flows := make([]Flow, MaxResolveBatch+1)
	for i := range flows {
		flows[i] = batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443")
	}
	out := ResolveBatch(flows)
	if len(out) != len(flows) || len(m.full) != 0 {
		t.Fatalf("over-limit batch must be refused before any dump: %d dumps", len(m.full))
	}
	for _, a := range out {
		if a.ReasonCode != ReasonSocketCensusUnavailable || a.Status != "unidentified" || len(a.Sockets) != 0 {
			t.Fatalf("unexpected refusal shape: %+v", a)
		}
	}
}

func TestResolveBatchPositionalNamespaceAndNoReceiverMatchResolve(t *testing.T) {
	m := &dumpModel{sockets: batchSockets(), filterPort: true}
	m.install(t)
	batchHolderModel(t)
	foreign := batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443")
	foreign.NetNS = "net:[1]"
	none := batchFlow("tcp", "192.0.2.10:49999", "203.0.113.9:443") // no receiver
	flows := []Flow{foreign, none, batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443")}
	out := ResolveBatch(flows)
	if out[0].ReasonCode != ReasonNamespaceMismatch || len(out[0].Sockets) != 0 {
		t.Fatalf("foreign namespace flow must be refused in place: %+v", out[0])
	}
	if !reflect.DeepEqual(out[1], Resolve(none)) {
		t.Fatalf("no-receiver flow differs from Resolve:\n%+v\n%+v", out[1], Resolve(none))
	}
	if len(out[2].Sockets) != 1 || out[2].Sockets[0].Inode != 1 {
		t.Fatalf("positional mapping broken: %+v", out[2])
	}
}

func TestResolveBatchDumpFailuresPropagateLikeResolve(t *testing.T) {
	m := &dumpModel{sockets: batchSockets(), fullErr: errors.New("diag down"), portErr: errors.New("diag down")}
	m.install(t)
	flows := []Flow{batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443"), batchFlow("udp", "192.0.2.10:40003", "203.0.113.9:53")}
	out := ResolveBatch(flows)
	for i, f := range flows {
		single := Resolve(f)
		if out[i].ReasonCode != ReasonSocketCensusUnavailable || single.ReasonCode != ReasonSocketCensusUnavailable || out[i].Status != single.Status {
			t.Fatalf("dump failure mismatch for %d: batch %+v single %+v", i, out[i], single)
		}
	}
	// Recheck failure after a successful first dump.
	m2 := &dumpModel{sockets: batchSockets(), filterPort: true}
	m2.install(t)
	batchHolderModel(t)
	calls := 0
	orig := socketDumps.full
	socketDumps.full = func() ([]Socket, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("recheck down")
		}
		return orig()
	}
	out = ResolveBatch([]Flow{batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443")})
	if out[0].ReasonCode != ReasonSocketCensusUnavailable || out[0].Reason != "socket recheck unavailable" {
		t.Fatalf("recheck failure not propagated: %+v", out[0])
	}
}

// Per-flow results equal Resolve for mixed TCP/UDP, v4/v6, a duplicated flow,
// a socket held by two processes and a socket with no holder, under the same
// incomplete-inspection conditions. Fingerprints, sockets, status, reason and
// visibility must all match; owners are restricted per flow.
func TestResolveBatchEquivalentToResolvePerFlowUnderModelCensus(t *testing.T) {
	m := &dumpModel{sockets: batchSockets(), filterPort: true}
	m.install(t)
	batchHolderModel(t)
	flows := []Flow{
		batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443"),
		batchFlow("tcp", "[2001:db8::1]:40002", "[2001:db8::2]:443"),
		batchFlow("udp", "192.0.2.10:40003", "203.0.113.9:53"),  // shared holder
		batchFlow("udp", "192.0.2.10:40004", "203.0.113.9:53"),  // no holder
		batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443"), // duplicate
	}
	out := ResolveBatch(flows)
	if len(m.full) != 2 {
		t.Fatalf("batch must use exactly one dump and one recheck, got %d", len(m.full))
	}
	collateral := 0
	for i, f := range flows {
		single := Resolve(f)
		// Documented difference: census completeness is shared. A flow whose own
		// census would be complete-negative (socket 4: no holder) is reported as
		// visibility-incomplete when another flow's inspection failed in the same
		// shared census. The batch is never LESS strict than Resolve.
		if single.ReasonCode == ReasonNoUserspaceOwnerObserved && out[i].ReasonCode == ReasonProcessVisibilityIncomplete {
			collateral++
			if out[i].VisibilityComplete || out[i].Status != "unidentified" || !reflect.DeepEqual(out[i].Sockets, single.Sockets) {
				t.Fatalf("collateral refusal must stay conservative and keep the flow's sockets: %+v", out[i])
			}
			continue
		}
		for _, cmp := range []struct {
			name string
			a, b any
		}{{"status", out[i].Status, single.Status}, {"reason", out[i].ReasonCode, single.ReasonCode}, {"visibility", out[i].VisibilityComplete, single.VisibilityComplete},
			{"sockets", out[i].Sockets, single.Sockets}, {"fingerprint", out[i].Fingerprint, single.Fingerprint}, {"owners", out[i].Owners, single.Owners}} {
			if !reflect.DeepEqual(cmp.a, cmp.b) {
				t.Fatalf("flow %d %s differs: batch %v single %v", i, cmp.name, cmp.a, cmp.b)
			}
		}
		if len(out[i].Sockets) != 1 || int(out[i].Sockets[0].Inode) != []int{1, 2, 3, 4, 1}[i] {
			t.Fatalf("flow %d carries foreign sockets: %+v", i, out[i].Sockets)
		}
	}
	if collateral != 1 {
		t.Fatalf("expected exactly the no-holder flow to show the shared-completeness collateral, got %d", collateral)
	}
}

// finalizeAttribution never admits owners of sockets outside the flow's wanted set.
func TestFinalizeAttributionRestrictsOwnersToWantedSockets(t *testing.T) {
	a := Attribution{Status: "unidentified", Sockets: []Socket{{Protocol: "tcp", Inode: 1, Cookie: "0000000000000001"}}}
	owners := map[string][]Process{
		"socket:[1]": {{PID: 10, ThreadGroup: 10, Start: "100", Application: Application{Kind: "native", Key: "a"}}},
		"socket:[2]": {{PID: 20, ThreadGroup: 20, Start: "200", Application: Application{Kind: "native", Key: "b"}}},
	}
	wa := map[string]bool{"socket:[1]": true}
	finalizeAttribution(&a, wa, collectOwners(&a, wa, owners), false, a.Sockets)
	if len(a.Owners) != 1 || a.Owners[0].PID != 10 || a.Status != "directly-associated" || a.Application == nil || a.Application.Key != "a" {
		t.Fatalf("restriction failed: %+v", a)
	}
	b := Attribution{Status: "unidentified", Sockets: []Socket{{Protocol: "tcp", Inode: 1, Cookie: "0000000000000001"}}}
	finalizeAttribution(&b, wa, collectOwners(&b, wa, owners), true, b.Sockets)
	if b.VisibilityComplete || b.Status == "directly-associated" {
		t.Fatalf("incomplete census must stay conservative: %+v", b)
	}
}

// Real kernel, this process: two loopback TCP clients and one connected UDP
// socket. ResolveBatch must equal per-flow Resolve on every field that carries
// decision weight; completeness depends on /proc visibility of other users'
// processes and is therefore compared, not asserted true.
// liveIdentityTests gates tests that touch this process's real sockets and
// /proc. They run in the guest fixture and when FLOWGATE_LIVE_IDENTITY_TESTS
// is set explicitly; the broad identity package is not run on the host.
func liveIdentityTests(t *testing.T) {
	t.Helper()
	if os.Getenv("FLOWGATE_LIVE_IDENTITY_TESTS") == "" && (os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS()) {
		t.Skip("live identity test: set FLOWGATE_LIVE_IDENTITY_TESTS=1 or run inside the lab namespace")
	}
}

func TestResolveBatchEquivalentToResolveOnOwnSockets(t *testing.T) {
	liveIdentityTests(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	var flows []Flow
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Skip(err)
		}
		defer c.Close()
		flows = append(flows, Flow{Protocol: "tcp", Direction: "outgoing", Local: netip.MustParseAddrPort(c.LocalAddr().String()), Remote: netip.MustParseAddrPort(c.RemoteAddr().String()), NetNS: NetNS()})
	}
	u, err := net.Dial("udp", "127.0.0.1:9")
	if err == nil {
		defer u.Close()
		flows = append(flows, Flow{Protocol: "udp", Direction: "outgoing", Local: netip.MustParseAddrPort(u.LocalAddr().String()), Remote: netip.MustParseAddrPort(u.RemoteAddr().String()), NetNS: NetNS()})
	}
	out := ResolveBatch(flows)
	for i, f := range flows {
		single := Resolve(f)
		if !reflect.DeepEqual(out[i].Sockets, single.Sockets) || len(out[i].Sockets) != 1 {
			t.Fatalf("flow %d sockets differ or are not exactly its own: batch %+v single %+v", i, out[i].Sockets, single.Sockets)
		}
		// The test process's own threads start and stop during a census, so a
		// pass may report membership_changed and drop the holder non-
		// deterministically (seen on both paths). When both passes are complete
		// the decision must be identical; otherwise both must be conservative.
		if out[i].VisibilityComplete && single.VisibilityComplete {
			if !sameAttribution(out[i], single) {
				t.Fatalf("flow %d differs:\nbatch  %+v\nsingle %+v", i, out[i], single)
			}
			continue
		}
		for _, a := range []Attribution{out[i], single} {
			if a.VisibilityComplete || a.Status == "directly-associated" || a.Application != nil {
				t.Fatalf("flow %d: an incomplete pass must stay conservative: %+v", i, a)
			}
		}
		t.Logf("flow %d: incomplete census on this host (batch %s / single %s); decision fields conservative on both", i, out[i].ReasonCode, single.ReasonCode)
	}
}

// Positive assembly for two distinct applications from one shared owners map:
// each flow collects only its own holder, both become directly-associated with
// their own application, and neither sees the other's owner.
func TestCollectAndFinalizeTwoDistinctApplicationsFromSharedOwners(t *testing.T) {
	shared := map[string][]Process{
		"socket:[1]": {{PID: 10, ThreadGroup: 10, Start: "100", UID: 0, Application: Application{Kind: "native", Key: "alpha"}}},
		"socket:[2]": {{PID: 20, ThreadGroup: 20, Start: "200", UID: 0, Application: Application{Kind: "native", Key: "beta"}}},
		"socket:[3]": {{PID: 10, ThreadGroup: 10, Start: "100", UID: 0, Application: Application{Kind: "native", Key: "alpha"}}, {PID: 20, ThreadGroup: 20, Start: "200", UID: 0, Application: Application{Kind: "native", Key: "beta"}}},
	}
	mk := func(inode uint32) Attribution {
		return Attribution{Status: "unidentified", Sockets: []Socket{{Protocol: "tcp", Inode: inode, Cookie: fmt.Sprintf("%016x", inode)}}}
	}
	a, b, c := mk(1), mk(2), mk(3)
	wa, wb, wc := map[string]bool{"socket:[1]": true}, map[string]bool{"socket:[2]": true}, map[string]bool{"socket:[3]": true}
	ca, cb, cc := collectOwners(&a, wa, shared), collectOwners(&b, wb, shared), collectOwners(&c, wc, shared)
	finalizeAttribution(&a, wa, ca, false, a.Sockets)
	finalizeAttribution(&b, wb, cb, false, b.Sockets)
	finalizeAttribution(&c, wc, cc, false, c.Sockets)
	if a.Status != "directly-associated" || a.Application.Key != "alpha" || len(a.Owners) != 1 || a.Owners[0].PID != 10 {
		t.Fatalf("alpha flow wrong: %+v", a)
	}
	if b.Status != "directly-associated" || b.Application.Key != "beta" || len(b.Owners) != 1 || b.Owners[0].PID != 20 {
		t.Fatalf("beta flow wrong: %+v", b)
	}
	if c.Status != "multiple-candidates" || len(c.Owners) != 2 || c.Application != nil {
		t.Fatalf("shared socket must stay ambiguous: %+v", c)
	}
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("distinct flows must not share a fingerprint")
	}
}

// resolveReferenceOld is a frozen copy of Resolve as of 834debf (before the
// finalisation was extracted). Resolve must behave identically, including the
// failure path where the recheck dump fails AFTER owners were observed.
func resolveReferenceOld(f Flow) Attribution {
	a := Attribution{Status: "unidentified", Reason: "no visible matching socket", ReasonCode: ReasonNoSocketObserved}
	if f.NetNS != NetNS() {
		a.setReason(ReasonNamespaceMismatch, "foreign network namespace is outside this observer")
		return a
	}
	dump, _ := resolveDump(f)
	sockets, e := dump()
	if e != nil {
		a.setReason(ReasonSocketCensusUnavailable, "socket diagnostics unavailable: "+e.Error())
		return a
	}
	wanted := map[string]bool{}
	for _, s := range receivers(sockets, f) {
		a.Sockets = append(a.Sockets, s)
		wanted[fmt.Sprintf("socket:[%d]", s.Inode)] = true
	}
	if len(wanted) == 0 {
		return a
	}
	_, resolved := resolveHolderIdentities(wanted, func(pid int) (Process, error) {
		p, err := Inspect(pid)
		if err == nil {
			p.Provenance = CaptureProvenance(p)
		}
		return p, err
	}, nil)
	covered := map[string]bool{}
	incomplete := !resolved.Complete
	seen := map[string]bool{}
	for socket, owners := range resolved.Owners {
		for _, p := range owners {
			covered[socket] = true
			key := fmt.Sprintf("%d:%s:%s", p.PID, p.Start, p.HolderWitness)
			if !seen[key] {
				a.Owners = append(a.Owners, p)
				seen[key] = true
			}
		}
	}
	again, err := dump()
	if err != nil {
		a.setReason(ReasonSocketCensusUnavailable, "socket recheck unavailable")
		return a
	}
	current := receivers(again, f)
	if fingerprint(nil, current) != fingerprint(nil, a.Sockets) {
		a.setReason(ReasonSocketChanged, "listener changed during attribution")
		return a
	}
	a.VisibilityComplete = !incomplete && len(covered) == len(wanted)
	a.Fingerprint = fingerprint(a.Owners, a.Sockets)
	if !incomplete && len(covered) == len(wanted) && len(a.Sockets) == 1 {
		if association, client := brokerAssociation(a.Owners); association != nil {
			a.Association = association
			app := client.Application
			a.Application = &app
			a.Status = "corroborated-broker-client"
			a.setReason(ReasonBrokerClientAssociation, "one visible Windows client and verified Wine broker; non-sharing handle assumption applies")
			a.Fingerprint = digest(a.Fingerprint + fmt.Sprintf("|%d:%d", association.ClientChannel, association.BrokerChannel))
			return a
		}
	}
	if unresolvedOwnership(&a, incomplete) {
		return a
	}
	if incomplete || len(covered) != len(wanted) {
		a.setReason(ReasonProcessVisibilityIncomplete, "incomplete process visibility; cannot exclude another owner")
		return a
	}
	p := a.Owners[0]
	if p.Application.Key == "" {
		a.setReason(ReasonRuntimeIdentityUnverified, "runtime observed but Windows image/prefix not corroborated")
		return a
	}
	a.Status = "directly-associated"
	if p.Application.Kind == "wine" {
		a.Status = "corroborated"
	}
	a.setReason(ReasonNativeOwnerObserved, "one visible socket and one current FD owner; observation is subject to races")
	if p.Application.Kind == "wine" {
		a.ReasonCode = ReasonRuntimeOwnerObserved
	}
	app := p.Application
	a.Application = &app
	return a
}

// ownerIdentity reduces a holder to its decision-bearing fields. Provenance is
// per-capture metadata (its pointer target differs between two captures of the
// same process) and carries no decision weight; it is excluded on purpose.
func ownerIdentity(p Process) string {
	return fmt.Sprintf("%d|%d|%s|%d|%s|%s|%s|%s|%s|%s", p.PID, p.ThreadGroup, p.Start, p.UID, p.Executable, p.ExecutableRevision, p.HolderWitness, p.NetNS, p.Application.Kind, p.Application.Key)
}

func sameAttribution(x, y Attribution) bool {
	if len(x.Owners) != len(y.Owners) {
		return false
	}
	for i := range x.Owners {
		if ownerIdentity(x.Owners[i]) != ownerIdentity(y.Owners[i]) {
			return false
		}
	}
	return x.Status == y.Status && x.ReasonCode == y.ReasonCode && x.Reason == y.Reason && x.VisibilityComplete == y.VisibilityComplete && x.Fingerprint == y.Fingerprint && reflect.DeepEqual(x.Sockets, y.Sockets) && reflect.DeepEqual(x.Application, y.Application)
}

// Model-census failure classes: refactored Resolve equals the frozen reference
// (no receiver, census unavailable, holder inspection unavailable, shared socket).
func TestResolveMatchesFrozenReferenceUnderModelFailures(t *testing.T) {
	m := &dumpModel{sockets: batchSockets(), filterPort: true}
	m.install(t)
	batchHolderModel(t)
	for _, f := range []Flow{batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443"), batchFlow("udp", "192.0.2.10:40003", "203.0.113.9:53"), batchFlow("udp", "192.0.2.10:40004", "203.0.113.9:53"), batchFlow("tcp", "192.0.2.10:49999", "203.0.113.9:443")} {
		if got, want := Resolve(f), resolveReferenceOld(f); !sameAttribution(got, want) {
			t.Fatalf("Resolve diverged from frozen reference for %v:\n got %+v\nwant %+v", f, got, want)
		}
	}
	m.fullErr, m.portErr = errors.New("down"), errors.New("down")
	f := batchFlow("tcp", "192.0.2.10:40001", "203.0.113.9:443")
	if got, want := Resolve(f), resolveReferenceOld(f); !sameAttribution(got, want) {
		t.Fatalf("dump failure diverged: got %+v want %+v", got, want)
	}
}

// Live: this process holds the socket, so owners are observed; the recheck dump
// then fails. The frozen reference keeps the observed owners on that path and
// so must Resolve and ResolveBatch (B1 regression).
func TestRecheckFailureKeepsObservedOwnersLikeFrozenReference(t *testing.T) {
	liveIdentityTests(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Skip(err)
	}
	defer c.Close()
	f := Flow{Protocol: "tcp", Direction: "outgoing", Local: netip.MustParseAddrPort(c.LocalAddr().String()), Remote: netip.MustParseAddrPort(c.RemoteAddr().String()), NetNS: NetNS()}
	failSecond := func() func() {
		saved := socketDumps
		calls := 0
		socketDumps.full = func() ([]Socket, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("recheck down")
			}
			return saved.full()
		}
		return func() { socketDumps = saved }
	}
	restore := failSecond()
	want := resolveReferenceOld(f)
	restore()
	restore = failSecond()
	got := Resolve(f)
	restore()
	restore = failSecond()
	batch := ResolveBatch([]Flow{f})[0]
	restore()
	if want.ReasonCode != ReasonSocketCensusUnavailable || len(want.Owners) == 0 {
		t.Skipf("reference did not observe owners before the recheck failure in this environment: %+v", want)
	}
	if !sameAttribution(got, want) || !sameAttribution(batch, want) {
		t.Fatalf("recheck-failure evidence differs:\nwant  %+v\ngot   %+v\nbatch %+v", want, got, batch)
	}
}
