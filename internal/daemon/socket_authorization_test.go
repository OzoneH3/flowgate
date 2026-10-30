package daemon

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/socketgrant"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type grantModel struct {
	values      map[socketgrant.Key]socketgrant.Value
	epoch       uint64
	fail        bool
	failNonzero bool
}

func (m *grantModel) Put(k socketgrant.Key, v socketgrant.Value) error { m.values[k] = v; return nil }
func (m *grantModel) Delete(k socketgrant.Key) error                   { delete(m.values, k); return nil }
func (m *grantModel) Epoch(n uint64) error {
	if m.fail || (m.failNonzero && n != 0) {
		return errors.New("write failed")
	}
	m.epoch = n
	return nil
}

func TestSocketAuthorizationFailedRevocationDisablesBeforeEdit(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	m.failNonzero = true
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	if !s.disabled || m.epoch != 0 || len(e.rules) != 0 {
		t.Fatal("edit did not follow confirmed kernel disable")
	}
	if err := e.SetRules(nil); err != nil {
		t.Fatal("disabled accelerator blocked later edit", err)
	}
}

func TestSocketAuthorizationSchedulesOnlyRuleAllow(t *testing.T) {
	for _, action := range []string{"allow", "block", "ask"} {
		t.Run(action, func(t *testing.T) {
			e, s, f, a, _ := wineGrantFixture(t)
			s.flows = map[string]*socketFlow{}
			e.rules[0].Action = action
			e.ObserveResolved(f.flow, "udp", a)
			if (len(s.flows) > 0) != (action == "allow") {
				t.Fatalf("%s scheduled %d", action, len(s.flows))
			}
		})
	}
}
func (m *grantModel) Close() error { return nil }
func (m *grantModel) Stats(socketgrant.Key) (socketgrant.Stats, error) {
	return socketgrant.Stats{}, nil
}
func (m *grantModel) Totals() (socketgrant.Stats, error) { return socketgrant.Stats{}, nil }
func wineGrantFixture(t testing.TB) (*Engine, *socketAuthorization, *socketFlow, identity.Attribution, *grantModel) {
	t.Helper()
	e := New(time.Second)
	f := identity.Flow{Protocol: "udp", Direction: "outgoing", NetNS: identity.NetNS(), Local: netip.MustParseAddrPort("192.0.2.1:1234"), Remote: netip.MustParseAddrPort("198.51.100.1:9000")}
	app := identity.Application{Kind: "wine", Executable: "/synthetic/alpha.exe", Prefix: "/synthetic/prefix-one", Revision: "rev-a"}
	app.Key = identity.ApplicationKey(1000, app)
	a := identity.Attribution{VisibilityComplete: true, Status: "corroborated-runtime-table", Fingerprint: "full-observation-a", Application: &app,
		Owners:  []identity.Process{{UID: 1000, PID: 123, Start: "1", NetNS: f.NetNS}},
		Sockets: []identity.Socket{{Protocol: "udp", NetNS: f.NetNS, Inode: 1, Cookie: "0100000000000000", Local: f.Local}},
		Table:   &identity.TableEvidence{UID: 1000, Prefix: app.Prefix, SocketCookie: "0100000000000000", Generation: "table-one", Owners: []identity.WindowsOwner{{PID: 1, Image: app.Executable}}}}
	m := &grantModel{values: map[socketgrant.Key]socketgrant.Value{}}
	store, err := socketgrant.New(m)
	if err != nil {
		t.Fatal(err)
	}
	s := &socketAuthorization{store: store, flows: map[string]*socketFlow{}}
	e.socketAuthorization = s
	flow := &socketFlow{flow: f}
	s.flows[f.Key()] = flow
	e.rules = []policy.Rule{{ID: "allow-alpha", Schema: 2, Action: "allow", Filter: policy.Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Protocol: "udp", Direction: "outgoing", RemoteAddress: "*"}}}
	return e, s, flow, a, m
}
func TestSocketAuthorizationApplicationPrefixUserAndDestination(t *testing.T) {
	for _, change := range []string{"same", "other-application", "other-prefix", "other-user", "incomplete", "cookie-table-mismatch"} {
		t.Run(change, func(t *testing.T) {
			e, s, f, a, m := wineGrantFixture(t)
			switch change {
			case "other-application":
				a.Application.Executable = "/synthetic/beta.exe"
				a.Application.Key = identity.ApplicationKey(1000, *a.Application)
			case "other-prefix":
				a.Application.Prefix = "/synthetic/prefix-two"
				a.Table.Prefix = a.Application.Prefix
				a.Application.Key = identity.ApplicationKey(1000, *a.Application)
			case "other-user":
				a.Table.UID = 1001
				a.Owners[0].UID = 1001
				a.Application.Key = identity.ApplicationKey(1001, *a.Application)
			case "incomplete":
				a.VisibilityComplete = false
			case "cookie-table-mismatch":
				a.Sockets[0].Cookie = "0200000000000000"
			}
			e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
			if (len(m.values) == 1) != (change == "same") {
				t.Fatalf("%s grants=%v", change, m.values)
			}
		})
	}
}
func TestSocketAuthorizationRevokesRealPolicyMutationModel(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	k, _ := socketgrant.KeyFor(f.flow, a)
	v := m.values[k]
	if v.Generation != m.epoch {
		t.Fatal("no original grant")
	}
	rules := append([]policy.Rule(nil), e.rules...)
	rules[0].Action = "block"
	if err := e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	if v.Generation == m.epoch {
		t.Fatal("policy did not revoke kernel generation")
	}
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	if len(m.values) != 0 {
		t.Fatal("denied application retained certificate")
	}
}
func TestSocketAuthorizationEditWhileVerificationAndFailedRevocation(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	ticket := s.store.Begin()
	if err := e.SetRules(append([]policy.Rule(nil), e.rules...)); err != nil {
		t.Fatal(err)
	}
	e.finishSocketAuthorizationLocked(s, f, ticket, a)
	if len(m.values) != 0 {
		t.Fatal("verification crossed policy edit")
	}
	m.fail = true
	if err := e.SetRules(nil); err == nil {
		t.Fatal("failed revocation acknowledged")
	}
	if len(e.rules) != 1 {
		t.Fatal("policy published after revocation failure")
	}
}

func TestSocketAuthorizationFrozenRenewalMembershipAndEpoch(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(fmt.Sprint(edit), func(t *testing.T) {
			e, s, f, a, m := wineGrantFixture(t)
			g := &socketFlow{flow: f.flow}
			g.flow.Local = netip.MustParseAddrPort("192.0.2.1:1235")
			b := a
			b.Sockets = append([]identity.Socket(nil), a.Sockets...)
			b.Sockets[0].Local = g.flow.Local
			b.Sockets[0].Inode = 2
			b.Sockets[0].Cookie = "0200000000000000"
			table := *a.Table
			table.SocketCookie = b.Sockets[0].Cookie
			b.Table = &table
			s.flows[g.flow.Key()] = g
			f.busy = true
			g.busy = true
			s.active = 1
			s.resolveGroup = func(fs []identity.Flow, emit func(int, *identity.Attribution)) {
				if len(fs) != 2 {
					t.Fatal("membership changed")
				}
				late := f.flow
				late.Local = netip.MustParseAddrPort("192.0.2.1:1236")
				e.mu.Lock()
				e.trackSocketFlowLocked(late)
				e.mu.Unlock()
				emit(0, &a)
				if len(m.values) != 1 {
					t.Fatal("first completion held behind group barrier")
				}
				if edit {
					if err := e.SetRules(append([]policy.Rule(nil), e.rules...)); err != nil {
						t.Fatal(err)
					}
				}
				emit(1, &b)
			}
			e.resolveSocketRenewalGroup(context.Background(), s, []*socketFlow{f, g}, s.store.Begin(), time.Now())
			want := 2
			if edit {
				want = 1
			}
			if len(m.values) != want {
				t.Fatalf("grants=%d want=%d", len(m.values), want)
			}
			if s.active != 0 || f.busy || g.busy {
				t.Fatal("group slots leaked")
			}
			for _, v := range m.values {
				if edit && v.Generation == m.epoch {
					t.Fatal("old epoch still authoritative")
				}
			}
		})
	}
}

func TestSocketAuthorizationRenewalGroupLookahead(t *testing.T) {
	now := time.Now()
	chosen := &socketFlow{runtime: true, haveKey: true, application: "app"}
	chosen.flow.Protocol = "udp"
	chosen.flow.NetNS = "net:[1]"
	chosen.flow.Direction = "outgoing"
	for _, kind := range []string{"boundary", "too-early", "busy", "native", "unknown", "application", "namespace", "direction"} {
		t.Run(kind, func(t *testing.T) {
			peer := *chosen
			peer.next = now.Add(100 * time.Millisecond)
			switch kind {
			case "too-early":
				peer.next = peer.next.Add(time.Nanosecond)
			case "busy":
				peer.busy = true
			case "native":
				peer.runtime = false
			case "unknown":
				peer.haveKey = false
			case "application":
				peer.application = "other"
			case "namespace":
				peer.flow.NetNS = "net:[2]"
			case "direction":
				peer.flow.Direction = "incoming"
			}
			s := &socketAuthorization{flows: map[string]*socketFlow{"a": chosen, "b": &peer}, resolveGroup: func([]identity.Flow, func(int, *identity.Attribution)) {}}
			got := s.renewalGroup(chosen, now)
			want := 1
			if kind == "boundary" {
				want = 2
			}
			if len(got) != want || got[0] != chosen {
				t.Fatalf("group size %d want %d", len(got), want)
			}
		})
	}
	s := &socketAuthorization{flows: map[string]*socketFlow{}, resolveGroup: func([]identity.Flow, func(int, *identity.Attribution)) {}}
	for i := 0; i < 20; i++ {
		peer := *chosen
		s.flows[fmt.Sprint(i)] = &peer
	}
	if len(s.renewalGroup(chosen, now)) != identity.MaxRuntimeObservationFlows {
		t.Fatal("group bound changed")
	}
}

func TestSocketAuthorizationTraceBound(t *testing.T) {
	s := &socketAuthorization{}
	for i := 0; i < socketRenewalTraceLimit+3; i++ {
		s.recordRenewal(socketRenewalTrace{Finished: uint64(i)})
	}
	rows, lost := s.renewalTrace()
	if lost != 3 || len(rows) != socketRenewalTraceLimit || rows[0].Sequence != 3 || rows[len(rows)-1].Sequence != socketRenewalTraceLimit+2 {
		t.Fatal("trace bound/order incorrect")
	}
	rows[0].Finished = 999999
	again, _ := s.renewalTrace()
	if again[0].Finished != 3 {
		t.Fatal("trace snapshot aliases live evidence")
	}
}

func TestSocketAuthorizationDueAndExpiryScheduling(t *testing.T) {
	now := time.Now()
	wine := &socketFlow{haveKey: true, deadline: 1000, next: now.Add(-time.Millisecond)}
	native := &socketFlow{haveKey: true, deadline: 2000, next: now.Add(-time.Second)}
	s := &socketAuthorization{wake: make(chan struct{}, 1), flows: map[string]*socketFlow{"wine": wine, "native": native}}
	if s.nextRenewal(now, 500) != wine {
		t.Fatal("later expiry displaced due earlier grant")
	}
	wine.busy = true
	if s.nextRenewal(now, 500) != native {
		t.Fatal("busy flow selected")
	}
	native.next = now.Add(7 * time.Millisecond)
	if s.nextRenewal(now, 500) != nil || s.nextRenewalWake(now) != 7*time.Millisecond {
		t.Fatal("future work or timer wrong")
	}
	// A tick timestamp before next would miss this; use actual scheduling time.
	if s.nextRenewal(now.Add(8*time.Millisecond), 500) != native {
		t.Fatal("due work delayed")
	}
	s.active = 2
	if s.nextRenewalWake(now) != 25*time.Millisecond {
		t.Fatal("full worker pool spins")
	}
	s.wakeScheduler()
	s.wakeScheduler()
	if len(s.wake) != 1 {
		t.Fatal("wake not coalesced")
	}
	<-s.wake
	s.active = 1
	s.wakeScheduler()
	if len(s.wake) != 1 {
		t.Fatal("completion wake lost")
	}
}

func TestSocketAuthorizationFrozenBatchUsesOneFreshScan(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	calls := 0
	s.resolve = func(identity.Flow) identity.Attribution { calls++; return a }
	e.Resolve = func(identity.Flow) identity.Attribution { t.Fatal("duplicate ordinary scan"); return a }
	decide, ok := e.PrepareUDPBatch(f.flow, "frozen", 2, true)
	if !ok || calls != 1 || len(m.values) != 1 {
		t.Fatalf("ok=%v calls=%d grants=%d", ok, calls, len(m.values))
	}
	if got := decide(); got.State != "allowed" {
		t.Fatal(got.State)
	}
	rules := append([]policy.Rule(nil), e.rules...)
	rules[0].Action = "block"
	if err := e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	if got := decide(); got.State != "blocked" {
		t.Fatal("second packet ignored policy change", got.State)
	}
	if calls != 1 {
		t.Fatal("batch rescanned")
	}
}
func TestSocketAuthorizationBatchRejectsPolicyChangeDuringScan(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	s.resolve = func(identity.Flow) identity.Attribution {
		if err := e.SetRules(append([]policy.Rule(nil), e.rules...)); err != nil {
			t.Fatal(err)
		}
		return a
	}
	if _, ok := e.resolveSocketBatch(f.flow); !ok {
		t.Fatal("fresh scan unavailable")
	}
	if len(m.values) != 0 {
		t.Fatal("published across epoch change")
	}
	if f.busy || s.active != 0 {
		t.Fatal("slot leaked")
	}
}
func TestSocketAuthorizationBatchBoundsAndIncomplete(t *testing.T) {
	for _, mode := range []string{"busy", "full", "incomplete", "denied", "ask"} {
		t.Run(mode, func(t *testing.T) {
			e, s, f, a, m := wineGrantFixture(t)
			calls := 0
			s.resolve = func(identity.Flow) identity.Attribution { calls++; return a }
			switch mode {
			case "busy":
				f.busy = true
			case "full":
				s.active = 2
			case "incomplete":
				a.VisibilityComplete = false
			case "denied":
				e.rules[0].Action = "block"
			case "ask":
				e.rules[0].Action = "ask"
			}
			_, ok := e.resolveSocketBatch(f.flow)
			if (mode == "busy" || mode == "full") && (ok || calls != 0) {
				t.Fatal("exceeded admission bound")
			}
			if len(m.values) != 0 {
				t.Fatal("unsafe certificate")
			}
		})
	}
}

func TestSocketAuthorizationUnknownBatchKeepsOrdinaryAdmission(t *testing.T) {
	e, s, f, _, _ := wineGrantFixture(t)
	delete(s.flows, f.flow.Key())
	s.resolve = func(identity.Flow) identity.Attribution {
		t.Fatal("unknown flow took renewal priority")
		return identity.Attribution{}
	}
	if _, ok := e.resolveSocketBatch(f.flow); ok {
		t.Fatal("unknown flow used shared path")
	}
	if s.active != 0 || len(s.flows) != 0 {
		t.Fatal("unknown flow consumed renewal capacity")
	}
}
