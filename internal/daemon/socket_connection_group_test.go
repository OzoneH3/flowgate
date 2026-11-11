package daemon

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestConnectionCheckGroupOnlyDueEstablishedSameApplication(t *testing.T) {
	now := time.Now()
	chosen := &socketFlow{haveKey: true, runtime: true, application: "uid-prefix-alpha", next: now, flow: identity.Flow{Protocol: "udp", Direction: "outgoing", NetNS: "net:1"}}
	for _, kind := range []string{"due", "future", "initial", "busy", "native", "other-app-prefix", "netns", "direction", "protocol", "no-group"} {
		t.Run(kind, func(t *testing.T) {
			peer := *chosen
			switch kind {
			case "future":
				peer.next = now.Add(time.Nanosecond)
			case "initial":
				peer.haveKey = false
			case "busy":
				peer.busy = true
			case "native":
				peer.runtime = false
			case "other-app-prefix":
				peer.application = "uid-prefix-beta"
			case "netns":
				peer.flow.NetNS = "net:2"
			case "direction":
				peer.flow.Direction = "incoming"
			case "protocol":
				peer.flow.Protocol = "tcp"
			}
			s := &socketAuthorization{flows: map[string]*socketFlow{"one": chosen, "two": &peer}, resolveGroup: func([]identity.Flow, func(int, *identity.Attribution)) {}}
			if kind == "no-group" {
				s.resolveGroup = nil
			}
			got := s.connectionCheckGroup(chosen, now)
			want := 1
			if kind == "due" {
				want = 2
			}
			if len(got) != want || got[0] != chosen {
				t.Fatalf("group=%v want %d", got, want)
			}
			if peer.next != map[bool]time.Time{true: now.Add(time.Nanosecond), false: now}[kind == "future"] {
				t.Fatal("selector changed cadence")
			}
		})
	}
	s := &socketAuthorization{flows: map[string]*socketFlow{}, resolveGroup: func([]identity.Flow, func(int, *identity.Attribution)) {}}
	for i := 0; i < 20; i++ {
		p := *chosen
		s.flows[string(rune('a'+i))] = &p
	}
	if got := s.connectionCheckGroup(chosen, now); len(got) != identity.MaxRuntimeObservationFlows {
		t.Fatal("group cap", len(got))
	}
	initial := *chosen
	initial.haveKey = false
	if got := s.connectionCheckGroup(&initial, now); len(got) != 1 {
		t.Fatal("initial grant used group")
	}
}

func connectionGroupFixture(t *testing.T) (*Engine, *socketAuthorization, []*socketFlow, identity.Attribution, *grantModel) {
	t.Helper()
	e, s, f, a, m := connectionFixture(t)
	var err error
	s.store, err = socketgrant.NewConnection(&retiringGrantModel{grantModel: m})
	if err != nil {
		t.Fatal(err)
	}
	m.values = map[socketgrant.Key]socketgrant.Value{}
	f.haveKey = false
	e.finishSocketAuthorizationLocked(s, f, s.store.Begin(), a)
	other := &socketFlow{flow: f.flow}
	other.flow.Remote = netip.AddrPortFrom(other.flow.Remote.Addr(), 9001)
	s.flows[s.flowKey(other.flow)] = other
	e.finishSocketAuthorizationLocked(s, other, s.store.Begin(), a)
	if !other.haveKey {
		t.Fatal("second established grant missing")
	}
	for _, f := range []*socketFlow{f, other} {
		f.busy = true
	}
	s.active = 1
	s.jobs = &sync.WaitGroup{}
	s.jobs.Add(1)
	s.wake = make(chan struct{}, 1)
	return e, s, []*socketFlow{f, other}, a, m
}

func TestConnectionCheckGroupIndependentResultsAndCadence(t *testing.T) {
	for _, kind := range []string{"same", "inconclusive", "owner-change", "nil-fallback", "missing", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			e, s, group, a, m := connectionGroupFixture(t)
			fallback := 0
			s.resolve = func(f identity.Flow) identity.Attribution {
				fallback++
				if f != group[1].flow {
					t.Fatal("wrong fallback flow")
				}
				return a
			}
			s.resolveGroup = func(fs []identity.Flow, emit func(int, *identity.Attribution)) {
				if len(fs) != 2 || fs[0] != group[0].flow || fs[1] != group[1].flow {
					t.Fatal("group membership changed")
				}
				emit(0, &a)
				if kind == "missing" {
					return
				}
				switch kind {
				case "inconclusive":
					v := identity.Attribution{}
					emit(1, &v)
				case "owner-change":
					v := a
					app := *a.Application
					app.Prefix = "/synthetic/other-prefix"
					app.Key = identity.ApplicationKey(1000, app)
					v.Application = &app
					table := *a.Table
					table.Prefix = app.Prefix
					v.Table = &table
					emit(1, &v)
				case "nil-fallback":
					emit(1, nil)
				default:
					emit(1, &a)
				}
				if kind == "duplicate" {
					emit(0, &a)
					emit(2, &a)
					emit(-1, &a)
				}
			}
			start := time.Now()
			e.resolveConnectionChecks(context.Background(), s, group, s.store.Begin())
			end := time.Now()
			wantChecks := uint64(2)
			if kind == "missing" {
				wantChecks = 1
			}
			if s.checks != wantChecks || s.active != 0 {
				t.Fatal("completion", s.checks, s.active)
			}
			for _, f := range group {
				if f.busy || f.next.Before(start.Add(connectionCheckInterval)) || f.next.After(end.Add(connectionCheckInterval)) {
					t.Fatal("cadence or busy", f.next)
				}
			}
			if !group[0].haveKey {
				t.Fatal("other socket interrupted")
			}
			want := 2
			if kind == "owner-change" {
				want = 1
			}
			if len(m.values) != want {
				t.Fatal("grant count", len(m.values), want)
			}
			if (fallback == 1) != (kind == "nil-fallback") {
				t.Fatal("fallback", fallback)
			}
			if kind == "missing" || kind == "inconclusive" {
				if s.backgroundInconclusive != 1 {
					t.Fatal("missing inconclusive diagnostic")
				}
			}
		})
	}
}

func TestConnectionCheckGroupSlowAndPolicyRevocation(t *testing.T) {
	e, s, group, a, m := connectionGroupFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.resolveGroup = func(_ []identity.Flow, emit func(int, *identity.Attribution)) {
		close(entered)
		<-release
		emit(0, &a)
		emit(1, &a)
	}
	ticket := s.store.Begin()
	go func() { e.resolveConnectionChecks(context.Background(), s, group, ticket); close(done) }()
	<-entered
	e.mu.Lock()
	live := len(m.values) == 2 && group[0].haveKey && group[1].haveKey
	e.mu.Unlock()
	if !live {
		t.Fatal("slow check interrupted existing grants")
	}
	if err := e.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if len(m.values) != 0 || len(s.flows) != 0 {
		t.Fatal("late observation resurrected revoked sockets")
	}
}

func TestConnectionCheckGroupIndependentCompletionTimes(t *testing.T) {
	e, s, group, a, _ := connectionGroupFixture(t)
	s.resolveGroup = func(_ []identity.Flow, emit func(int, *identity.Attribution)) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); emit(1, &a) }()
		wg.Wait()
		e.mu.Lock()
		first := group[1].next
		pending := group[0].busy
		e.mu.Unlock()
		if first.IsZero() || !pending {
			t.Error("first completion waited for group")
		}
		time.Sleep(time.Millisecond)
		emit(0, &a)
	}
	e.resolveConnectionChecks(context.Background(), s, group, s.store.Begin())
	if !group[0].next.After(group[1].next) || s.checks != 2 {
		t.Fatal("completion times were aligned")
	}
}

func TestConnectionCheckGroupStaleCompletionCannotChangeOtherLifecycle(t *testing.T) {
	for _, kind := range []string{"cancel", "session", "retire"} {
		t.Run(kind, func(t *testing.T) {
			e, s, group, a, m := connectionGroupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.resolveGroup = func(_ []identity.Flow, emit func(int, *identity.Attribution)) {
				switch kind {
				case "cancel":
					cancel()
				case "session":
					e.mu.Lock()
					e.socketAuthorization = nil
					e.mu.Unlock()
				case "retire":
					if err := e.RetireSocketInterface(3, "test"); err != nil {
						t.Error(err)
					}
				}
				// A positive changed owner would remove grants if the old session or
				// retired socket could still consume these late observations.
				v := a
				app := *a.Application
				app.Revision = "changed"
				v.Application = &app
				emit(1, &v)
				emit(0, &v)
			}
			e.resolveConnectionChecks(ctx, s, group, s.store.Begin())
			if s.checks != 0 || s.confirmedChanges != 0 || s.active != 0 {
				t.Fatal("stale result was consumed")
			}
			want := 2
			if kind == "retire" {
				want = 0
			}
			if len(m.values) != want {
				t.Fatal("lifecycle grant count", len(m.values), want)
			}
			for _, f := range group {
				if f.busy {
					t.Fatal("stuck busy")
				}
			}
		})
	}
}
