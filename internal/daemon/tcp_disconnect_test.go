package daemon

import (
	"context"
	"testing"
	"time"

	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/socketcontrol"
)

func TestTCPBlockEditDisconnectRequiresNewAndCurrentWinner(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configure  func(*policy.Rule, *policy.Rule, *[]policy.Rule)
		current    func([]policy.Rule) []policy.Rule
		want       bool
		priorLease string
		clearLease bool
	}{
		{name: "create", want: true},
		{name: "Ask without a lease transitions to Block", want: true, configure: func(allow, _ *policy.Rule, _ *[]policy.Rule) {
			allow.Action = "ask"
		}},
		{name: "Ask with Allow lease transitions to Block", want: true, priorLease: "allow"},
		{name: "Ask with active Block lease is already blocked", priorLease: "block"},
		{name: "Block lease at edit still counts if removed before abort check", priorLease: "block", clearLease: true},
		{name: "enable", want: true, configure: func(_, block *policy.Rule, before *[]policy.Rule) {
			old := *block
			old.Disabled = true
			old.Version--
			*before = append(*before, old)
		}},
		{name: "already enabled", configure: func(_, block *policy.Rule, before *[]policy.Rule) {
			*before = append(*before, *block)
		}},
		{name: "losing block", configure: func(allow, _ *policy.Rule, _ *[]policy.Rule) {
			allow.Priority = 300
		}},
		{name: "winner changed during ownership check", current: func(rules []policy.Rule) []policy.Rule {
			rules[0].Priority = 300
			return rules
		}},
		{name: "losing at publication even if it later wins", configure: func(allow, _ *policy.Rule, _ *[]policy.Rule) {
			allow.Priority = 300
		}, current: func(rules []policy.Rule) []policy.Rule {
			return rules[1:]
		}},
		{name: "version changed during ownership check", current: func(rules []policy.Rule) []policy.Rule {
			rules[1].Version++
			return rules
		}},
		{name: "replaced another Block", configure: func(allow, _ *policy.Rule, _ *[]policy.Rule) {
			allow.Action = "block"
		}},
		{name: "interface could affect winner", configure: func(allow, _ *policy.Rule, _ *[]policy.Rule) {
			allow.Filter.InterfaceIndex = 9
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, a, now := fixture()
			f, err := identity.ParseFlow("tcp", "outgoing", "10.0.0.1:33220", "10.0.0.2:443")
			if err != nil {
				t.Fatal(err)
			}
			allow := policy.Rule{ID: "allow", Version: 1, Action: "allow", Priority: 100, Created: *now,
				Filter: policy.Filter{Application: a.Application.Key, Revision: a.Application.Revision,
					UID: a.Principal().UID, Protocol: "tcp", Direction: f.Direction}}
			block := allow
			block.ID, block.Action, block.Priority, block.Version = "block", "block", 200, 2
			block.Filter.RemoteAddress = f.Remote.Addr().String()
			before := []policy.Rule{allow}
			if tc.configure != nil {
				tc.configure(&before[0], &block, &before)
			}
			if tc.priorLease != "" {
				before[0].Action = "ask"
				a.VisibilityComplete = true
				a.Owners[0].PID, a.Owners[0].BootID = 123, "boot"
				lease, err := e.newLeaseLocked(&Event{Flow: f}, *a, tc.priorLease, *now, 30*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				e.storeLeaseLocked(lease)
				base, rule, _ := e.evaluateLocked(before, f, *a, *now)
				if action, _, _ := e.leaseOverlayLocked(base, rule, f, *a, *now); base != "ask" || action != tc.priorLease {
					t.Fatalf("bad lease fixture: %s -> %s", base, action)
				}
			}
			e.rules = before
			status := EnforcementStatus{State: "active", Profile: "both"}
			e.Enforcement = func() EnforcementStatus { return status }
			var got bool
			e.tcpDisconnect = &tcpDisconnect{
				abort: func(_ context.Context, s identity.Socket) (socketcontrol.Result, error) {
					got = s.Cookie == "exact"
					return socketcontrol.Result{Status: socketcontrol.Acknowledged}, nil
				},
			}
			e.publishRuleStateLocked([]policy.Rule{before[0], block})
			if tc.clearLease {
				clear(e.processLeases)
			}
			if tc.current != nil {
				e.rules = tc.current(append([]policy.Rule(nil), e.rules...))
			}
			if e.tcpBlockEdit != nil {
				e.abortNewlyBlockedTCP(context.Background(), e.tcpBlockEdit, EstablishedTCP{
					Flow: f, Socket: identity.Socket{Cookie: "exact"},
				}, *a, status)
			}
			if got != tc.want {
				t.Fatalf("abort = %t, want %t", got, tc.want)
			}
		})
	}
}
