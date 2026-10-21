package queue

import (
	"context"
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketProcessorLifetimes(t *testing.T) {
	for _, test := range []string{"allow", "block", "hold", "retention-full", "expired-before", "expired-during", "cancelled-during", "submit-failed", "sender-dropped"} {
		t.Run(test, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			j := job(1, 8000)
			var expired atomic.Uint64
			observed, retained, sent := 0, 0, 0
			actual := false
			outcome := ""
			if test == "expired-before" {
				j.deadline = time.Now().Add(-time.Second)
			}
			p := packetProcessor{ctx: ctx, expired: &expired,
				observe: func(identity.Flow, string) daemon.Event {
					observed++
					state := "allowed"
					if test == "hold" || test == "retention-full" {
						state = "awaiting-decision"
					}
					if test == "block" {
						state = "blocked"
					}
					deadline := time.Now().Add(time.Minute)
					if test == "expired-during" {
						deadline = time.Now().Add(-time.Second)
					}
					if test == "cancelled-during" {
						cancel()
					}
					return daemon.Event{State: state, Deadline: deadline}
				},
				retain: func(uint32, int, daemon.Event) bool { retained++; return test != "retention-full" },
				record: func(_ daemon.Event, s string, _ error) { outcome = s },
				verdict: func(_ uint32, allow bool) (bool, error) {
					sent++
					actual = allow
					if test == "sender-dropped" {
						actual = false
					}
					if test == "submit-failed" {
						return false, errors.New("send failed")
					}
					return actual, nil
				},
			}
			p.process(j, false)
			if test == "hold" {
				if sent != 0 || retained != 1 || outcome != daemon.VerdictHeld {
					t.Fatal(sent, retained, outcome)
				}
				return
			}
			if sent != 1 {
				t.Fatal("verdict count", sent)
			}
			if test == "expired-before" {
				if observed != 0 || actual {
					t.Fatal("expired job resolved or allowed")
				}
				return
			}
			expected := daemon.VerdictDropped
			if test == "allow" {
				expected = daemon.VerdictAccepted
			}
			if test == "submit-failed" {
				expected = daemon.VerdictFailed
			}
			if outcome != expected {
				t.Fatal(outcome, expected)
			}
			if test != "allow" && test != "submit-failed" && actual {
				t.Fatal("unexpected allow")
			}
		})
	}
}

// Queue scheduling must never turn the ordering key into permission authority:
// replacing an owner on the exact same tuple still requires a new decision.
func TestPacketProcessorDoesNotTransferWindowsPermission(t *testing.T) {
	e := daemon.New(time.Minute)
	e.LocalPeer = nil
	alpha := identity.Application{Kind: "wine", Key: "alpha-prefix-a", Revision: "alpha-r1", Executable: "/prefix-a/drive_c/alpha.exe", Prefix: "/prefix-a"}
	beta := identity.Application{Kind: "wine", Key: "beta-prefix-b", Revision: "beta-r1", Executable: "/prefix-b/drive_c/beta.exe", Prefix: "/prefix-b"}
	owner := alpha
	uid := uint32(1000)
	e.Resolve = func(identity.Flow) identity.Attribution {
		current := owner
		return identity.Attribution{Application: &current, Owners: []identity.Process{{UID: uid, Start: "1"}}, Fingerprint: owner.Key}
	}
	if err := e.SetRules([]policy.Rule{{ID: "alpha-only", Action: "allow", Filter: policy.Filter{Application: alpha.Key, Revision: alpha.Revision, UID: uid, Protocol: "udp", Direction: "outgoing"}}}); err != nil {
		t.Fatal(err)
	}
	var expired atomic.Uint64
	allowed := false
	held := false
	p := packetProcessor{ctx: context.Background(), observe: e.Observe, expired: &expired,
		retain:  func(uint32, int, daemon.Event) bool { held = true; return true },
		record:  func(daemon.Event, string, error) {},
		verdict: func(_ uint32, a bool) (bool, error) { allowed = a; return a, nil },
	}
	j := job(1, 8000)
	p.process(j, false)
	if !allowed || held {
		t.Fatal("alpha rule not applied")
	}
	for _, test := range []string{"beta-prefix", "other-user", "other-direction", "unknown"} {
		owner = alpha
		uid = 1000
		j = job(2, 8000)
		allowed = false
		held = false
		switch test {
		case "beta-prefix":
			owner = beta
		case "other-user":
			uid = 1001
		case "other-direction":
			j.flow.Direction = "incoming"
		case "unknown":
			owner = identity.Application{}
		}
		p.process(j, false)
		if allowed {
			t.Fatalf("alpha permission transferred: %s", test)
		}
	}
}

func TestPacketProcessorChecksAdmissionDeadlineAfterResolution(t *testing.T) {
	var expired atomic.Uint64
	j := job(1, 8000)
	j.deadline = time.Now().Add(10 * time.Millisecond)
	sent := false
	p := packetProcessor{ctx: context.Background(), expired: &expired,
		observe: func(identity.Flow, string) daemon.Event {
			time.Sleep(time.Until(j.deadline) + time.Millisecond)
			return daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)}
		},
		retain: func(uint32, int, daemon.Event) bool { t.Fatal("expired packet retained"); return false },
		record: func(_ daemon.Event, s string, _ error) {
			if s != daemon.VerdictDropped {
				t.Error(s)
			}
		},
		verdict: func(_ uint32, a bool) (bool, error) {
			sent = true
			if a {
				t.Error("expired admission allowed")
			}
			return a, nil
		},
	}
	p.process(j, false)
	if !sent || expired.Load() != 1 {
		t.Fatal("expired packet not drained")
	}
}
