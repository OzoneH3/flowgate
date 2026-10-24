package queue

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/queuehealth"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessorHealthRejectionExactlyOnce(t *testing.T) {
	for _, mode := range []string{"deadline-before", "shutdown-before", "deadline-during", "retention", "allow", "block", "held"} {
		t.Run(mode, func(t *testing.T) {
			var got []queuehealth.Cause
			var expired atomic.Uint64
			sent := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			j := packetJob{id: 1, size: 10, deadline: time.Now().Add(time.Minute)}
			if mode == "deadline-before" {
				j.deadline = time.Now().Add(-time.Second)
			}
			if mode == "shutdown-before" {
				cancel()
			}
			p := packetProcessor{ctx: ctx, expired: &expired, diagnostic: func(c queuehealth.Cause) { got = append(got, c) }, observe: func(identity.Flow, string) daemon.Event {
				v := daemon.Event{State: "allowed", Deadline: time.Now().Add(time.Minute)}
				if mode == "deadline-during" {
					v.Deadline = time.Now().Add(-time.Second)
				}
				if mode == "retention" || mode == "held" {
					v.State = "awaiting-decision"
				}
				if mode == "block" {
					v.State = "blocked"
				}
				return v
			}, retain: func(uint32, int, daemon.Event) bool { return mode == "held" }, record: func(daemon.Event, string, error) {}, verdict: func(_ uint32, allow bool) (bool, error) { sent++; return allow, nil }}
			p.process(j, false)
			var want []queuehealth.Cause
			switch mode {
			case "deadline-before", "deadline-during":
				want = []queuehealth.Cause{queuehealth.Deadline}
			case "shutdown-before":
				want = []queuehealth.Cause{queuehealth.Shutdown}
			case "retention":
				want = []queuehealth.Cause{queuehealth.RetentionCapacity}
			}
			if len(got) != len(want) || (len(want) > 0 && got[0] != want[0]) {
				t.Fatal(got, want)
			}
			if mode == "held" {
				if sent != 0 {
					t.Fatal(sent)
				}
			} else if sent != 1 {
				t.Fatal(sent)
			}
		})
	}
}
func TestRetainedHealthDeadlineShutdownAndPolicySeparate(t *testing.T) {
	for _, mode := range []string{"expired", "stop", "policy"} {
		t.Run(mode, func(t *testing.T) {
			var got []queuehealth.Cause
			r := Retainer{diagnostic: func(c queuehealth.Cause) { got = append(got, c) }}
			v := daemon.Event{ID: "one", Deadline: time.Now().Add(time.Minute)}
			if mode == "expired" {
				v.Deadline = time.Now().Add(-time.Second)
			}
			r.Add(1, 10, v)
			r.Flush(time.Now(), func(string, string) string { return "drop" }, func(uint32, bool) error { return nil }, mode == "stop")
			if mode == "policy" {
				if len(got) != 0 {
					t.Fatal(got)
				}
			} else {
				want := queuehealth.RetainedDeadline
				if mode == "stop" {
					want = queuehealth.RetainedShutdown
				}
				if len(got) != 1 || got[0] != want {
					t.Fatal(got)
				}
			}
		})
	}
}
