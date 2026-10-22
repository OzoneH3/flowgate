package daemon

import (
	"fmt"
	"testing"
	"time"

	"flowgate/internal/policy"
)

func TestEndedRequestHistoryCannotDisconnectBoundedClients(t *testing.T) {
	e, f, a, now := fixture()
	e.Timeout = 30 * time.Second
	e.LocalPeer = nil
	var first string
	for i := 0; i < e.Max; i++ {
		if i%20 == 0 {
			*now = now.Add(time.Second)
		}
		v := e.Observe(f, fmt.Sprint(i))
		if v.State != "awaiting-decision" {
			t.Fatal(i, v.State)
		}
		if i == 0 {
			first = v.ID
		}
	}
	*now = now.Add(40 * time.Second)
	// Ended requests retain future-rule evidence, but ordinary allowed traffic
	// must not grow the published event list beyond either GUI's 256-row contract.
	e.mu.Lock()
	e.rules = []policy.Rule{{ID: "allowed", Action: "allow", Filter: policy.Filter{Application: a.Application.Key, Revision: a.Application.Revision, UID: 1000, Direction: f.Direction, Protocol: f.Protocol, RemoteAddress: "*"}}}
	e.mu.Unlock()
	v := e.Observe(f, "ordinary-allowed")
	if v.State != "allowed" {
		t.Fatal(v.State, v.Reason)
	}
	var state listReadState
	if err := state.publish(e); err != nil {
		t.Fatal(err)
	}
	view, err := state.read(1000, false, *now)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Events) > e.Max {
		t.Fatalf("GUI rejects published list: %d events exceeds %d", len(view.Events), e.Max)
	}
	e.mu.Lock()
	retained := e.requestRules[first] != nil
	e.mu.Unlock()
	if !retained {
		t.Fatal("history eviction destroyed retained request evidence")
	}
	// A fresh unanswered request must stay visible alongside the current
	// admission, even when every optional historical slot was occupied.
	a.Application.Key = "new-app"
	pending := e.Observe(f, "fresh-pending")
	if pending.State != "awaiting-decision" {
		t.Fatal(pending.State)
	}
	rows := e.List(1000, false)
	if len(rows) > e.Max {
		t.Fatal("direct list exceeded client bound", len(rows))
	}
	foundPending := false
	for _, row := range rows {
		if row.ID == pending.ID {
			foundPending = true
		}
	}
	if !foundPending {
		t.Fatal("new actionable prompt hidden by ended history")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.events[f.Key()+"|ordinary-allowed"] == nil {
		t.Fatal("current allowed flow was discarded")
	}
}

func TestHistoryTrimNeverEvictsLivePromptOrOnceLease(t *testing.T) {
	e, _, _, now := fixture()
	live := now.Add(time.Minute)
	ended := now.Add(-time.Minute)
	e.events = map[string]*Event{
		"pending": {ID: "pending", State: "awaiting-decision", FirstSeen: now.Add(-time.Hour), Deadline: live},
		"once":    {ID: "once", State: "allowed", Rule: "once:grant", FirstSeen: now.Add(-time.Hour), Deadline: live},
		"old":     {ID: "old", State: "expired", FirstSeen: now.Add(-2 * time.Minute), Deadline: ended},
		"newer":   {ID: "newer", State: "expired", FirstSeen: now.Add(-time.Minute), Deadline: ended},
	}
	e.trimEndedHistoryLocked(3, *now)
	if len(e.events) != 3 || e.events["old"] != nil || e.events["newer"] == nil {
		t.Fatal("oldest ended history not selected")
	}
	e.trimEndedHistoryLocked(1, *now)
	if len(e.events) != 2 || e.events["pending"] == nil || e.events["once"] == nil {
		t.Fatal("display trimming evicted live authority")
	}
}
