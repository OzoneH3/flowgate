package monitor

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestSnapshotFailureAndFreshness(t *testing.T) {
	o := New(time.Second)
	if s := o.Snapshot(); s.Error == "" || s.Complete {
		t.Fatal("initial collection presented as complete")
	}
	o.snapshot = identity.ActivitySnapshot{Sequence: 9, Collected: time.Now(), Rows: []identity.ActivityRow{{ID: "current"}}, Complete: true}
	first, second := o.Snapshot(), o.Snapshot()
	if first.Sequence != 9 || second.Sequence != 9 || len(second.Rows) != 1 {
		t.Fatal("polling mutated snapshot")
	}
	o.snapshot.Collected = time.Now().Add(-10 * time.Second)
	if s := o.Snapshot(); s.Error == "" || s.Complete || len(s.Rows) != 0 || len(s.Processes) != 0 {
		t.Fatal("stale activity shown as live")
	}
	// Returned stale view doesn't mutate the retained immutable snapshot.
	if len(o.snapshot.Rows) != 1 {
		t.Fatal("reader mutated collector state")
	}
}
