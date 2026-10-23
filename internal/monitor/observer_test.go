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

func TestObservedHookAfterAnnotationAndBudgetNeverOnRead(t *testing.T) {
	o := New(time.Second)
	calls := 0
	o.Annotate = func(s *identity.ActivitySnapshot) { s.Rows[0].OwnershipCategory = "annotated" }
	o.Observed = func(s identity.ActivitySnapshot) {
		calls++
		if s.Rows[0].OwnershipCategory != "annotated" {
			t.Fatal("consumed before annotation")
		}
	}
	s := identity.ActivitySnapshot{Sequence: 1, Collected: time.Now(), Complete: true, Rows: []identity.ActivityRow{{ID: "one"}}}
	o.publish(s)
	for i := 0; i < 10; i++ {
		o.Snapshot()
	}
	if calls != 1 {
		t.Fatal("reads consumed observations", calls)
	}
	o.Observed = func(s identity.ActivitySnapshot) {
		calls++
		if s.Complete || len(s.Rows) != 0 {
			t.Fatal("oversized observation escaped cap")
		}
	}
	s.Rows[0].Evidence = string(make([]byte, 4<<20))
	o.publish(s)
	if calls != 2 {
		t.Fatal(calls)
	}
}
