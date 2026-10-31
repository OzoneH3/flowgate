package identity

import "testing"

// Reproduces the presentation omission without running a resolver or census.
// Each observer snapshot starts from current kernel rows, not the last annotation.
func TestWineActivityBusySnapshotOmitsPreviousAssociation(t *testing.T) {
	previous := ActivitySnapshot{Complete: true, Rows: []ActivityRow{{ID: "same-live-socket", RuntimeApplication: &RuntimeApplication{Application: Application{Key: "synthetic-A", Kind: "wine", Prefix: "prefix-A"}}}}}
	next := ActivitySnapshot{Complete: true, Rows: []ActivityRow{{ID: previous.Rows[0].ID}}}
	m := &WineObservers{}
	m.admissionDemand.Store(1)
	m.AnnotateActivity(&next)
	if previous.Rows[0].RuntimeApplication == nil || next.Rows[0].RuntimeApplication != nil {
		t.Fatal("busy snapshot omission was not reproduced")
	}
}
