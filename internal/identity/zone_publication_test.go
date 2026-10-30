package identity

import (
	"errors"
	"testing"
	"time"
)

func TestZonePublisherCanReadSnapshotAndCommitOnFailure(t *testing.T) {
	m := &ZoneManager{}
	expected := errors.New("accelerator unavailable")
	m.publisher = func(z NetworkZones, commit func()) error {
		_ = m.Snapshot() // would deadlock if callback held snapshot mutex
		commit()
		if m.Snapshot().Revision != z.Revision {
			t.Error("commit not visible")
		}
		return expected
	}
	done := make(chan struct{})
	go func() {
		m.publication.Lock()
		defer m.publication.Unlock()
		m.publish(NetworkZones{Revision: "next"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("publication/snapshot lock inversion")
	}
	if m.Snapshot().Revision != "next" || m.PublicationError() != expected {
		t.Fatal("failed accelerator rolled back snapshot or hid error")
	}
}
