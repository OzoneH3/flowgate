package uploadshape

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestPrioritySelectsTailWithoutMovingBackground(t *testing.T) {
	var d discoverySnapshot
	d.reset()
	rows := censusRows(1300)
	d.load(rows, nil, time.Now())
	d.next()
	p := priorityQueue{hints: priorityHints{inodes: map[uint32]bool{rows[1299].Inode: true}}}
	p.selectRows(&d)
	s, ok := p.next()
	if !ok || s.Cookie != rows[1299].Cookie || d.view.Cursor != 1 || !p.hints.view.Completed {
		t.Fatal(s, d.view, p)
	}
	p = priorityQueue{hints: priorityHints{inodes: map[uint32]bool{rows[0].Inode: true, 99999: true}}}
	p.selectRows(&d)
	if p.hints.view.Reason != "snapshot_not_present" || !p.hints.view.Incomplete {
		t.Fatal(p)
	}
}

func TestPriorityFreshProofAndReservedBackgroundAcrossEdits(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(40)
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	m.priorityHints = func([]Cap) priorityHints {
		return priorityHints{inodes: map[uint32]bool{rows[36].Inode: true, rows[37].Inode: true, rows[38].Inode: true, rows[39].Inode: true}}
	}
	batches := make(chan []identity.Flow, 8)
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		batches <- fl
		return make([]identity.Attribution, len(fl))
	}
	defer m.Close()
	cfg := Config{Enabled: true, Caps: []Cap{{Application: "a", BitsPerSecond: 4000000}}}
	m.Configure(1, cfg)
	for turn := 0; turn < 3; turn++ {
		select {
		case fl := <-batches:
			if len(fl) != 8 || fl[0].Local != rows[36].Local || fl[4].Local != rows[turn*4].Local {
				t.Fatalf("priority/background reservation: turn %d %+v", turn, fl)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no progress")
		}
		if turn < 2 {
			cfg.Caps[0].BitsPerSecond++
			m.Configure(m.Snapshot().Version, cfg)
		}
	}
	until(t, func() bool { return m.Snapshot().DiscoverySnapshot.Cursor >= 12 })
	if m.Snapshot().DiscoverySnapshot.Generation != 1 {
		t.Fatal("config reset generation")
	}
	m.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == "bind" {
			t.Fatal("hint authorized binding without proof")
		}
	}
}

func TestDownloadEditsTriggerPriorityWithoutResettingBackground(t *testing.T) {
	m := newManager(Options{})
	f := &model{}
	m.start = func() (transport, error) { return f, nil }
	rows := censusRows(40)
	m.sockets = func() ([]identity.Socket, error) { return rows, nil }
	m.priorityHints = func([]Cap) priorityHints {
		return priorityHints{inodes: map[uint32]bool{rows[36].Inode: true, rows[37].Inode: true, rows[38].Inode: true, rows[39].Inode: true}}
	}
	batches := make(chan []identity.Flow, 8)
	m.resolveBatch = func(fl []identity.Flow) []identity.Attribution {
		batches <- fl
		return make([]identity.Attribution, len(fl))
	}
	defer m.Close()
	cfg := Config{Enabled: true, Caps: []Cap{{Application: "a", DownloadBitsPerSecond: 4000000}}}
	m.Configure(1, cfg)
	for turn := 0; turn < 3; turn++ {
		select {
		case fl := <-batches:
			if len(fl) != 8 || fl[0].Local != rows[36].Local || fl[4].Local != rows[turn*4].Local {
				t.Fatalf("priority/background reservation: turn %d %+v", turn, fl)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no progress")
		}
		if turn < 2 {
			cfg.Caps[0].DownloadBitsPerSecond++
			m.Configure(m.Snapshot().Version, cfg)
		}
	}
	until(t, func() bool { return m.Snapshot().DiscoverySnapshot.Cursor >= 12 })
	if m.Snapshot().DiscoverySnapshot.Generation != 1 {
		t.Fatal("config reset generation")
	}
	m.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == "bind" {
			t.Fatal("hint authorized binding without proof")
		}
	}
}
