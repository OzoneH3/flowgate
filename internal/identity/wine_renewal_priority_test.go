package identity

import "testing"

func TestRenewalReservationBoundsAndOrdinaryProgress(t *testing.T) {
	m := &WineObservers{census: make(chan struct{}, 2), queueCensus: make(chan struct{}, 1)}
	ordinary, ok := m.acquireCensus(false, false)
	if !ok {
		t.Fatal("ordinary unavailable")
	}
	if _, ok = m.acquireCensus(false, false); ok {
		t.Fatal("ordinary used reserved capacity")
	}
	renewal, ok := m.acquireCensus(false, true)
	if !ok {
		t.Fatal("reserved slot unavailable")
	}
	if _, ok = m.acquireCensus(false, true); ok {
		t.Fatal("exceeded total bound")
	}
	renewal()
	ordinary()
	a, ok := m.acquireCensus(false, true)
	if !ok {
		t.Fatal("first renewal")
	}
	b, ok := m.acquireCensus(false, true)
	if !ok {
		t.Fatal("second renewal")
	}
	if _, ok = m.acquireCensus(false, false); ok {
		t.Fatal("ordinary exceeded total bound")
	}
	if len(m.queueCensus) != 0 {
		t.Fatal("failed ordinary admission leaked reservation")
	}
	a()
	b()
	c, ok := m.acquireCensus(false, false)
	if !ok {
		t.Fatal("ordinary cannot resume")
	}
	c()
	if len(m.census) != 0 || len(m.queueCensus) != 0 {
		t.Fatal("leaked tokens")
	}
}
func TestNoReservationPreservesOrdinaryCapacity(t *testing.T) {
	m := &WineObservers{census: make(chan struct{}, 2)}
	a, ok := m.acquireCensus(false, false)
	if !ok {
		t.Fatal("first")
	}
	b, ok := m.acquireCensus(false, false)
	if !ok {
		t.Fatal("second")
	}
	if _, ok = m.acquireCensus(false, true); ok {
		t.Fatal("exceeded total")
	}
	a()
	b()
}
