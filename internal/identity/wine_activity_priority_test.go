package identity

import "testing"

func TestActivityYieldsToAdmissionDemand(t *testing.T) {
	m := &WineObservers{census: make(chan struct{}, 2)}
	m.admissionDemand.Store(1)
	if m.tryActivityCensus() || len(m.census) != 0 {
		t.Fatal("presentation took a slot ahead of admission")
	}
	m.admissionDemand.Store(0)
	if !m.tryActivityCensus() {
		t.Fatal("idle presentation cannot resume")
	}
	<-m.census
	m.census <- struct{}{}
	m.census <- struct{}{}
	if m.tryActivityCensus() || len(m.census) != 2 {
		t.Fatal("presentation did not yield to occupied slots")
	}
}
