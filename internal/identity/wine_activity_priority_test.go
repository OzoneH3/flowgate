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

func TestActivityScanReleasesBrokerForAdmission(t *testing.T) {
	for _, mode := range []string{"resume", "admission", "budget", "generation", "stopped", "lost"} {
		t.Run(mode, func(t *testing.T) {
			w := &WineTable{}
			w.mu.Lock()
			permitted := true
			fresh, acquired := w.activityCollect(func() ActivitySnapshot {
				if !w.mu.TryLock() {
					t.Fatal("process scan still blocks admission on broker lock")
				}
				if mode == "generation" {
					w.generation = "replacement"
				}
				if mode == "stopped" {
					w.dead = true
				}
				if mode == "lost" {
					w.lost.Store(true)
				}
				if mode != "admission" {
					w.mu.Unlock()
				}
				if mode == "budget" {
					permitted = false
				}
				return ActivitySnapshot{Complete: true, Sequence: 42}
			}, func() bool { return permitted })
			if mode == "admission" {
				w.mu.Unlock()
			}
			if acquired {
				w.mu.Unlock()
			}
			if acquired != (mode == "resume") || !fresh.Complete || fresh.Sequence != 42 {
				t.Fatalf("mode=%s acquired=%v snapshot=%+v", mode, acquired, fresh)
			}
			if !w.mu.TryLock() {
				t.Fatal("broker mutex leaked")
			}
			w.mu.Unlock()
		})
	}
}
