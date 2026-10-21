package queue

import (
	"errors"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"fmt"
	"testing"
	"time"
)

func event(id string) daemon.Event {
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:8", "127.0.0.1:9")
	return daemon.Event{ID: id, Flow: f, Deadline: time.Now().Add(time.Minute)}
}
func TestRetentionBoundsAndVerdicts(t *testing.T) {
	r := &Retainer{}
	v := event("one")
	for i := 0; i < 4; i++ {
		if !r.Add(uint32(i), 100, v) {
			t.Fatal("early cap")
		}
	}
	v.ID = "replacement"
	if r.Add(5, 100, v) {
		t.Fatal("per-flow cap bypassed by new event")
	}
	drops := 0
	err := r.Flush(time.Now(), func(string, string) string { return "drop" }, func(uint32, bool) error { drops++; return errors.New("queue error") }, false)
	if err == nil || drops != 4 || r.bytes != 0 || len(r.packets) != 0 {
		t.Fatal("error drain", err, drops)
	}
	for i := 0; i < 64; i++ {
		v = event(fmt.Sprint(i))
		v.Token = fmt.Sprint(i)
		if !r.Add(uint32(i), 100, v) {
			t.Fatal("global capacity")
		}
	}
	v.Token = "extra"
	if r.Add(65, 100, v) {
		t.Fatal("global cap bypass")
	}
	r.Flush(time.Now(), nil, func(_ uint32, allow bool) error {
		if allow {
			t.Fatal("shutdown allowed")
		}
		return nil
	}, true)
	v = event("large")
	if r.Add(1, MaxFlowBytes+1, v) {
		t.Fatal("flow byte cap")
	}
	for i := 0; i < 16; i++ {
		v.Token = fmt.Sprint(i)
		if !r.Add(uint32(i), MaxFlowBytes, v) {
			t.Fatal("byte budget")
		}
	}
	v.Token = "extra"
	if r.Add(32, 1, v) {
		t.Fatal("global byte cap")
	}
}
func TestRetentionTimeoutAndTCPDuplicates(t *testing.T) {
	r := &Retainer{}
	v := event("one")
	v.Flow.Protocol = "tcp"
	r.Add(1, 100, v)
	if r.Add(2, 100, v) {
		t.Fatal("TCP duplicate retained")
	}
	r.Flush(time.Now().Add(time.Hour), func(string, string) string { t.Fatal("expired consulted policy"); return "allow" }, func(_ uint32, allow bool) error {
		if allow {
			t.Fatal("expired released")
		}
		return nil
	}, false)
}

func TestRetentionAddProgressesDuringSlowRevalidation(t *testing.T) {
	r := &Retainer{}
	if !r.Add(1, 100, event("first")) {
		t.Fatal("add")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.Flush(time.Now(), func(string, string) string { close(entered); <-release; return "allow" }, func(uint32, bool) error { return nil }, false)
	}()
	<-entered
	added := make(chan bool, 1)
	go func() { v := event("second"); v.Token = "second"; added <- r.Add(2, 100, v) }()
	select {
	case ok := <-added:
		if !ok {
			t.Error("add refused")
		}
	case <-time.After(time.Second):
		t.Error("Add blocked by attribution")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.packets) != 1 || r.packets[0].id != 2 || r.bytes != 100 {
		t.Fatal("concurrent Add lost", r.packets, r.bytes)
	}
}

func TestRetentionExpiryDuringRevalidationDrainsPendingAndSkipsLaterLookup(t *testing.T) {
	r := &Retainer{}
	first, second := event("first"), event("second")
	// Long enough to reach the first state callback even under race testing.
	// The callback explicitly waits for expiry, so no scheduler timing decides
	// whether the post-resolution check is exercised.
	first.Deadline = time.Now().Add(200 * time.Millisecond)
	second.Deadline = first.Deadline
	second.Token = "second"
	if !r.Add(1, 100, first) || !r.Add(2, 100, second) {
		t.Fatal("add")
	}
	checks := 0
	verdicts := map[uint32]int{}
	err := r.Flush(time.Now(), func(id, fingerprint string) string {
		checks++
		if id != "first" {
			t.Errorf("expired later packet triggered ownership lookup: %s", id)
			return "pending"
		}
		time.Sleep(time.Until(first.Deadline) + time.Millisecond)
		return "pending"
	}, func(id uint32, allow bool) error {
		if allow {
			t.Error("expired packet allowed")
		}
		verdicts[id]++
		return nil
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if checks != 1 {
		t.Fatalf("ownership checks: %d, want 1", checks)
	}
	if verdicts[1] != 1 || verdicts[2] != 1 {
		t.Fatalf("expired pending packets not drained exactly once: %v", verdicts)
	}
	if len(r.packets) != 0 || r.bytes != 0 {
		t.Fatal("expired packets still consume retention capacity")
	}
}
