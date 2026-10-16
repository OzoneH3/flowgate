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
