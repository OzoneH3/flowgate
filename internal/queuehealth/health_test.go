package queuehealth

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHealthReasonsPrivacyAndRecovery(t *testing.T) {
	var r Registry
	s := r.Start(101, "both")
	if s == nil {
		t.Fatal("start")
	}
	for c := Cause(0); c < causeCount; c++ {
		s.Add(c)
	}
	s.GaugeSource(func() Gauges { return Gauges{AttributionPackets: 3, AttributionBytes: 90, RetainedPackets: 1} })
	now := time.Now().UTC()
	v := r.snapshot(now, true)
	if v.State != "pressure" || len(v.Sessions) != 1 || v.Sessions[0].Gauges.AttributionPackets != 3 {
		t.Fatal(v)
	}
	for _, key := range names {
		if v.Sessions[0].Counters[key] != "1" {
			t.Fatal(key, v)
		}
	}
	if v.CounterUnits[names[NetlinkOverflow]] != "notifications" || v.CounterUnits[names[Deadline]] != "packets" {
		t.Fatal(v.CounterUnits)
	}
	plain, _ := json.Marshal(r.snapshot(now, false))
	if strings.Contains(string(plain), "sessions") || strings.Contains(string(plain), "counters") || strings.Contains(string(plain), s.generation) {
		t.Fatal(string(plain))
	}
	recovered := r.snapshot(now.Add(RecentWindow+time.Second), true)
	if recovered.State != "ready" || recovered.Sessions[0].Counters[names[Deadline]] != "1" {
		t.Fatal(recovered)
	}
	s.End()
	ended := r.Snapshot(true)
	if ended.State != "inactive" || ended.Sessions[0].StoppedAt == nil || ended.Sessions[0].Gauges.AttributionPackets != 0 {
		t.Fatal(ended)
	}
	next := r.Start(101, "incoming")
	if next.generation == s.generation || r.Snapshot(true).Sessions[1].Counters[names[Deadline]] != "0" {
		t.Fatal("generation mixed")
	}
}
func TestHealthSaturatesConcurrentAndBounded(t *testing.T) {
	var r Registry
	s := r.Start(1, "incoming")
	s.counters[Deadline].Store(^uint64(0) - 1)
	s.Add(Deadline)
	if !s.saturated.Load() {
		t.Fatal("exact maximum must be marked saturated")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				s.Add(Deadline)
			}
		}()
	}
	wg.Wait()
	v := r.Snapshot(true)
	if !v.Sessions[0].Saturated || v.Sessions[0].Counters[names[Deadline]] != "18446744073709551615" {
		t.Fatal(v)
	}
	for range 30 {
		s.End()
		s = r.Start(1, "incoming")
	}
	if len(r.Snapshot(true).Sessions) != MaxSessions {
		t.Fatal("retention not bounded")
	}
	var full Registry
	for range MaxSessions {
		full.Start(1, "both")
	}
	if full.Start(2, "both") != nil || full.Snapshot(false).State != "unavailable" {
		t.Fatal("untracked active queue claimed healthy")
	}
}
func TestShutdownDoesNotClaimPressure(t *testing.T) {
	var r Registry
	s := r.Start(1, "incoming")
	s.Add(Shutdown)
	s.Add(RetainedShutdown)
	if r.Snapshot(false).State != "ready" {
		t.Fatal("clean shutdown pressure")
	}
}
