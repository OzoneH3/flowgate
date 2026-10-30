package identity

import (
	"errors"
	"testing"
)

func TestWineFrozenGroupScopeFallsBackWithoutDiscovery(t *testing.T) {
	for _, kind := range []string{"limit", "namespace", "direction", "native"} {
		t.Run(kind, func(t *testing.T) {
			model := &dumpModel{sockets: batchSockets()}
			model.install(t)
			f := batchFlow("udp", "192.0.2.10:40003", "203.0.113.9:53")
			flows := []Flow{f, f}
			switch kind {
			case "limit":
				flows = make([]Flow, MaxRuntimeObservationFlows+1)
			case "namespace":
				flows[1].NetNS = "net:[1]"
			case "direction":
				flows[1].Direction = "incoming"
			case "native":
				flows[1].Protocol = "tcp"
			}
			seen := make([]int, len(flows))
			m := &WineObservers{}
			m.ResolveFrozenRuntime(flows, func(i int, a *Attribution) {
				seen[i]++
				if a != nil {
					t.Fatal("ineligible group acquired authority")
				}
			})
			for _, n := range seen {
				if n != 1 {
					t.Fatal("missing/duplicate completion")
				}
			}
			if len(model.full) != 0 {
				t.Fatal("ineligible group performed socket discovery")
			}
		})
	}
}

func TestWineFrozenGroupIncompleteBrokerlessFallsBack(t *testing.T) {
	model := &dumpModel{fullErr: errors.New("incomplete socket census")}
	model.install(t)
	m := &WineObservers{}
	f := batchFlow("udp", "192.0.2.10:40003", "203.0.113.9:53")
	seen := 0
	m.ResolveFrozenRuntime([]Flow{f, f}, func(_ int, a *Attribution) {
		seen++
		if a != nil {
			t.Fatal("brokerless failure replaced ordinary resolver")
		}
	})
	if seen != 2 {
		t.Fatal("missing completion")
	}
}
