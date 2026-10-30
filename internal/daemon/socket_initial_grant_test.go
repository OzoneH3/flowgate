package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"testing"
	"time"
)

func TestSocketInitialGrantProofPolicyAndBounds(t *testing.T) {
	for _, mode := range []string{"fresh", "hint", "old-start", "future-start", "epoch-edit", "deny", "ask", "incomplete", "other-app", "other-prefix", "map-full", "app-full", "existing"} {
		t.Run(mode, func(t *testing.T) {
			e, s, f, a, m := wineGrantFixture(t)
			delete(s.flows, f.flow.Key())
			switch mode {
			case "deny":
				e.rules[0].Action = "block"
			case "ask":
				e.rules[0].Action = "ask"
			case "incomplete":
				a.VisibilityComplete = false
			case "other-app":
				a.Application.Executable = "/synthetic/beta.exe"
				a.Application.Key = identity.ApplicationKey(1000, *a.Application)
			case "other-prefix":
				a.Application.Prefix = "/synthetic/prefix-two"
				a.Table.Prefix = a.Application.Prefix
				a.Application.Key = identity.ApplicationKey(1000, *a.Application)
			case "map-full":
				for i := 0; i < socketgrant.MaxEntries; i++ {
					s.flows[fmt.Sprint(i)] = &socketFlow{application: "other"}
				}
			case "app-full":
				for i := 0; i < 8; i++ {
					s.flows[fmt.Sprint(i)] = &socketFlow{application: a.Application.Key}
				}
			case "existing":
				s.flows[f.flow.Key()] = f
				f.busy = true
				s.active = 1
			}
			calls := 0
			s.ordinaryObserved = func(identity.Flow) (identity.Attribution, uint64) {
				calls++
				e.mu.Lock()
				active := s.active
				e.mu.Unlock()
				if active != 0 {
					t.Fatal("initial observation took renewal job")
				}
				stamp := socketgrant.BootNow()
				switch mode {
				case "hint":
					stamp = 0
				case "old-start":
					stamp = 1
				case "future-start":
					stamp += uint64(time.Hour)
				case "epoch-edit":
					if err := e.SetRules(append(e.rules[:0:0], e.rules...)); err != nil {
						t.Fatal(err)
					}
				}
				return a, stamp
			}
			_, ok := e.resolveSocketInitialBatch(f.flow)
			if mode == "existing" {
				if ok || calls != 0 || s.flows[f.flow.Key()] != f || !f.busy || s.active != 1 {
					t.Fatal("existing renewal touched")
				}
				return
			}
			if !ok || calls != 1 || s.active != 0 {
				t.Fatal("ordinary resolver/admission changed")
			}
			if (len(m.values) == 1) != (mode == "fresh") {
				t.Fatalf("mode=%s grants=%d", mode, len(m.values))
			}
			if mode == "deny" || mode == "ask" || mode == "other-app" || mode == "other-prefix" || mode == "incomplete" {
				if len(s.flows) != 0 {
					t.Fatal("refusal allocated persistent renewal work")
				}
			}
			if mode == "map-full" && len(s.flows) != socketgrant.MaxEntries {
				t.Fatal("map capacity changed")
			}
			if mode == "app-full" && len(s.flows) != 8 {
				t.Fatal("per-app capacity exceeded")
			}
		})
	}
}

func TestSocketInitialGrantFrozenBatchKeepsPerPacketPolicy(t *testing.T) {
	e, s, f, a, m := wineGrantFixture(t)
	delete(s.flows, f.flow.Key())
	s.resolve = func(identity.Flow) identity.Attribution { t.Fatal("initial flow took priority resolver"); return a }
	s.ordinaryObserved = func(identity.Flow) (identity.Attribution, uint64) { return a, socketgrant.BootNow() }
	e.Resolve = func(identity.Flow) identity.Attribution { t.Fatal("duplicate initial census"); return a }
	decide, ok := e.PrepareUDPBatch(f.flow, "initial", 2, true)
	if !ok || len(m.values) != 1 {
		t.Fatal("fresh proof not shared")
	}
	if v := decide(); v.State != "allowed" {
		t.Fatal(v.State)
	}
	rules := append(e.rules[:0:0], e.rules...)
	rules[0].Action = "block"
	if err := e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	if v := decide(); v.State != "blocked" {
		t.Fatal("packet ignored current policy", v.State)
	}
}
