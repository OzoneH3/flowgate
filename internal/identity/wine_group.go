package identity

import (
	"fmt"
	"sync"
	"time"
)

type wineGroupSession struct {
	resolve func(*WineTable) Attribution
	retired bool
}

// MaxRuntimeObservationFlows bounds one scheduler-frozen observation group.
// Packet membership is owned by the scheduler; this API never accepts arrivals.
const MaxRuntimeObservationFlows = 8

// ResolveFrozenRuntime shares fresh raw discovery only. Each verified session
// finishes independently, so a slow prefix is not a whole-group verdict barrier.
// A nil attribution asks the caller to use its unchanged ordinary resolver.
func (m *WineObservers) ResolveFrozenRuntime(flows []Flow, emit func(int, *Attribution)) {
	started := time.Now()
	defer func() { m.renewalCount.Add(1); m.renewalTotalNS.Add(uint64(time.Since(started))) }()
	if len(flows) == 0 {
		return
	}
	if len(flows) > MaxRuntimeObservationFlows {
		for i := range flows {
			emit(i, nil)
		}
		return
	}
	for _, f := range flows {
		if f.Protocol != "udp" || f.NetNS != flows[0].NetNS || f.Direction != flows[0].Direction {
			for i := range flows {
				emit(i, nil)
			}
			return
		}
	}
	phaseStart := renewalBootNow()
	observed := time.Now()
	initial := ResolveBatch(flows)
	initialDone := renewalBootNow()
	type prefixWork struct {
		broker  *Process
		bin     string
		indices []int
	}
	groups := []*prefixWork{}
	byKey := map[string]*prefixWork{}
	for i, a := range initial {
		broker, bin, _ := m.selectBroker(a)
		if broker == nil {
			// An incomplete union scan must not change non-runtime outcomes.
			// The ordinary path obtains its own fresh evidence.
			emit(i, nil)
			continue
		}
		if !a.VisibilityComplete {
			a.Application = nil
			a.Association = nil
			a.Status = "unidentified"
			emit(i, &a)
			continue
		}
		key := fmt.Sprintf("%d:%s:%s:%s", broker.PID, broker.Start, broker.ExecutableRevision, broker.Application.Prefix)
		g := byKey[key]
		if g == nil {
			g = &prefixWork{broker: broker, bin: bin}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.indices = append(g.indices, i)
	}
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		go func(g *prefixWork) {
			defer wg.Done()
			fs := make([]Flow, len(g.indices))
			as := make([]Attribution, len(g.indices))
			for j, i := range g.indices {
				fs[j] = flows[i]
				as[j] = initial[i]
			}
			phase := &renewalPhase{Flow: fs[0].Key(), Start: phaseStart, InitialDone: initialDone, GroupSize: len(fs)}
			as[0].renewalPhase = phase
			defer func() { phase.Finished = renewalBootNow(); m.renewalPhases.add(*phase) }()
			var resolved []Attribution
			session := &wineGroupSession{resolve: func(w *WineTable) Attribution {
				resolved = w.resolveFrozenPrefix(fs, as, observed)
				return resolved[0]
			}}
			result, _ := m.sessionResolvePriority(fs[0], as[0], g.broker, g.bin, true, true, session)
			if len(resolved) == 0 {
				for _, i := range g.indices {
					emit(i, nil)
				}
				return
			}
			// sessionResolve rechecks retirement after releasing its pin. Never publish
			// any group result that bypasses that existing lifecycle guard.
			if session.retired {
				for j := range resolved {
					resolved[j].Application = nil
					resolved[j].Association = nil
					resolved[j].Status = "unidentified"
					resolved[j].setReason(result.ReasonCode, result.Reason)
				}
			}
			for j, i := range g.indices {
				a := resolved[j]
				a.renewalPhase = nil
				emit(i, &a)
			}
		}(g)
	}
	wg.Wait()
}

func (w *WineTable) resolveFrozenPrefix(flows []Flow, initial []Attribution, observed time.Time) []Attribution {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(observed) >= wineDispatchTTL {
		observed = time.Now()
		initial = ResolveBatch(flows)
	}
	out := make([]Attribution, len(flows))
	prepared := make([]*preparedWineCensus, len(flows))
	pending := []int{}
	finalFlows := []Flow{}
	// Helper and image checks are fresh within this frozen prefix group only.
	// Keys include exact process generation/revision; no later group reuses them.
	servers := map[string]bool{}
	serverValid := func(b *Process) bool {
		key := fmt.Sprintf("%d:%s:%s", b.PID, b.Start, b.ExecutableRevision)
		if ok, exists := servers[key]; exists {
			return ok
		}
		ok := w.sameServer(b)
		servers[key] = ok
		return ok
	}
	for i, f := range flows {
		a := initial[i]
		flowObserved := observed
		if time.Since(observed) >= wineDispatchTTL {
			flowObserved = time.Now()
			a = Resolve(f)
		}
		a.diagnosticSource = "frozen_runtime_group"
		a.diagnosticHintAge = time.Since(flowObserved)
		p, result := w.prepareCensusLocked(f, a, serverValid)
		if p == nil {
			out[i] = result
			continue
		}
		prepared[i] = p
		pending = append(pending, i)
		finalFlows = append(finalFlows, f)
	}
	// Starts only AFTER every included first runtime snapshot. Other prefixes
	// never participate in this barrier or wait for it before their completion.
	final := ResolveBatch(finalFlows)
	images := map[string]bool{}
	imageVisible := func(b *Process, path, revision string) bool {
		key := fmt.Sprintf("%d:%s:%s:%s", b.PID, b.Start, path, revision)
		if ok, exists := images[key]; exists {
			return ok
		}
		ok := w.imageRevisionVisible(b, path, revision)
		images[key] = ok
		return ok
	}
	for j, i := range pending {
		out[i] = w.completeCensusLocked(prepared[i], final[j], imageVisible)
	}
	return out
}
