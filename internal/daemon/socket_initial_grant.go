package daemon

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"runtime/pprof"
	"time"
)

// EnableSocketFirstGrantMerge requires a trusted resolver reporting the actual
// full-initial-observation start, never a cached or diagnostic timestamp.
func (e *Engine) EnableSocketFirstGrantMerge(resolve func(identity.Flow) (identity.Attribution, uint64)) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketAuthorization == nil || (e.Mode != "isolated-lab" && !e.socketAuthorization.productionSession) || resolve == nil {
		return fmt.Errorf("isolated observed resolver required")
	}
	e.socketAuthorization.ordinaryObserved = resolve
	return nil
}

// Unknown flows stay on ordinary admission. No renewal job, reserved slot or
// persistent entry is allocated before their fresh proof and current policy.
func (e *Engine) resolveSocketInitialBatch(flow identity.Flow) (identity.Attribution, bool) {
	e.mu.Lock()
	s := e.socketAuthorization
	if s == nil || s.disabled || s.failure != nil || s.ordinaryObserved == nil || s.flows[s.flowKey(flow)] != nil ||
		flow.Protocol != "udp" || flow.Direction != "outgoing" || !flow.Local.Addr().Is4() || !flow.Remote.Addr().Is4() || flow.NetNS != identity.NetNS() {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	if !s.observeQueueRoute(flow) {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	ticket := s.store.Begin()
	started := time.Now()
	resolve := s.ordinaryObserved
	admission := s.ordinaryAdmission
	e.mu.Unlock()
	var a identity.Attribution
	var observation uint64
	pprof.Do(context.Background(), pprof.Labels("flowgate_work", "queue_census", "socket_grant_stage", "initial_candidate"), func(context.Context) {
		if admission == nil {
			a, observation = resolve(flow)
			return
		}
		a, observation = admission(flow, func() {
			e.yieldSocketOrdinaryScan(s, flow)
			e.mu.Lock()
			// Start a NEW ticket immediately before the full scan, after scheduling
			// delay. This never renews an existing grant or reuses any old observation.
			if e.socketAuthorization == s && !s.disabled && s.failure == nil {
				ticket = s.store.Begin()
				started = time.Now()
			}
			e.mu.Unlock()
		})
	})
	e.mu.Lock()
	defer e.mu.Unlock()
	s.initialMergeChecks++
	if e.socketAuthorization != s || s.failure != nil || s.disabled || observation == 0 || observation < ticket.Start() || observation > socketgrant.BootNow() || s.flows[s.flowKey(flow)] != nil || len(s.flows) >= socketgrant.MaxEntries {
		return a, true
	}
	s.initialMergeFresh++
	// This temporary entry is visible only under the policy mutex. The existing
	// publication checks remove refusals, and there is no scheduler work for them.
	f := &socketFlow{flow: flow, lastPacket: socketgrant.BootNow(), next: started.Add(100 * time.Millisecond)}
	s.flows[s.flowKey(flow)] = f
	e.finishSocketAuthorizationLocked(s, f, ticket, a)
	if f.haveKey {
		f.firstGrantSource = "ordinary_fresh_merge"
		s.initialMergePublished++
	}
	if s.flows[s.flowKey(flow)] == f {
		s.wakeScheduler()
	}
	return a, true
}
