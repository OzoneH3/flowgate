package daemon

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/socketgrant"
	"fmt"
	"runtime/pprof"
	"time"
)

const connectionCheckInterval = 5 * time.Second

func connectionStatus(out map[string]any, s *socketAuthorization) {
	out["revocation_unconfirmed"] = s.revocationUnconfirmed
	out["authorization"] = "socket-and-destination"
	out["window_ms"] = 0
	out["ownership_renewal_required"] = false
	out["background_check_interval_ms"] = connectionCheckInterval.Milliseconds()
	out["background_inconclusive"] = s.backgroundInconclusive
	out["confirmed_changes"] = s.confirmedChanges
	out["closed_connections"] = s.closedConnections
}

// Only positive complete evidence can change an established identity. Failed,
// slow or ambiguous observations have no effect on the existing authorization.
func (e *Engine) checkConnectionObservationLocked(s *socketAuthorization, f *socketFlow, a identity.Attribution) {
	if s.flows[s.flowKey(f.flow)] != f {
		return
	}
	k, ok := socketgrant.KeyForQueuedOutput(f.flow, a)
	if !ok {
		s.backgroundInconclusive++
		return
	}
	if k == f.key && a.Application.Key == f.application && a.Application.Revision == f.authorizedRevision {
		return
	}
	if err := s.store.Forget(f.key); err != nil {
		e.failConnectionAuthorizationLocked(s, err)
		return
	}
	f.haveKey = false
	f.completeObservationWait()
	delete(s.flows, s.flowKey(f.flow))
	s.confirmedChanges++
	// A new owner must receive its own current policy decision on the queue.
}

// A complete kernel UDP dump can establish closure independently of process
// visibility. Dump errors do not remove entries. A closed cookie cannot match a
// new socket even before this bounded map cleanup runs.
func (e *Engine) sweepConnectionSockets(s *socketAuthorization) {
	sockets, err := s.socketSnapshot()
	if err != nil {
		return
	}
	present := map[uint64]bool{}
	for _, socket := range sockets {
		b, err := hex.DecodeString(socket.Cookie)
		if err == nil && len(b) == 8 && socket.NetNS == identity.NetNS() {
			present[binary.NativeEndian.Uint64(b)] = true
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketAuthorization != s || s.disabled || s.failure != nil {
		return
	}
	for key, f := range s.flows {
		if !f.haveKey {
			continue
		}
		expired := f.deadline != 0 && socketgrant.BootNow() >= f.deadline
		if present[f.key.Cookie] && !expired {
			continue
		}
		if err := s.store.Forget(f.key); err != nil {
			e.failConnectionAuthorizationLocked(s, err)
			return
		}
		f.haveKey = false
		f.completeObservationWait()
		delete(s.flows, key)
		s.closedConnections++
	}
}

// Connection grants do not depend on this worker's progress. Initial proofs
// remain on the ordinary packet path; background checks never own packet batches.
func (e *Engine) runConnectionAuthorization(ctx context.Context, s *socketAuthorization) {
	defer close(s.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	nextSweep := time.Now().Add(time.Second)
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.failConnectionAuthorizationLocked(s, ctx.Err())
			e.mu.Unlock()
			return
		case <-ticker.C:
		case <-s.wake:
		}
		if !time.Now().Before(nextSweep) {
			e.sweepConnectionSockets(s)
			nextSweep = time.Now().Add(time.Second)
		}
		e.mu.Lock()
		for s.failure == nil && !s.disabled && s.active < 2 {
			now := time.Now()
			var chosen *socketFlow
			for _, f := range s.flows {
				if f.busy || now.Before(f.next) {
					continue
				}
				if chosen == nil || (chosen.haveKey && !f.haveKey) || (chosen.haveKey == f.haveKey && f.next.Before(chosen.next)) {
					chosen = f
				}
			}
			if chosen == nil || (chosen.haveKey && s.active != 0) {
				break
			}
			group := s.connectionCheckGroup(chosen, now)
			for _, f := range group {
				f.busy = true
			}
			s.active++
			s.jobs.Add(1)
			ticket := s.store.Begin()
			if len(group) > 1 {
				s.groups++
				s.groupFlows += uint64(len(group))
			}
			go e.resolveConnectionChecks(ctx, s, group, ticket)
		}
		e.mu.Unlock()
	}
}

// Only already-due established runtime sockets may share a fresh observation.
// No arrival wait, cadence alignment, initial grant or saved proof is involved.
func (s *socketAuthorization) connectionCheckGroup(chosen *socketFlow, now time.Time) []*socketFlow {
	group := []*socketFlow{chosen}
	if s.resolveGroup == nil || !chosen.haveKey || !chosen.runtime {
		return group
	}
	for _, f := range s.flows {
		if len(group) == identity.MaxRuntimeObservationFlows {
			break
		}
		if !f.busy && !f.next.After(now) && renewalPeers(chosen, f) {
			group = append(group, f)
		}
	}
	return group
}

func (e *Engine) resolveConnectionChecks(ctx context.Context, s *socketAuthorization, group []*socketFlow, ticket socketgrant.Ticket) {
	defer func() {
		e.mu.Lock()
		s.active--
		s.jobs.Done()
		e.mu.Unlock()
		s.wakeScheduler()
	}()
	// Existing grouped resolvers may emit from independent prefix goroutines.
	// The engine lock serializes completion and also guards this per-pass set.
	completed := make([]bool, len(group))
	emit := func(i int, a *identity.Attribution) {
		e.mu.Lock()
		if i < 0 || i >= len(group) || completed[i] {
			e.mu.Unlock()
			return
		}
		completed[i] = true
		e.mu.Unlock()
		f := group[i]
		if a == nil {
			fresh := s.resolve(f.flow)
			a = &fresh
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if ctx.Err() == nil && e.socketAuthorization == s && s.failure == nil && !s.disabled && s.flows[s.flowKey(f.flow)] == f {
			e.finishSocketAuthorizationLocked(s, f, ticket, *a)
			s.checks++
		}
		f.busy = false
		f.next = time.Now().Add(connectionCheckInterval)
	}
	pprof.Do(ctx, pprof.Labels("flowgate_work", "socket_connection_check"), func(context.Context) {
		if len(group) == 1 {
			a := s.resolve(group[0].flow)
			emit(0, &a)
		} else {
			flows := make([]identity.Flow, len(group))
			for i, f := range group {
				flows[i] = f.flow
			}
			s.resolveGroup(flows, emit)
		}
	})
	// A missing result is inconclusive, never a reason to remove an existing
	// grant or leave its scheduling state stuck. It gets the same next cadence.
	e.mu.Lock()
	for i, f := range group {
		if !completed[i] {
			if ctx.Err() == nil && e.socketAuthorization == s && s.failure == nil && !s.disabled && s.flows[s.flowKey(f.flow)] == f {
				s.backgroundInconclusive++
			}
			f.busy = false
			f.next = time.Now().Add(connectionCheckInterval)
		}
	}
	e.mu.Unlock()
}

func (e *Engine) failConnectionAuthorizationLocked(s *socketAuthorization, cause error) {
	s.failure = cause
	if err := s.store.Close(); err != nil {
		s.revocationUnconfirmed = true
		s.failure = fmt.Errorf("KERNEL REVOCATION UNCONFIRMED: %v; %w", cause, err)
	} else {
		s.disabled = true
	}
}

// Detached evidence for policy re-evaluation of this already-authorized socket.
// It carries no fresh-proof marker and is never used to authorize a new tuple.
func snapshotConnectionPolicy(a identity.Attribution) *identity.Attribution {
	cloneApp := func(app identity.Application) identity.Application {
		app.Evidence = append([]string(nil), app.Evidence...)
		if app.Hosted != nil {
			h := *app.Hosted
			h.Chain = append([]identity.HostedStep(nil), h.Chain...)
			app.Hosted = &h
		}
		return app
	}
	out := identity.Attribution{VisibilityComplete: a.VisibilityComplete, Status: a.Status, Reason: a.Reason, ReasonCode: a.ReasonCode, Fingerprint: a.Fingerprint, Sockets: append([]identity.Socket(nil), a.Sockets...), Owners: append([]identity.Process(nil), a.Owners...)}
	if a.Application != nil {
		app := cloneApp(*a.Application)
		out.Application = &app
	}
	for i := range out.Owners {
		out.Owners[i].Application = cloneApp(out.Owners[i].Application)
		out.Owners[i].Provenance = nil
	}
	if a.Table != nil {
		table := *a.Table
		table.Owners = append([]identity.WindowsOwner(nil), a.Table.Owners...)
		out.Table = &table
	}
	if a.Association != nil {
		association := *a.Association
		association.Evidence = append([]string(nil), association.Evidence...)
		association.Assumptions = append([]string(nil), association.Assumptions...)
		out.Association = &association
	}
	return &out
}

// A rule edit must revoke changed permissions, without sending still-allowed
// established connections through identity discovery again. The engine lock
// covers evaluation, confirmed kernel changes and policy publication.
func (e *Engine) reconcileSocketPolicyLocked(next []policy.Rule) error {
	e.queuePolicyEpoch.Add(1)
	s := e.socketAuthorization
	if s == nil || !s.connectionScoped || s.disabled || s.failure != nil {
		return e.revokeSocketGrantsLocked()
	}
	if err := s.store.InvalidateTickets(); err != nil {
		e.failConnectionAuthorizationLocked(s, err)
		if s.disabled {
			return nil
		}
		return s.failure
	}
	now := e.Now()
	for key, f := range s.flows {
		keep := false
		horizon := uint64(0)
		if f.haveKey && f.connectionPolicy != nil {
			a := *f.connectionPolicy
			bound, ok := socketgrant.KeyForQueuedOutput(f.flow, a)
			if ok && bound == f.key && a.Application.Key == f.application && a.Application.Revision == f.authorizedRevision {
				action, id, _ := e.evaluateLocked(next, f.flow, a, now)
				var rule *policy.Rule
				for i := range next {
					if next[i].ID == id {
						rule = &next[i]
						break
					}
				}
				// Keep exactly the initially-supported explicit app permission class.
				keep = action == "allow" && rule != nil && !rule.NetworkEndpoint && rule.Preset == nil && rule.Filter.Application == a.Application.Key && rule.Filter.UID == a.Principal().UID && rule.Filter.Process.IsZero() && rule.Filter.InterfaceIndex == 0 && rule.Filter.InterfaceName == "" && rule.Filter.PeerService.Application == "" && !rule.Filter.AllPrograms && !rule.Filter.AllUIDs && e.leaseForLocked(f.flow, a, now) == nil
				if keep && !rule.Expires.IsZero() {
					remaining := rule.Expires.Sub(now)
					if remaining <= 0 {
						keep = false
					} else {
						horizon = socketgrant.BootNow() + uint64(remaining)
					}
				}
			}
		}
		if keep && (f.deadline == 0 || socketgrant.BootNow() < f.deadline) {
			if horizon != 0 && (f.deadline == 0 || horizon < f.deadline) {
				if err := s.store.Limit(f.key, horizon); err != nil {
					e.failConnectionAuthorizationLocked(s, err)
					if s.disabled {
						return nil
					}
					return s.failure
				}
				f.deadline = horizon
			}
			continue
		}
		if f.haveKey {
			if err := s.store.Forget(f.key); err != nil {
				e.failConnectionAuthorizationLocked(s, err)
				if s.disabled {
					return nil
				}
				return s.failure
			}
			f.haveKey = false
		}
		f.completeObservationWait()
		delete(s.flows, key)
	}
	return nil
}
