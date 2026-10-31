package daemon

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flowgate/internal/identity"
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
			f := chosen
			f.busy = true
			s.active++
			s.jobs.Add(1)
			ticket := s.store.Begin()
			go func() {
				var a identity.Attribution
				pprof.Do(ctx, pprof.Labels("flowgate_work", "socket_connection_check"), func(context.Context) { a = s.resolve(f.flow) })
				e.mu.Lock()
				if ctx.Err() == nil && e.socketAuthorization == s && s.failure == nil && !s.disabled && s.flows[s.flowKey(f.flow)] == f {
					e.finishSocketAuthorizationLocked(s, f, ticket, a)
					s.checks++
				}
				f.busy = false
				f.next = time.Now().Add(connectionCheckInterval)
				s.active--
				s.jobs.Done()
				e.mu.Unlock()
				s.wakeScheduler()
			}()
		}
		e.mu.Unlock()
	}
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
