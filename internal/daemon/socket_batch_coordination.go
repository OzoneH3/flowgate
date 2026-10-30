package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"time"
)

const socketBatchCoordinationWait = 100 * time.Millisecond

type socketBatchRequest struct {
	frozen  time.Time
	until   time.Time
	started chan struct{}
	result  chan *identity.Attribution
}

// EnableSocketBatchCoordination is lab-only scheduling, not ownership reuse.
func (e *Engine) EnableSocketBatchCoordination() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketAuthorization == nil || (e.Mode != "isolated-lab" && !e.socketAuthorization.productionSession) {
		return fmt.Errorf("isolated socket authorization required")
	}
	e.socketAuthorization.batchCoordination = true
	return nil
}

// The caller has already frozen packet membership. Wait for the NEXT scheduler
// observation, never the one already in flight. e.mu is held on entry and return.
// Queue ownership, packet bounds and original packet deadlines remain unchanged.
func (e *Engine) awaitSocketBatchLocked(s *socketAuthorization, f *socketFlow) (identity.Attribution, bool) {
	if f.batchPending != nil {
		s.batchSecondClaimant++
		return identity.Attribution{}, false
	}
	now := time.Now()
	r := &socketBatchRequest{frozen: now, until: now.Add(socketBatchCoordinationWait), started: make(chan struct{}), result: make(chan *identity.Attribution, 1)}
	f.batchPending = r
	f.lastPacket = socketgrant.BootNow()
	s.batchClaims++
	s.wakeScheduler()
	timer := time.NewTimer(socketBatchCoordinationWait)
	defer timer.Stop()
	var done <-chan struct{}
	if s.ctx != nil {
		done = s.ctx.Done()
	}
	e.mu.Unlock()
	select {
	case <-r.started:
	case <-timer.C:
	case <-done:
	}
	e.mu.Lock()
	// Admission and timeout race under the same policy lock. Once selected by
	// the scheduler, this is ordinary in-progress resolution, not more wait time.
	select {
	case <-r.started:
		e.mu.Unlock()
		var a *identity.Attribution
		select {
		case a = <-r.result:
		case <-done:
		}
		e.mu.Lock()
		if a != nil {
			return *a, true
		}
		return identity.Attribution{}, false
	default:
		if f.batchPending == r {
			f.batchPending = nil
		}
		s.batchTimeouts++
		s.noteSocketBatchWait(time.Since(now))
		s.wakeScheduler()
		return identity.Attribution{}, false
	}
}

func (s *socketAuthorization) noteSocketBatchWait(wait time.Duration) {
	if wait <= 0 {
		return
	}
	s.batchWaitNS += uint64(wait)
	if uint64(wait) > s.batchMaxWaitNS {
		s.batchMaxWaitNS = uint64(wait)
	}
}

// Scheduler invokes this only after selecting/freeze of the group, before
// launching its new scan. Pending requests never read the prior busy job result.
func (s *socketAuthorization) startSocketBatchLocked(f *socketFlow, started time.Time) {
	r := f.batchPending
	if r == nil {
		return
	}
	f.batchPending = nil
	if !started.Before(r.until) || started.Before(r.frozen) {
		return
	}
	f.batchRunning = r
	s.noteSocketBatchWait(started.Sub(r.frozen))
	close(r.started)
}

func (s *socketAuthorization) completeSocketBatchLocked(f *socketFlow, a *identity.Attribution, valid bool) {
	r := f.batchRunning
	if r == nil {
		return
	}
	f.batchRunning = nil
	if valid && a != nil {
		copy := *a
		r.result <- &copy
		s.batchDelivered++
	} else {
		r.result <- nil
	}
}
