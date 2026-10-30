package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"time"
)

const socketOrdinaryYieldLimit = 100 * time.Millisecond

// EnableSocketOrdinaryYield is an isolated scheduling experiment. It requires
// first-grant merging, but never modifies the permission decision or its expiry.
func (e *Engine) EnableSocketOrdinaryYield(resolve func(identity.Flow, func()) (identity.Attribution, uint64)) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.socketAuthorization
	if e.Mode != "isolated-lab" || s == nil || s.ordinaryObserved == nil || resolve == nil {
		return fmt.Errorf("isolated observed resolver required")
	}
	s.ordinaryYield = true
	s.ordinaryAdmission = resolve
	return nil
}

func (f *socketFlow) completeObservationWait() {
	if f.observationDone != nil {
		close(f.observationDone)
		f.observationDone = nil
	}
}

// Historical cost is only a scheduling estimate. Kernel expiry is authoritative.
func renewalAtRisk(f *socketFlow, now time.Time, boot uint64) bool {
	if !f.runtime || !f.haveKey || f.deadline == 0 {
		return false
	}
	cost := f.maxRenewalDuration()
	if cost <= 0 {
		return false
	}
	if !f.busy && f.renewalEligibleAt().After(now) {
		return false
	}
	if f.deadline <= boot {
		return true
	}
	if f.busy {
		cost -= now.Sub(f.verificationStarted)
		if cost < 0 {
			cost = 0
		}
	} else {
		if f.renewalEligibleAt().After(now) {
			return false
		}
		cost += now.Sub(f.renewalEligibleAt())
	}
	return time.Duration(f.deadline-boot) <= cost+20*time.Millisecond
}

// Capture completion notifications, not evidence. One absolute wait cap per
// ordinary full scan; no lock, observer slot or renewal job is held while waiting.
func (e *Engine) yieldSocketOrdinaryScan(s *socketAuthorization, flow identity.Flow) {
	e.mu.Lock()
	if e.socketAuthorization != s || !s.ordinaryYield || s.disabled || s.failure != nil || s.flows[s.flowKey(flow)] != nil {
		e.mu.Unlock()
		return
	}
	now, boot := time.Now(), socketgrant.BootNow()
	waits := make([]<-chan struct{}, 0, 8)
	for _, f := range s.flows {
		if !renewalAtRisk(f, now, boot) {
			continue
		}
		if f.observationDone == nil {
			f.observationDone = make(chan struct{})
		}
		waits = append(waits, f.observationDone)
	}
	if len(waits) == 0 {
		e.mu.Unlock()
		return
	}
	s.ordinaryYieldCount++
	s.wakeScheduler()
	var stopped <-chan struct{}
	if s.ctx != nil {
		stopped = s.ctx.Done()
	}
	e.mu.Unlock()
	timer := time.NewTimer(socketOrdinaryYieldLimit)
	defer timer.Stop()
	capped := false
waiting:
	for _, done := range waits {
		select {
		case <-done:
		case <-timer.C:
			capped = true
			break waiting
		case <-stopped:
			break waiting
		}
	}
	elapsed := time.Since(now)
	e.mu.Lock()
	s.ordinaryYieldNS += uint64(elapsed)
	if uint64(elapsed) > s.ordinaryYieldMaxNS {
		s.ordinaryYieldMaxNS = uint64(elapsed)
	}
	if capped {
		s.ordinaryYieldCaps++
	}
	e.mu.Unlock()
}
