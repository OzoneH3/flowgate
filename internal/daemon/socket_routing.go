package daemon

import (
	"flowgate/internal/identity"
	"strconv"
)

func (s *socketAuthorization) flowKey(f identity.Flow) string {
	if !s.routeBound {
		return f.Key()
	}
	outdev, _ := f.QueueOutputInterface()
	return f.Key() + "|queue-outdev:" + strconv.FormatUint(uint64(outdev), 10)
}

// Coverage is a session capability, not permission authority. A new interface
// has no installed gate and must use ordinary verification, not a failing Put.
// Isolated lab backends retain their existing caller-controlled route fixtures.
func (s *socketAuthorization) coversQueueRoute(flow identity.Flow) bool {
	if !s.routeBound {
		return true
	}
	outdev, ok := flow.QueueOutputInterface()
	if !ok || s.retiredInterfaces[outdev] != "" {
		return false
	}
	if !s.productionSession {
		return true
	}
	if s.interfaceCoverage != nil {
		for _, link := range s.interfaceCoverage.Installed {
			if link.Index == outdev {
				return true
			}
		}
	}
	return false
}

// Called under Engine.mu with actual queued-packet evidence. Retiring another
// interface frees its bounded slot and invalidates any in-flight publisher.
// ECMP can repeatedly miss/reverify; it never inherits a different route's grant.
func (s *socketAuthorization) observeQueueRoute(flow identity.Flow) bool {
	if !s.routeBound {
		return true
	}
	outdev, ok := flow.QueueOutputInterface()
	if !ok || !s.coversQueueRoute(flow) {
		return false
	}
	for key, old := range s.flows {
		previous, valid := old.flow.QueueOutputInterface()
		if old.flow.Key() != flow.Key() || !valid || previous == outdev {
			continue
		}
		if old.haveKey {
			if err := s.store.Forget(old.key); err != nil {
				s.failure = err
				return false
			}
		}
		old.haveKey = false
		old.completeObservationWait()
		s.completeSocketBatchLocked(old, nil, false)
		delete(s.flows, key)
		s.routeMoves++
	}
	return true
}
