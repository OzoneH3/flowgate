package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

// loopbackFlow is the fresh kernel loopback-device observation used by the
// preliminary peer-prefetch check; tests substitute it to count observations.
var loopbackFlow = identity.IsLoopbackFlow

func (e *Engine) defaultLoopback(f identity.Flow) bool {
	if !loopbackFlow(f) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(policy.LoopbackRules(e.activeRulesLocked(e.rules), f, e.Now())) == 0
}
