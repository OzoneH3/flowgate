package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
)

func (e *Engine) defaultLoopback(f identity.Flow) bool {
	if !identity.IsLoopbackFlow(f) {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(policy.LoopbackRules(e.activeRulesLocked(e.rules), f, e.Now())) == 0
}
