package daemon

import (
	"flowgate/internal/policy"
	"fmt"
)

const ConditionalDeleteCapability = "conditional-rule-delete-v1"
const ConditionalMutationCapability = "conditional-rule-mutation-v1"

type RuleMutationError struct {
	Code    string
	Message string
}

func (e *RuleMutationError) Error() string     { return e.Message }
func mutationError(code, message string) error { return &RuleMutationError{code, message} }

type DeletedRule struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

// DeleteRule serializes the condition, durable transaction and publication with
// EditRule/ChangeRule. Generation is immutable for the lifetime of an Engine.
func (e *Engine) DeleteRule(generation, id string, expected *uint64, uid uint32, admin bool) (DeletedRule, error) {
	active := false
	if e.Enforcement != nil {
		active = e.Enforcement().State != "stopped"
	}
	e.mu.Lock()
	defer e.unlockAndSettle()
	if generation == "" || generation != e.Generation {
		return DeletedRule{}, mutationError("generation_conflict", "backend generation changed or missing; reload")
	}
	if expected == nil || id == "" {
		return DeletedRule{}, mutationError("invalid_request", "rule ID and expected_version required")
	}
	if e.SaveRules == nil {
		return DeletedRule{}, mutationError("unavailable", "durable rules unavailable")
	}
	for i, r := range e.rules {
		if r.ID != id {
			continue
		}
		if !admin && (r.Filter.AllUIDs || r.Filter.UID != uid) {
			return DeletedRule{}, mutationError("forbidden", "not authorized")
		}
		if r.Preset != nil && active {
			return DeletedRule{}, mutationError("protection_active", "Stop protection before removing preset permissions")
		}
		if r.Version != *expected {
			return DeletedRule{}, mutationError("version_conflict", "stale rule version; reload before deleting")
		}
		next := make([]policy.Rule, 0, len(e.rules)-1)
		next = append(next, e.rules[:i]...)
		next = append(next, e.rules[i+1:]...)
		if err := e.reconcileSocketPolicyLocked(next); err != nil {
			return DeletedRule{}, err
		}
		if err := e.SaveRules(next); err != nil {
			return DeletedRule{}, mutationError("persistence_failed", fmt.Sprintf("delete transaction failed; old policy retained: %v", err))
		}
		e.rules = next
		e.pruneHandlesLocked()
		// Same conservative invalidation as legacy deletion: cached rule verdicts
		// drop; explicit Once/For-a-while answers stay (configured rules still win).
		e.resetCachedLocked("rule deleted")
		return DeletedRule{ID: r.ID, Version: r.Version}, nil
	}
	// A missing rule is not idempotent success: its absence alone cannot prove
	// which request removed it after a lost response.
	return DeletedRule{}, mutationError("not_found", "rule no longer exists; reload authoritative state")
}
