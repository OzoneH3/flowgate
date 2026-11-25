package daemon

import (
	"flowgate/internal/policy"
	"fmt"
)

const ConditionalDeleteCapability = "conditional-rule-delete-v1"
const ConditionalMutationCapability = "conditional-rule-mutation-v1"
const ApplicationRuleDeleteCapability = "application-rule-delete-v1"

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

type ApplicationRuleRef struct {
	ID      string  `json:"id"`
	Version *uint64 `json:"version"`
}

// ApplicationRuleDelete is an explicit snapshot selected from list. Rules
// added after the snapshot are outside the deletion, even for the same app.
type ApplicationRuleDelete struct {
	Application string               `json:"application"`
	UID         *uint32              `json:"uid"`
	Rules       []ApplicationRuleRef `json:"rules"`
}

// DeleteRule serializes the condition, durable transaction and publication with
// EditRule/ChangeRule. Generation is immutable for the lifetime of an Engine.
func (e *Engine) DeleteRule(generation, id string, expected *uint64, uid uint32, admin bool) (DeletedRule, error) {
	active := false
	if e.Enforcement != nil {
		active = e.Enforcement().State != "stopped"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
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
		if err := e.deleteRulesLocked(next); err != nil {
			return DeletedRule{}, err
		}
		return DeletedRule{ID: r.ID, Version: r.Version}, nil
	}
	// A missing rule is not idempotent success: its absence alone cannot prove
	// which request removed it after a lost response.
	return DeletedRule{}, mutationError("not_found", "rule no longer exists; reload authoritative state")
}

func (e *Engine) DeleteApplicationRules(generation string, selection ApplicationRuleDelete, uid uint32, admin bool) ([]DeletedRule, error) {
	if generation == "" || generation != e.Generation {
		return nil, mutationError("generation_conflict", "backend generation changed or missing; reload")
	}
	if selection.UID == nil || selection.Application == "" || len(selection.Rules) == 0 || len(selection.Rules) > 256 {
		return nil, mutationError("invalid_request", "application, UID and 1–256 exact rule versions required")
	}
	if !admin && *selection.UID != uid {
		return nil, mutationError("forbidden", "not authorized")
	}
	wanted := make(map[string]uint64, len(selection.Rules))
	deleted := make([]DeletedRule, 0, len(selection.Rules))
	for _, ref := range selection.Rules {
		if _, duplicate := wanted[ref.ID]; duplicate || ref.ID == "" || ref.Version == nil {
			return nil, mutationError("invalid_request", "unique rule IDs and explicit versions required")
		}
		wanted[ref.ID] = *ref.Version
		deleted = append(deleted, DeletedRule{ID: ref.ID, Version: *ref.Version})
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.SaveRules == nil {
		return nil, mutationError("unavailable", "durable rules unavailable")
	}
	next := make([]policy.Rule, 0, len(e.rules))
	for _, r := range e.rules {
		version, selected := wanted[r.ID]
		if !selected {
			next = append(next, r)
			continue
		}
		f := r.Filter
		if !admin && (f.AllUIDs || f.UID != uid) {
			return nil, mutationError("not_found", "a selected rule is missing; reload before deleting")
		}
		if f.AllUIDs || f.UID != *selection.UID || f.Application != selection.Application ||
			f.AllPrograms || !f.Process.IsZero() || r.Preset != nil || r.NetworkEndpoint || r.ShareWithRoot || r.RootApplication != "" {
			return nil, mutationError("invalid_target", "rule is outside the selected application's deletable scope")
		}
		if version != r.Version {
			return nil, mutationError("version_conflict", "application rule changed; reload before deleting")
		}
		delete(wanted, r.ID)
	}
	if len(wanted) != 0 {
		return nil, mutationError("not_found", "a selected rule is missing; reload before deleting")
	}
	if err := e.deleteRulesLocked(next); err != nil {
		return nil, err
	}
	return deleted, nil
}

func (e *Engine) deleteRulesLocked(next []policy.Rule) error {
	if err := e.reconcileSocketPolicyLocked(next); err != nil {
		return err
	}
	if err := e.SaveRules(next); err != nil {
		return mutationError("persistence_failed", fmt.Sprintf("delete transaction failed; old policy retained: %v", err))
	}
	e.rules = next
	e.pruneHandlesLocked()
	// Existing explicit Once/For-a-while answers remain. Pending requests are
	// re-evaluated asynchronously with fresh identity checks.
	e.resetCachedLocked("rule deleted")
	e.settleLaterLocked()
	return nil
}
