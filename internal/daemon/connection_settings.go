package daemon

import "strconv"

const ConnectionChecksCapability = "connection-check-settings-v1"

type ConnectionCheckSettings struct {
	Enabled  bool   `json:"enabled"`
	Revision string `json:"revision"`
}
type ConnectionCheckOptions struct {
	Enabled          *bool  `json:"enabled"`
	ExpectedRevision string `json:"expected_revision"`
}

// Initialize before serving. Persistence failure must never change live settings.
func (e *Engine) InitConnectionChecks(disabled bool, revision uint64, save func(bool, uint64) error) {
	e.connectionChecksDisabled = disabled
	e.connectionChecksRevision = revision
	e.saveConnectionChecks = save
}
func (e *Engine) connectionChecksLocked() ConnectionCheckSettings {
	return ConnectionCheckSettings{!e.connectionChecksDisabled, strconv.FormatUint(e.connectionChecksRevision, 10)}
}
func (e *Engine) ConnectionChecks() ConnectionCheckSettings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.connectionChecksLocked()
}
func (e *Engine) ConfigureConnectionChecks(generation string, o ConnectionCheckOptions, admin, readonly bool) (ConnectionCheckSettings, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !admin || readonly {
		return ConnectionCheckSettings{}, mutationError("forbidden", "Connection checks require administrator on the writable primary endpoint")
	}
	if generation != e.Generation {
		return ConnectionCheckSettings{}, mutationError("stale_generation", "Daemon changed; refresh settings")
	}
	if e.saveConnectionChecks == nil {
		return ConnectionCheckSettings{}, mutationError("unavailable", "Persistent connection settings unavailable")
	}
	if o.Enabled == nil {
		return ConnectionCheckSettings{}, mutationError("invalid_request", "Explicit enabled value required")
	}
	if o.ExpectedRevision != strconv.FormatUint(e.connectionChecksRevision, 10) {
		return ConnectionCheckSettings{}, mutationError("revision_conflict", "Settings changed; refresh")
	}
	if err := e.saveConnectionChecks(!*o.Enabled, e.connectionChecksRevision); err != nil {
		return ConnectionCheckSettings{}, mutationError("persistence_failed", err.Error())
	}
	e.connectionChecksDisabled = !*o.Enabled
	e.connectionChecksRevision++
	if s := e.socketAuthorization; s != nil {
		s.wakeScheduler()
	}
	return e.connectionChecksLocked(), nil
}

// Only scheduling of already-authorized ownership observations is optional.
// Initial proofs, policy reconciliation, deadlines and socket cleanup are not.
func (e *Engine) connectionCheckDue(f *socketFlow) bool {
	return !f.haveKey || !e.connectionChecksDisabled
}
