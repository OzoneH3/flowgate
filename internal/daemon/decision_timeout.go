package daemon

import (
	"strconv"
	"time"
)

const DecisionTimeoutCapability = "decision-timeout-settings-v1"

type DecisionTimeoutSettings struct {
	Seconds  float64 `json:"seconds"`
	Revision string  `json:"revision"`
}

type DecisionTimeoutOptions struct {
	Seconds          int    `json:"seconds"`
	ExpectedRevision string `json:"expected_revision"`
}

// InitDecisionTimeout loads persistent settings before the queue and API start.
func (e *Engine) InitDecisionTimeout(seconds int, revision uint64, save func(int, uint64) error) {
	e.decisionTimeout = time.Duration(seconds) * time.Second
	e.decisionTimeoutRevision = revision
	e.saveDecisionTimeout = save
}

func (e *Engine) decisionTimeoutLocked() time.Duration {
	if e.decisionTimeout > 0 {
		return e.decisionTimeout
	}
	return e.Timeout
}

func (e *Engine) decisionTimeoutSettingsLocked() DecisionTimeoutSettings {
	return DecisionTimeoutSettings{e.decisionTimeoutLocked().Seconds(), strconv.FormatUint(e.decisionTimeoutRevision, 10)}
}

func (e *Engine) DecisionTimeoutSettings() DecisionTimeoutSettings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.decisionTimeoutSettingsLocked()
}

func (e *Engine) ConfigureDecisionTimeout(generation string, opts DecisionTimeoutOptions, admin, readonly bool) (DecisionTimeoutSettings, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !admin || readonly {
		return DecisionTimeoutSettings{}, mutationError("forbidden", "Decision timeout requires administrator on the writable primary endpoint")
	}
	if generation != e.Generation {
		return DecisionTimeoutSettings{}, mutationError("stale_generation", "Daemon changed; refresh settings")
	}
	if e.saveDecisionTimeout == nil {
		return DecisionTimeoutSettings{}, mutationError("unavailable", "Persistent decision timeout is unavailable")
	}
	if opts.Seconds < 2 || opts.Seconds > 60 {
		return DecisionTimeoutSettings{}, mutationError("invalid_request", "Decision timeout must be 2–60 seconds")
	}
	if opts.ExpectedRevision != strconv.FormatUint(e.decisionTimeoutRevision, 10) {
		return DecisionTimeoutSettings{}, mutationError("revision_conflict", "Settings changed; refresh")
	}
	if err := e.saveDecisionTimeout(opts.Seconds, e.decisionTimeoutRevision); err != nil {
		return DecisionTimeoutSettings{}, mutationError("persistence_failed", err.Error())
	}
	e.decisionTimeout = time.Duration(opts.Seconds) * time.Second
	e.decisionTimeoutRevision++
	return e.decisionTimeoutSettingsLocked(), nil
}
