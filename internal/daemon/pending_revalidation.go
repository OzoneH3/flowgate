package daemon

import (
	"flowgate/internal/identity"
	"strings"
)

// Called only after the existing binding predicate failed, while e.mu is held.
// Finalizing preview refusals prevents the same dead request looking actionable
// until its original deadline. Its original attribution remains the display basis.
func (e *Engine) rejectPendingBindingLocked(v *Event, current identity.Attribution) error {
	r := identity.ComparePendingBinding(v.Attribution, current, e.Now())
	r.Processes = identity.RecheckPendingProcesses(v.Attribution)
	for _, process := range r.Processes {
		if process.State == "exited" {
			r.Reason += "; original process exited"
		}
		if process.State == "changed" {
			r.Reason += "; separate process recheck found identity changes"
		}
	}
	v.Revalidation = &r
	v.State = "expired"
	fields := make([]string, 0, len(r.Changes))
	for _, c := range r.Changes {
		fields = append(fields, c.Field)
	}
	for _, p := range r.Processes {
		for _, c := range p.Changes {
			fields = append(fields, c.Field)
		}
	}
	v.Reason = r.Reason
	if len(fields) > 0 {
		v.Reason += " (changed: " + strings.Join(fields, ", ") + ")"
	}
	e.recordFinal(v, "block", r.Code, "", v.Reason, nil, nil, "deferred", "")
	return mutationError(r.Code, v.Reason)
}

func (e *Engine) rejectPendingDeadlineLocked(v *Event) error {
	v.State = "expired"
	v.Reason = "Request deadline passed during revalidation; no decision or rule saved"
	e.recordFinal(v, "block", "timeout", "", v.Reason, nil, nil, "deferred", "")
	return mutationError("stale_decision", v.Reason)
}
