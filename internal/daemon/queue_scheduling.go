package daemon

import "time"

// QueuePolicyEpoch invalidates scheduling hints only. It never authorizes traffic.
func (e *Engine) QueuePolicyEpoch() uint64 { return e.queuePolicyEpoch.Load() }

// QueueSchedulingHint binds a completed decision's scheduling metadata to the
// policy that evaluated it, and never outlives a temporary deciding rule.
func (v Event) QueueSchedulingHint() (uint64, time.Time) {
	until := v.Deadline
	if v.State == "allowed" {
		until = time.Time{}
	}
	if v.decided != nil && !v.decided.Expires.IsZero() && (until.IsZero() || v.decided.Expires.Before(until)) {
		until = v.decided.Expires
	}
	return v.queuePolicyEpoch, until
}
