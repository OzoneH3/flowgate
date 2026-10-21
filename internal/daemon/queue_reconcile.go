package daemon

import (
	"flowgate/internal/identity"
	"fmt"
	"strings"
	"time"
)

// QueueReconcileCapability: decide, request-rule-save and observed-rule-save
// responses list the other requests that left awaiting-decision through the
// policy re-evaluation the operation caused (`settled`), so clients remove
// exactly those from their queue without guessing by application or endpoint.
// Events also carry `previous_revision_rules` (display only).
const QueueReconcileCapability = "queue-reconcile-v1"

// RequestForAWhileCapability: For a while from an ended (or timed-out) request
// whose exact process instance is still running. Creates the process lease
// only; the ended request is never decided or delivered.
const RequestForAWhileCapability = "request-for-a-while-v1"

// SettledRequest is one request settled by an operation's re-evaluation.
type SettledRequest struct {
	ID    string `json:"id"`
	State string `json:"state"` // allowed, blocked or expired (connection ended)
	Rule  string `json:"rule,omitempty"`
}

// RevisionRuleRef names a stored rule bound to another revision of the same
// application key (for example before an executable update).
type RevisionRuleRef struct {
	ID       string `json:"id"`
	Version  uint64 `json:"version,omitempty"`
	Action   string `json:"action"`
	Revision string `json:"revision"`
}

// collectSettledLocked starts collecting settled requests and returns the
// function restoring the previous collector (caller holds e.mu).
func (e *Engine) collectSettledLocked() func() {
	prev := e.settledSink
	list := []SettledRequest{}
	e.settledSink = &list
	return func() { e.settledSink = prev }
}

func (e *Engine) settledLocked() []SettledRequest {
	if e.settledSink == nil {
		return nil
	}
	return append([]SettledRequest{}, (*e.settledSink)...)
}

func (e *Engine) noteSettledLocked(v *Event) {
	if e.settledSink == nil {
		return
	}
	for _, s := range *e.settledSink {
		if s.ID == v.ID {
			return
		}
	}
	*e.settledSink = append(*e.settledSink, SettledRequest{ID: v.ID, State: v.State, Rule: v.Rule})
}

func (e *Engine) markRetainedDecidedLocked(id string) {
	if r := e.requestRules[id]; r != nil {
		r.Decided = true
	}
}

// previousRevisionRulesLocked: enabled, unexpired application rules for the
// same key, user and direction, but another revision. Never evaluated here.
func (e *Engine) previousRevisionRulesLocked(v *Event) []RevisionRuleRef {
	app, p := v.Attribution.Application, v.Attribution.Principal()
	if app == nil || app.Key == "" || app.Revision == "" || p == nil {
		return nil
	}
	now := e.Now()
	var out []RevisionRuleRef
	for _, r := range e.rules {
		f := r.Filter
		if r.Disabled || r.Preset != nil || f.AllPrograms || !f.Process.IsZero() || (!r.Expires.IsZero() && !now.Before(r.Expires)) {
			continue
		}
		if f.Application != app.Key || f.Revision == "" || f.Revision == app.Revision || f.Direction != v.Flow.Direction || (!f.AllUIDs && f.UID != p.UID) {
			continue
		}
		out = append(out, RevisionRuleRef{ID: r.ID, Version: r.Version, Action: r.Action, Revision: f.Revision})
		if len(out) == 8 {
			break
		}
	}
	return out
}

// ForAWhileFromRequest creates a For-a-while process lease from a retained
// request that can no longer be decided (its socket ended or it timed out)
// while its exact process instance is still running. The original PID, start
// ticks, UID, boot ID, pid/mount namespace and verified application identity
// (key, revision, executable) must all match the live process. The request
// itself stays ended: nothing is delivered and no rule is created. Other
// awaiting requests of that process and direction settle by the lease.
func (e *Engine) ForAWhileFromRequest(generation, id, action string, seconds int64, uid uint32, admin bool) (ProcessLease, []SettledRequest, error) {
	e.lockResolved(e.requestSelection(id, uid, admin, true))
	defer e.unlockResolved()
	if generation == "" || generation != e.Generation {
		return ProcessLease{}, nil, mutationError("generation_conflict", "Backend changed; reload")
	}
	d, err := forAWhileDuration(seconds)
	if err != nil {
		return ProcessLease{}, nil, err
	}
	if action != "allow" && action != "block" {
		return ProcessLease{}, nil, mutationError("invalid_request", "action must be allow or block")
	}
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	e.pruneRequestRulesLocked(now)
	e.pruneLeasesLocked(now, false)
	r := e.requestRules[id]
	if r == nil {
		return ProcessLease{}, nil, mutationError("request_unavailable", "This request's process identity is no longer retained")
	}
	if !admin && r.UID != uid {
		return ProcessLease{}, nil, mutationError("forbidden", "Request belongs to another principal")
	}
	for _, v := range e.events {
		if v.ID != id {
			continue
		}
		if v.State == "allowed" || v.State == "blocked" {
			return ProcessLease{}, nil, mutationError("request_decided", "This request was already decided")
		}
		if v.State == "awaiting-decision" && now.Before(v.Deadline) {
			a, ok := e.resolvedEventLocked(v)
			if !ok {
				return ProcessLease{}, nil, retryChangedRequest() // never infer an ended request from missing evidence
			}
			if a.Application != nil && a.Principal() != nil && a.Fingerprint == v.Attribution.Fingerprint {
				return ProcessLease{}, nil, mutationError("request_pending", "This request is still pending; use Allow or Deny with For a while")
			}
			// The connection ended: finalize it first (held packets drop).
			_ = e.rejectPendingBindingLocked(v, a)
		}
	}
	if r.Decided {
		return ProcessLease{}, nil, mutationError("request_decided", "This request was already decided")
	}
	if r.Owner == nil {
		return ProcessLease{}, nil, mutationError("process_scope_unavailable", "For a while needs the one verified process that made this request")
	}
	o := *r.Owner
	if err := e.verifyLiveOwnerLocked(r, o); err != nil {
		return ProcessLease{}, nil, err
	}
	l := &processLease{ID: randomID(), Action: action, Direction: r.Filter.Direction, EventID: id, Application: r.Application, UID: o.UID, PID: o.PID, Start: o.Start, BootID: o.BootID, PIDNS: o.PIDNS, MountNS: o.MountNS, Created: now, Until: now.Add(d), Duration: d}
	if err := e.leaseCapacityLocked(l); err != nil {
		return ProcessLease{}, nil, err
	}
	defer e.collectSettledLocked()()
	e.storeLeaseLocked(l)
	r.Decided = true // one lease per ended request; a later choice needs a new request
	e.settlePendingLocked("for a while " + l.ID + " from ended request " + id)
	e.followUpSettleLocked()
	return e.leaseViewLocked(l, e.Now()), e.settledLocked(), nil
}

// verifyLiveOwnerLocked proves the retained owner is the same live process.
func (e *Engine) verifyLiveOwnerLocked(r *retainedRequest, o identity.Process) error {
	inspect := e.inspectProcess
	if inspect == nil {
		inspect = identity.Inspect
	}
	running := e.instanceRunning
	if running == nil {
		running = identity.InstanceRunning
	}
	ended := mutationError("process_ended", fmt.Sprintf("The process has exited (PID %d); For a while has nothing to cover", o.PID))
	cur, err := inspect(o.PID)
	if err != nil {
		if !running(o.PID, o.Start) {
			return ended
		}
		return mutationError("process_scope_unavailable", "The process could not be verified: "+err.Error())
	}
	if cur.Start != o.Start {
		return ended // the PID now belongs to another process instance
	}
	var changed []string
	for _, c := range [][3]string{
		{"uid", fmt.Sprint(o.UID), fmt.Sprint(cur.UID)},
		{"boot_id", o.BootID, cur.BootID},
		{"pidns", o.PIDNS, cur.PIDNS},
		{"mountns", o.MountNS, cur.MountNS},
		{"application_key", r.Application.Key, cur.Application.Key},
		{"application_revision", r.Application.Revision, cur.Application.Revision},
		{"executable", r.Application.Executable, cur.Application.Executable},
	} {
		if c[1] != c[2] && !(c[0] == "pidns" && c[1] == "") && !(c[0] == "mountns" && c[1] == "") {
			changed = append(changed, c[0])
		}
	}
	if len(changed) > 0 {
		return mutationError("process_scope_unavailable", "The process identity changed since the request ("+strings.Join(changed, ", ")+"); For a while is unavailable")
	}
	return nil
}

func (e *Engine) leaseCapacityLocked(l *processLease) error {
	for _, o := range e.processLeases {
		if o.PID == l.PID && o.Start == l.Start && o.Direction == l.Direction {
			return nil // replaces that lease
		}
	}
	if len(e.processLeases) >= maxProcessLeases {
		return mutationError("capacity", "For-a-while lease capacity reached; wait for expiry")
	}
	return nil
}

func (e *Engine) leaseViewLocked(l *processLease, now time.Time) ProcessLease {
	return ProcessLease{ID: l.ID, Action: l.Action, Direction: l.Direction, Application: l.Application.Key, Name: l.Application.Name, Executable: l.Application.Executable, UID: l.UID, PID: l.PID, Start: l.Start, Created: l.Created, Until: l.Until, RemainingMS: l.Until.Sub(now).Milliseconds(), Seconds: l.seconds(), EventID: l.EventID}
}

// endedLeaseSentence is the acknowledgement text for request-for-a-while.
func endedLeaseSentence(l ProcessLease) string {
	act := map[string]string{"allow": "Allow", "block": "Deny"}[l.Action]
	return fmt.Sprintf("For a while: %s for process %d (%s), %s connections only. This ended request was not delivered.", act, l.PID, durationText(time.Duration(l.Seconds)*time.Second), l.Direction)
}
