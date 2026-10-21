package daemon

import (
	"time"

	"flowgate/internal/identity"
)

// Ownership resolution can take hundreds of milliseconds (process scans, Wine
// runtime censuses). Interaction operations therefore resolve the requests they
// will examine before taking e.mu, then run their unchanged locked logic with
// those results. Every freshness, deadline and binding check still runs on the
// prefetched attribution.
//
// Only requests the caller may act on are resolved: selection validates the
// target first, so a missing, foreign or ended request costs no census. Results
// are bound to the exact request ID and expire after prefetchMaxAge. A request
// without a usable result is never resolved under e.mu, never ended and never
// allowed because of it: the clicked request answers "retry", other awaiting
// requests are re-settled by a later operation.
const prefetchMaxAge = 2 * time.Second

type prefetchedAttribution struct {
	a  identity.Attribution
	at time.Time
}
type prefetchSet struct {
	events map[string]prefetchedAttribution // by request ID
	flows  map[string]prefetchedAttribution // by flow key, for flows that are not requests
}

// lockResolved selects requests and extra flows under e.mu, resolves them
// without it in the given order (put the decision target last so its evidence
// is freshest), then takes e.mu for the caller's operation. Pair with
// defer e.unlockResolved().
func (e *Engine) lockResolved(selectRequests func() ([]*Event, []identity.Flow)) {
	type job struct {
		id   string
		flow identity.Flow
	}
	e.mu.Lock()
	events, flows := selectRequests()
	var jobs []job
	for _, f := range flows {
		jobs = append(jobs, job{flow: f})
	}
	for _, v := range events {
		jobs = append(jobs, job{id: v.ID, flow: v.Flow})
	}
	e.mu.Unlock()
	set := prefetchSet{events: map[string]prefetchedAttribution{}, flows: map[string]prefetchedAttribution{}}
	for _, j := range jobs {
		r := prefetchedAttribution{a: e.Resolve(j.flow), at: e.Now()}
		if j.id != "" {
			set.events[j.id] = r
		} else {
			set.flows[j.flow.Key()] = r
		}
	}
	e.mu.Lock()
	e.prefetched = &set
}

func (e *Engine) fresh(r prefetchedAttribution, ok bool) (identity.Attribution, bool) {
	if !ok || e.Now().Sub(r.at) > prefetchMaxAge {
		return identity.Attribution{}, false
	}
	return r.a, true
}

// resolvedEventLocked returns this operation's attribution for request v, or
// false when none was resolved for exactly this request or it has aged out.
func (e *Engine) resolvedEventLocked(v *Event) (identity.Attribution, bool) {
	if e.prefetched == nil {
		return identity.Attribution{}, false
	}
	r, ok := e.prefetched.events[v.ID]
	return e.fresh(r, ok)
}

// resolvedFlowLocked is resolvedEventLocked for a flow that is not a request.
func (e *Engine) resolvedFlowLocked(f identity.Flow) (identity.Attribution, bool) {
	if e.prefetched == nil {
		return identity.Attribution{}, false
	}
	r, ok := e.prefetched.flows[f.Key()]
	return e.fresh(r, ok)
}

func retryChangedRequest() error {
	return mutationError("stale_decision", "Request identity could not be checked in time; retry")
}

// actionableLocked reports whether the caller may act on request v now.
func (e *Engine) actionableLocked(v *Event, uid uint32, admin bool) bool {
	return (admin || owned(v.Attribution, uid)) && v.State == "awaiting-decision" && e.Now().Before(v.Deadline)
}

// pendingLocked lists every live awaiting request, which a settling operation re-evaluates.
func (e *Engine) pendingLocked() []*Event {
	now := e.Now()
	var out []*Event
	for _, v := range e.events {
		if v.State == "awaiting-decision" && now.Before(v.Deadline) {
			out = append(out, v)
		}
	}
	return out
}

// requestSelection selects request id when the caller may act on it, preceded
// by every other awaiting request when the operation can settle them. Nothing is
// selected for a missing, foreign or ended request.
func (e *Engine) requestSelection(id string, uid uint32, admin, settles bool) func() ([]*Event, []identity.Flow) {
	return func() ([]*Event, []identity.Flow) {
		var target *Event
		for _, v := range e.events {
			if v.ID == id {
				target = v
			}
		}
		if target == nil || !e.actionableLocked(target, uid, admin) {
			return nil, nil
		}
		var events []*Event
		if settles {
			for _, v := range e.pendingLocked() {
				if v != target {
					events = append(events, v)
				}
			}
		}
		return append(events, target), nil
	}
}

// pairSelection selects the requested pair requests, their reversed server-side
// flows and, because a pair For-a-while can settle them, other awaiting requests.
func (e *Engine) pairSelection(ids []string, uid uint32, admin bool) func() ([]*Event, []identity.Flow) {
	return func() ([]*Event, []identity.Flow) {
		wanted := map[string]bool{}
		for _, id := range ids {
			wanted[id] = true
		}
		// Sides the caller cannot act on (decided, ended, foreign) are not
		// resolved; the locked validation reports them as before.
		var targets []*Event
		for _, v := range e.events {
			if wanted[v.ID] && e.actionableLocked(v, uid, admin) {
				targets = append(targets, v)
			}
		}
		if len(targets) == 0 {
			return nil, nil
		}
		var events []*Event
		var flows []identity.Flow
		for _, v := range e.pendingLocked() {
			if !wanted[v.ID] {
				events = append(events, v)
			}
		}
		for _, v := range targets {
			flows = append(flows, identity.ReversedFlow(v.Flow))
		}
		return append(events, targets...), flows
	}
}

// Settling awaiting requests after a policy or network-zone change needs their
// ownership. An operation holding e.mu only records the request
// (requestSettleLocked); the settle runs after e.mu is released, with ownership
// resolved outside the lock: synchronously at the end of an API operation
// (unlockAndSettle), or in the background when the change was noticed elsewhere
// (packet path, list snapshot). Awaiting requests keep waiting meanwhile.
// Requests created after the change were already evaluated under it.

func (e *Engine) requestSettleLocked(reason string) {
	if e.settleReason == "" {
		e.settleReason = reason
	}
}

func (e *Engine) unlockResolved() {
	e.prefetched = nil
	e.unlockAndSettle()
}

// unlockAndSettle releases e.mu, then runs any settle the operation requested.
func (e *Engine) unlockAndSettle() {
	reason := e.settleReason
	e.settleReason = ""
	e.mu.Unlock()
	if reason != "" {
		e.settleNow(reason)
	}
}

// followUpSettleLocked runs, inside the current operation, any settle the
// operation requested, so its acknowledgement and any cached receipt list every
// request it settled. e.mu is released while the awaiting requests' ownership
// is resolved. The operation's settled collector is detached for that window
// (no other operation can write into or read it) and reinstalled afterwards.
func (e *Engine) followUpSettleLocked() {
	reason := e.settleReason
	if reason == "" {
		return
	}
	e.settleReason = ""
	sink := e.settledSink
	e.settledSink, e.prefetched = nil, nil
	e.mu.Unlock()
	e.lockResolved(func() ([]*Event, []identity.Flow) { return e.pendingLocked(), nil })
	e.settledSink = sink
	e.settling = true
	e.settlePendingLocked(reason)
	e.settling = false
	e.prefetched = nil
}

// receiptWait bounds how long a replay waits for the committing call to finish
// its settlement receipt.
var receiptWait = 30 * time.Second

// awaitUnlocked waits for ch with e.mu released, detaching the operation's
// settled collector meanwhile, and reports false if receiptWait elapsed.
func (e *Engine) awaitUnlocked(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
	}
	sink := e.settledSink
	e.settledSink, e.prefetched = nil, nil
	e.mu.Unlock()
	done := true
	select {
	case <-ch:
	case <-time.After(receiptWait):
		done = false
	}
	e.mu.Lock()
	e.settledSink = sink
	return done
}

func (e *Engine) settleNow(reason string) {
	e.lockResolved(func() ([]*Event, []identity.Flow) { return e.pendingLocked(), nil })
	// Not part of any operation's acknowledgement: never write another one's collector.
	sink := e.settledSink
	e.settledSink = nil
	e.settling = true
	e.settlePendingLocked(reason)
	e.settling = false
	e.settledSink = sink
	// Requests skipped here aged out during resolution; they keep waiting.
	e.prefetched, e.settleReason = nil, ""
	e.mu.Unlock()
}

// settleLaterLocked runs a requested settle in the background for callers that
// cannot follow up themselves. Concurrent requests coalesce.
func (e *Engine) settleLaterLocked() {
	if e.settleScheduled {
		return
	}
	e.settleScheduled = true
	go func() {
		e.mu.Lock()
		e.settleScheduled = false
		reason := e.settleReason
		e.settleReason = ""
		e.mu.Unlock()
		if reason != "" {
			e.settleNow(reason)
		}
	}()
}

// settleIdle reports whether no deferred settle is queued (tests).
func (e *Engine) settleIdle() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.settleScheduled
}
