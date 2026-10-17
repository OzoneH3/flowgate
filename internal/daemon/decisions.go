package daemon

import (
	"flowgate/internal/decisionlog"
	"flowgate/internal/policy"
	"strconv"
	"strings"
	"time"
)

// DecisionLogCapability is advertised when a decision log is configured.
const DecisionLogCapability = "decision-log-v1"

// Verdict outcomes reported by the queue for the packet that produced an event.
const (
	VerdictAccepted = "accept_submitted"
	VerdictDropped  = "drop_submitted"
	VerdictFailed   = "submission_failed"
	VerdictHeld     = "held"
)

// ruleLocked copies the rule exactly as currently evaluated (caller holds e.mu).
func (e *Engine) ruleLocked(id string) *policy.Rule {
	for _, r := range e.rules {
		if r.ID == id {
			c := r
			return &c
		}
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// baseRecord captures flow/identity evidence from the event as observed at
// decision time. Unknown values stay absent; direction comes only from the hook.
func (e *Engine) baseRecord(v *Event, kind string) decisionlog.Record {
	r := decisionlog.Record{ID: decisionlog.NewRecordID(), Time: e.Now(), Generation: e.Generation, Mode: e.Mode, Kind: kind, RequestID: v.ID, Delivery: "not_observed"}
	family := "ipv6"
	if v.Flow.Remote.Addr().Is4() {
		family = "ipv4"
	}
	r.Flow = &decisionlog.Flow{Direction: v.Flow.Direction, Protocol: v.Flow.Protocol, Family: family, Local: v.Flow.Local.String(), Remote: v.Flow.Remote.String(), Interface: v.Flow.Interface}
	a := v.Attribution
	r.Attribution = &decisionlog.Attribution{Status: clip(a.Status, 64), Reason: clip(a.Reason, 512)}
	if a.Application != nil {
		r.Application = &decisionlog.Application{Key: a.Application.Key, Name: clip(a.Application.Name, 256), Kind: a.Application.Kind, Executable: clip(a.Application.Executable, 1024), Revision: clip(a.Application.Revision, 256)}
	}
	if p := a.Principal(); p != nil {
		uid := p.UID
		r.PrincipalUID = &uid
	}
	return r
}

// recordFinal records the disposition once per event (caller holds e.mu).
func (e *Engine) recordFinal(v *Event, action, source, scope, reason string, rule *policy.Rule, by *uint32, verdict, detail string) {
	if e.Decisions == nil || v.finalLogged {
		return
	}
	v.finalLogged = true
	r := e.baseRecord(v, decisionlog.KindFinal)
	r.Decision = &decisionlog.Decision{Action: action, Source: source, Scope: scope, Reason: reason, MatchingRules: v.Conflicts}
	if rule != nil {
		r.Decision.Rule = decisionlog.Snapshot(*rule)
	}
	if by != nil {
		uid := *by
		r.Decision.DecidedByUID = &uid
	}
	r.Verdict = &decisionlog.Verdict{State: verdict, Detail: detail}
	if verdict == "deferred" {
		r.Verdict.Detail = "applies to held packets at the next queue flush and to later packets of this flow lease"
	}
	e.Decisions.Record(r)
}

// discardPendingLocked records pending requests that a policy change discards.
func (e *Engine) discardPendingLocked(reason string) {
	for _, v := range e.events {
		if v.State == "awaiting-decision" {
			e.recordFinal(v, "block", "policy_change", "", reason, nil, nil, "deferred", "")
		}
	}
}

// FinalizePending records shutdown for still-pending requests before the
// queue drops their held packets. Call before closing the decision log.
func (e *Engine) FinalizePending() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, v := range e.events {
		if v.State == "awaiting-decision" {
			e.recordFinal(v, "block", "shutdown", "", "daemon stopped before a decision; held packets drop", nil, nil, "deferred", "")
		}
	}
}

// RecordPacketOutcome is called by the queue after it handled the packet that
// Observe evaluated. Only the first packet of an event is recorded; cached
// results for retransmissions or later datagrams of the same lease are not.
func (e *Engine) RecordPacketOutcome(v Event, verdict string, submitErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Decisions == nil {
		return
	}
	detail := ""
	if submitErr != nil {
		detail = clip(submitErr.Error(), 256)
	}
	if v.capacity {
		// Not stored by the engine; collapse repeats per flow for 5 seconds.
		now, key := e.Now(), v.Flow.Key()+"|"+v.Token
		if e.capacityLogged == nil || len(e.capacityLogged) > 256 {
			e.capacityLogged = map[string]time.Time{}
		}
		if at, ok := e.capacityLogged[key]; ok && now.Sub(at) < 5*time.Second {
			return
		}
		e.capacityLogged[key] = now
		c := v
		e.recordFinal(&c, "block", "capacity", "", v.Reason, nil, nil, verdict, detail)
		return
	}
	stored := e.events[v.Flow.Key()+"|"+v.Token]
	target := &v // evicted between Observe and here: record from the copy once
	if stored != nil && stored.ID == v.ID {
		target = stored
	}
	switch v.State {
	case "awaiting-decision":
		if target.pendingLogged {
			return
		}
		target.pendingLogged = true
		r := e.baseRecord(target, decisionlog.KindPending)
		r.Decision = &decisionlog.Decision{Action: "pending", Source: "default_ask", Reason: "no matching rule; awaiting a user decision until the deadline", MatchingRules: v.Conflicts}
		r.Verdict = &decisionlog.Verdict{State: verdict, Detail: detail}
		if verdict == VerdictHeld {
			r.Verdict.Detail = "initial packet held in the kernel queue until a decision or the deadline " + v.Deadline.UTC().Format(time.RFC3339)
		} else if verdict == VerdictDropped {
			r.Verdict.Detail = "retention bound reached; this packet dropped, the request stays pending"
		}
		e.Decisions.Record(r)
	case "allowed", "blocked":
		if target.finalLogged {
			return
		}
		action := map[string]string{"allowed": "allow", "blocked": "block"}[v.State]
		source := "rule"
		if v.Rule == "unsafe-attribution" {
			source = "attribution"
		} else if strings.HasPrefix(v.Rule, "once:") || target.decided == nil {
			return // user/edit dispositions are recorded where they are decided
		}
		// A retransmitted SYN or continuing UDP flow re-evaluated after its cached
		// lease expired yields the same decision: record it once per minute.
		key := v.Flow.Key() + "|" + v.Token + "|" + source + "|" + action
		if target.decided != nil {
			key += "|" + target.decided.ID + "|" + strconv.FormatUint(target.decided.Version, 10)
		}
		now := e.Now()
		if e.recentFinal == nil || len(e.recentFinal) > 1024 {
			e.recentFinal = map[string]time.Time{}
		}
		if at, ok := e.recentFinal[key]; ok && now.Sub(at) < time.Minute {
			target.finalLogged = true
			return
		}
		e.recentFinal[key] = now
		e.recordFinal(target, action, source, "", v.Reason, target.decided, nil, verdict, detail)
	}
}
