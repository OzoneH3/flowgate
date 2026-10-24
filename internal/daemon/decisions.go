package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"flowgate/internal/decisionlog"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
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
	r := decisionlog.Record{Revalidation: v.Revalidation, ID: decisionlog.NewRecordID(), Time: e.Now(), Generation: e.Generation, Mode: e.Mode, Kind: kind, RequestID: v.ID, Delivery: "not_observed"}
	if e.Evaluation != nil {
		r.Mode = "host-enforcement"
		r.EvaluationID = e.Evaluation.Status().ID
	}
	if v.logAttemptID != "" {
		r.RequestID = v.logAttemptID
	}
	family := "ipv6"
	if v.Flow.Remote.Addr().Is4() {
		family = "ipv4"
	}
	r.Flow = &decisionlog.Flow{NetworkScope: v.Flow.NetworkScope, Direction: v.Flow.Direction, Protocol: v.Flow.Protocol, Family: family, Local: v.Flow.Local.String(), Remote: v.Flow.Remote.String(), Interface: v.Flow.Interface}
	a := v.Attribution
	r.Attribution = &decisionlog.Attribution{Status: clip(a.Status, 64), Reason: clip(a.Reason, 512), ReasonCode: clip(a.ReasonCode, 64)}
	if a.Table != nil && len(a.Table.Owners) <= 4 {
		table := *a.Table
		table.Method = clip(table.Method, 512)
		table.Prefix = clip(table.Prefix, 4096)
		table.Owners = append([]identity.WindowsOwner(nil), table.Owners...)
		for i := range table.Owners {
			table.Owners[i].Image = clip(table.Owners[i].Image, 4096)
		}
		r.Attribution.RuntimeTable = &table
	}
	if a.Application != nil {
		r.Application = &decisionlog.Application{Key: a.Application.Key, Prefix: clip(a.Application.Prefix, 4096), Name: clip(a.Application.Name, 256), Kind: a.Application.Kind, Executable: clip(a.Application.Executable, 1024), Revision: clip(a.Application.Revision, 256)}
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
	if rule != nil && rule.NetworkEndpoint {
		scope = "network-endpoint"
	}
	r.Decision = &decisionlog.Decision{Action: action, Source: source, Scope: scope, Reason: reason, MatchingRules: v.Conflicts, LeaseID: v.leaseID}
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

// requestGroup is a presentation key for an application/direction/protocol burst.
// Destinations remain separate events: grouping never widens decision authority.
func requestGroup(f policy.Filter) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s", f.Application, f.Revision, f.UID, f.Direction, f.Protocol)))
	return hex.EncodeToString(h[:16])
}

// settlePendingLocked re-evaluates every awaiting request after a policy change
// through the normal identity and policy path (NetLimiter: a remembered or
// newly set rule applies to the following connections). Covered requests are
// finalized by that rule and leave the queue; uncovered ones keep waiting with
// their own deadline. Nothing is approved without a matching rule, and a Once
// decision never reaches here.
func (e *Engine) settlePendingLocked(reason string) {
	if e.prefetched == nil {
		e.requestSettleLocked(reason) // resolved after e.mu is released
		return
	}
	now := e.Now()
	for _, v := range e.events {
		if v.State != "awaiting-decision" || !now.Before(v.Deadline) {
			continue
		}
		a, ok := e.resolvedEventLocked(v)
		if !ok {
			if !e.settling {
				e.requestSettleLocked(reason) // not selected by this operation; settled afterwards
			}
			continue
		}
		if a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			// The attempt ended (socket gone) or its identity changed: it can no
			// longer be decided, so it must not linger as an actionable prompt.
			// Same disposition as the decision path; nothing is approved.
			_ = e.rejectPendingBindingLocked(v, a)
			e.noteSettledLocked(v)
			continue
		}
		action, rule, matches, lease := e.policyLocked(v.Flow, a, now)
		if action != "allow" && action != "block" {
			continue
		}
		v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		v.Rule, v.Conflicts, v.decided = rule, matches, e.ruleLocked(rule)
		v.Reason = "re-evaluated after policy change (" + reason + ")"
		source, scope := "rule", ""
		if lease != nil {
			v.Reason += "; " + lease.reason()
			v.leaseID = lease.ID
			source, scope = ForAWhileSource, ForAWhileScope
		}
		e.recordFinal(v, action, source, scope, v.Reason, v.decided, nil, "deferred", "")
		e.markRetainedDecidedLocked(v.ID)
		e.noteSettledLocked(v)
	}
}

// resetCachedLocked replaces the old discard-everything behaviour: cached
// verdicts are dropped conservatively, awaiting requests are re-evaluated and
// kept (decided or still waiting) so the queue never shows obsolete prompts.
// Explicit Once / For-a-while flow admissions (rule once:/while:) are kept too:
// they are not cached rule verdicts, Observe still lets any configured
// Allow/Block decide the flow first, and dropping them made a retransmitted
// SYN or a later datagram of an already answered flow prompt again.
//
// Settling awaiting requests is requested here and runs after e.mu is released
// (see requestSettleLocked); they keep waiting meanwhile and nothing is admitted.
func (e *Engine) resetCachedLocked(reason string) {
	e.settlePendingLocked(reason)
	e.dropCachedLocked()
}

// dropCachedLocked discards cached rule verdicts; awaiting requests and explicit
// Once / For-a-while flow admissions are kept.
func (e *Engine) dropCachedLocked() {
	settled := map[string]*Event{}
	for key, v := range e.events {
		if v.State == "awaiting-decision" || strings.HasPrefix(v.Reason, "re-evaluated after policy change") ||
			((v.State == "allowed" || v.State == "blocked") && (strings.HasPrefix(v.Rule, "once:") || strings.HasPrefix(v.Rule, leaseRulePrefix))) {
			settled[key] = v
		}
	}
	e.events = settled
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
	e.flushCapacity(e.Now(), true)
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
		// Capacity refusals have no admitted event identity. Count observations,
		// explicitly not unique connections, in bounded five-second buckets.
		now := e.Now()
		e.flushCapacity(now, false)
		key := v.Flow.Key() + "|" + v.Token + "|" + v.Attribution.Fingerprint + "|" + verdict + "|" + detail
		if e.capacityLogged == nil {
			e.capacityLogged = map[string]*capacityAggregate{}
		}
		if e.capacityLogged[key] == nil {
			if len(e.capacityLogged) >= 256 {
				var oldest string
				for k, b := range e.capacityLogged {
					if oldest == "" || b.first.Before(e.capacityLogged[oldest].first) {
						oldest = k
					}
				}
				e.emitCapacity(oldest)
			}
			e.capacityLogged[key] = &capacityAggregate{event: v, first: now, verdict: verdict, detail: detail}
		}
		bucket := e.capacityLogged[key]
		bucket.count++
		bucket.last = now
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
		if target.decided != nil && target.decided.Action == "ask" {
			r.Decision.Source = "rule_ask"
			r.Decision.Reason = "stored Ask rule " + target.decided.ID + " requires a decision; awaiting it until the deadline"
			r.Decision.Rule = decisionlog.Snapshot(*target.decided)
		}
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
		source, scope := "rule", ""
		if v.Rule == "unsafe-attribution" {
			source = "attribution"
		} else if leaseIDOf(v.Rule) != "" {
			source, scope = ForAWhileSource, ForAWhileScope
		} else if strings.HasPrefix(v.Rule, "once:") || target.decided == nil {
			return // user/edit dispositions are recorded where they are decided
		}

		e.recordFinal(target, action, source, scope, v.Reason, target.decided, nil, verdict, detail)
	}
}

// Aggregates are volatile until flushed by engine maintenance or clean shutdown.
// Expiry is a bucket boundary, not a durability deadline.
type capacityAggregate struct {
	event           Event
	first, last     time.Time
	count           uint64
	verdict, detail string
}

func (e *Engine) flushCapacity(now time.Time, all bool) {
	for key, b := range e.capacityLogged {
		if all || now.Sub(b.first) >= 5*time.Second {
			e.emitCapacity(key)
		}
	}
}
func (e *Engine) emitCapacity(key string) {
	b := e.capacityLogged[key]
	delete(e.capacityLogged, key)
	r := e.baseRecord(&b.event, decisionlog.KindFinal)
	r.RequestID = "" // a bucket is not an individual admitted attempt
	r.Time = b.last
	r.Aggregation = &decisionlog.Aggregation{Observations: b.count, First: b.first, Last: b.last, WindowMS: 5000}
	r.Decision = &decisionlog.Decision{Action: "block", Source: "capacity", Reason: fmt.Sprintf("%s; aggregated %d capacity-refused initiation observations (not unique connections; retransmissions/datagrams may repeat)", b.event.Reason, b.count)}
	r.Verdict = &decisionlog.Verdict{State: b.verdict, Detail: b.detail}
	e.Decisions.Record(r)
}
