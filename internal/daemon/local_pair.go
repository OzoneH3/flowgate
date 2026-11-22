package daemon

import (
	"flowgate/internal/identity"
	"fmt"
	"time"
)

// LocalPairCapability: events of same-host connections carry `local_peer`
// (the other endpoint identified from the exact reversed tuple), the two
// requests of one connection (client outgoing + server incoming) reference
// each other through local_peer.correlated_event_id, and `decide-pair`
// answers both sides of a verified pair atomically.
const LocalPairCapability = "local-pair-v1"

// pairAdmission answers the incoming side of a verified local pair that was
// decided from the client's outgoing request before the incoming SYN/datagram
// existed. It matches only that exact connection: reversed tuple, same TCP
// SYN sequence token (UDP: same tuple), same network namespace, the server
// attribution fingerprint verified at decision time and the same client
// socket cookie. A configured rule or lease still decides first.
type pairAdmission struct {
	Action            string
	OutgoingID        string
	ServerFingerprint string
	ClientCookie      string
	Until             time.Time
	By                uint32
}

type pairHit struct {
	Action string
	adm    *pairAdmission
}

// PairAdmissionView reports the prepared answer for the incoming side.
type PairAdmissionView struct {
	Action  string                   `json:"action"`
	Until   time.Time                `json:"until"`
	Local   string                   `json:"local"`
	Remote  string                   `json:"remote"`
	Server  *identity.LocalPeerOwner `json:"server,omitempty"`
	Outcome string                   `json:"outcome"` // pair | rule
	// A configured rule or For a while lease decides the incoming side instead.
	ConfiguredAction string `json:"configured_action,omitempty"`
	ConfiguredRule   string `json:"configured_rule,omitempty"`
	Sentence         string `json:"sentence"`
}

// PairDecision is the decide-pair result: both sides, never only one.
type PairDecision struct {
	Events            []Event            `json:"events"`
	IncomingAdmission *PairAdmissionView `json:"incoming_admission,omitempty"`
	Sentence          string             `json:"sentence"`
}

func pairKey(f identity.Flow, token string) string { return f.Key() + "|" + token }

// exactPair confirms that out (client outgoing) and in (server incoming) are
// the two requests of ONE connection: exact reversed tuple in the same network
// namespace, the same TCP SYN token (UDP: tuple), and the incoming request's
// verified client socket is the very socket (cookie) the outgoing request was
// attributed to, held by the same process instance.
func exactPair(out, in *Event) (bool, string) {
	switch {
	case out == nil || in == nil:
		return false, "both requests are required"
	case out.Flow.Direction != "outgoing" || in.Flow.Direction != "incoming":
		return false, "a pair is one outgoing and one incoming request"
	case out.Flow.NetNS != in.Flow.NetNS || out.Flow.Protocol != in.Flow.Protocol:
		return false, "different network namespace or protocol"
	case out.Flow.Local != in.Flow.Remote || out.Flow.Remote != in.Flow.Local:
		return false, fmt.Sprintf("tuples differ (%s -> %s vs %s <- %s)", out.Flow.Local, out.Flow.Remote, in.Flow.Local, in.Flow.Remote)
	case out.Token != in.Token:
		return false, "different connection attempt (TCP SYN sequence differs)"
	case in.LocalPeer == nil || in.LocalPeer.State != "verified" || in.LocalPeer.Socket == nil || in.LocalPeer.Socket.Kind != "client" || in.LocalPeer.Owner == nil:
		return false, "the incoming request's local client is not verified"
	}
	cookie := false
	for _, s := range out.Attribution.Sockets {
		if s.Cookie == in.LocalPeer.Socket.Cookie && s.Inode == in.LocalPeer.Socket.Inode {
			cookie = true
		}
	}
	if !cookie {
		return false, "the client socket differs from the outgoing request's socket"
	}
	o := in.LocalPeer.Owner
	for _, p := range out.Attribution.Owners {
		if p.PID == o.PID && p.Start == o.Start {
			return true, ""
		}
	}
	return false, "the client process differs from the outgoing request's process"
}

// observeLocalPairLocked sets v.LocalPeer, links the counterpart request of the
// same connection and returns a pair admission hit for an incoming side that
// no configured rule decides (caller holds e.mu).
func (e *Engine) observeLocalPairLocked(v *Event, a identity.Attribution, action string, now time.Time) *pairHit {
	if e.LocalPeer == nil {
		return nil
	}
	peer := e.LocalPeer(v.Flow)
	if peer == nil {
		return nil
	}
	v.LocalPeer = peer
	if other := e.events[pairKey(identity.ReversedFlow(v.Flow), v.Token)]; other != nil && now.Before(other.Deadline) {
		out, in := other, v
		if v.Flow.Direction == "outgoing" {
			out, in = v, other
		}
		if ok, _ := exactPair(out, in); ok {
			link := func(x *Event, id string) {
				cp := identity.LocalPeer{}
				if x.LocalPeer != nil {
					cp = *x.LocalPeer
				}
				cp.CorrelatedEventID = id
				x.LocalPeer = &cp
			}
			link(out, in.ID)
			link(in, out.ID)
		}
	}
	if v.Flow.Direction != "incoming" || action != "ask" {
		return nil
	}
	adm := e.pairAdmissions[pairKey(v.Flow, v.Token)]
	if adm == nil || !now.Before(adm.Until) || a.Application == nil || a.Fingerprint != adm.ServerFingerprint {
		return nil
	}
	if v.LocalPeer.State != "verified" || v.LocalPeer.Socket == nil || v.LocalPeer.Socket.Cookie != adm.ClientCookie {
		return nil
	}
	v.Rule = "once:" + v.ID
	return &pairHit{Action: adm.Action, adm: adm}
}

// admitPairLocked finalizes an incoming request answered by a pair admission.
func (e *Engine) admitPairLocked(v *Event, hit *pairHit, now time.Time) {
	v.Reason = fmt.Sprintf("explicit client decision for the verified local pair (outgoing request %s, same connection); FlowGate permission is not proof of network delivery", hit.adm.OutgoingID)
	v.Deadline = now.Add(30 * time.Second)
	v.logAttemptID, v.logDeadline = v.ID, v.Deadline
	by := hit.adm.By
	e.recordFinal(v, hit.Action, "user", "once", "explicit user decision for the verified local pair with outgoing request "+hit.adm.OutgoingID, nil, &by, "deferred", "")
}

func (e *Engine) pruneAdmissionsLocked(now time.Time) {
	for k, a := range e.pairAdmissions {
		if !now.Before(a.Until) {
			delete(e.pairAdmissions, k)
		}
	}
}

// DecidePair answers both requests of a verified local pair atomically: every
// check (pair, authorization, deadlines, identity bindings, leases) passes
// before anything changes. ids lists the client's outgoing request and, when
// it exists, the server's incoming request. When the incoming side has not
// been requested yet (its packet is held behind the outgoing decision), only
// Once is accepted and the exact connection's incoming side is prepared.
func (e *Engine) DecidePair(generation string, ids []string, action, scope string, seconds int64, uid uint32, admin bool) (PairDecision, []SettledRequest, error) {
	e.lockResolved(e.pairSelection(ids, uid, admin))
	defer e.unlockResolved()
	defer e.collectSettledLocked()()
	if generation == "" || generation != e.Generation {
		return PairDecision{}, nil, mutationError("generation_conflict", "Backend changed; reload")
	}
	if action != "allow" && action != "block" {
		return PairDecision{}, nil, mutationError("invalid_request", "action must be allow or block")
	}
	if scope != "once" && scope != ForAWhileScope {
		return PairDecision{}, nil, mutationError("invalid_request", "a pair decision is Once or For a while; Remember each side separately")
	}
	if seconds != 0 && scope != ForAWhileScope {
		return PairDecision{}, nil, mutationError("invalid_request", "duration_seconds applies to For a while only")
	}
	d, err := forAWhileDuration(seconds)
	if err != nil {
		return PairDecision{}, nil, err
	}
	if len(ids) < 1 || len(ids) > 2 || (len(ids) == 2 && ids[0] == ids[1]) {
		return PairDecision{}, nil, mutationError("invalid_request", "event_ids must name the outgoing request and, when present, its incoming counterpart")
	}
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	e.pruneAdmissionsLocked(now)
	var out, in *Event
	for _, id := range ids {
		var found *Event
		for _, v := range e.events {
			if v.ID == id {
				found = v
			}
		}
		if found == nil {
			return PairDecision{}, nil, mutationError("stale_decision", "unknown or expired request "+id)
		}
		if found.Flow.Direction == "outgoing" && out == nil {
			out = found
		} else if found.Flow.Direction == "incoming" && in == nil {
			in = found
		} else {
			return PairDecision{}, nil, mutationError("not_a_pair", "a pair is one outgoing and one incoming request")
		}
	}
	if out == nil {
		return PairDecision{}, nil, mutationError("not_a_pair", "a pair decision starts from the client's outgoing request; decide this request alone")
	}
	sides := []*Event{out}
	if in != nil {
		sides = append(sides, in)
	}
	for _, v := range sides {
		if !admin && !owned(v.Attribution, uid) {
			return PairDecision{}, nil, mutationError("forbidden", "not authorized for request "+v.ID)
		}
	}
	inFlow := identity.ReversedFlow(out.Flow)
	inFlow.NetworkScope = e.Zones.ClassifyFlow(inFlow)
	counterpart := e.events[pairKey(inFlow, out.Token)]
	if counterpart != nil && !now.Before(counterpart.Deadline) {
		counterpart = nil
	}
	if in == nil && counterpart != nil {
		return PairDecision{}, nil, mutationError("pair_changed", "The server's incoming request "+counterpart.ID+" exists now; review both sides again")
	}
	if in != nil {
		if counterpart != in {
			return PairDecision{}, nil, mutationError("not_a_pair", "these requests are not the two sides of one connection")
		}
		if ok, why := exactPair(out, in); !ok {
			return PairDecision{}, nil, mutationError("not_a_pair", "not a verified local pair: "+why)
		}
		if out.LocalPeer == nil || out.LocalPeer.CorrelatedEventID != in.ID || in.LocalPeer.CorrelatedEventID != out.ID {
			return PairDecision{}, nil, mutationError("not_a_pair", "the requests do not reference each other")
		}
	}
	var pending []*Event
	for _, v := range sides {
		if v.State == "awaiting-decision" && now.Before(v.Deadline) {
			pending = append(pending, v)
		}
	}
	if len(pending) == 0 {
		return PairDecision{}, nil, mutationError("stale_decision", "both sides are already decided or ended")
	}
	if in == nil {
		if len(pending) != 1 {
			return PairDecision{}, nil, mutationError("stale_decision", "the outgoing request is already decided; the incoming side is decided when it is requested")
		}
		if scope != "once" {
			return PairDecision{}, nil, mutationError("pair_scope_unavailable", "The server's incoming request does not exist yet; only Once can answer both sides of this connection")
		}
		if out.LocalPeer == nil || out.LocalPeer.State != "verified" || out.LocalPeer.Role != "server" || out.LocalPeer.Owner == nil {
			return PairDecision{}, nil, mutationError("not_a_pair", "the local server receiving this connection is not verified")
		}
	}
	// Validation: identity bindings and leases, before any mutation.
	attrs := map[*Event]identity.Attribution{}
	for _, v := range pending {
		a, ok := e.resolvedEventLocked(v)
		if !ok {
			return PairDecision{}, nil, retryChangedRequest()
		}
		if !e.Now().Before(v.Deadline) {
			return PairDecision{}, nil, e.rejectPendingDeadlineLocked(v)
		}
		if a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			return PairDecision{}, nil, e.rejectPendingBindingLocked(v, a)
		}
		attrs[v] = a
	}
	leases := map[*Event]*processLease{}
	if scope == ForAWhileScope {
		for _, v := range pending {
			l, err := e.newLeaseLocked(v, attrs[v], action, now, d)
			if err != nil {
				return PairDecision{}, nil, err
			}
			leases[v] = l
		}
		added := 0
		for _, l := range leases {
			replaces := false
			for _, o := range e.processLeases {
				replaces = replaces || (o.PID == l.PID && o.Start == l.Start && o.Direction == l.Direction)
			}
			if !replaces {
				added++
			}
		}
		if len(e.processLeases)+added > maxProcessLeases {
			return PairDecision{}, nil, mutationError("capacity", "For-a-while lease capacity reached; wait for expiry")
		}
	}
	if in == nil && len(e.pairAdmissions) >= 256 {
		return PairDecision{}, nil, mutationError("capacity", "pair admission capacity reached")
	}
	var adm *pairAdmission
	var view *PairAdmissionView
	if in == nil {
		sa, ok := e.resolvedFlowLocked(inFlow)
		if !ok {
			return PairDecision{}, nil, retryChangedRequest()
		}
		p := sa.Principal()
		owner := out.LocalPeer.Owner
		if sa.Application == nil || p == nil || len(sa.Owners) != 1 || sa.Owners[0].PID != owner.PID || sa.Owners[0].Start != owner.Start {
			return PairDecision{}, nil, mutationError("not_a_pair", "the local server changed since this request was observed; review again")
		}
		if !admin && p.UID != uid {
			return PairDecision{}, nil, mutationError("forbidden", "the server side belongs to another principal; decide the outgoing request alone")
		}
		if len(out.Attribution.Sockets) != 1 {
			return PairDecision{}, nil, mutationError("not_a_pair", "the client socket is not unique")
		}
		adm = &pairAdmission{Action: action, OutgoingID: out.ID, ServerFingerprint: sa.Fingerprint, ClientCookie: out.Attribution.Sockets[0].Cookie, Until: now.Add(30 * time.Second), By: uid}
		view = &PairAdmissionView{Action: action, Until: adm.Until, Local: inFlow.Local.String(), Remote: inFlow.Remote.String(), Server: owner, Outcome: "pair"}
		act, rule, _ := e.evaluateLocked(e.rules, inFlow, sa, now)
		act, rule, _ = e.leaseOverlayLocked(act, rule, inFlow, sa, now)
		verb := map[string]string{"allow": "Allowed", "block": "Denied"}
		if act == "allow" || act == "block" {
			view.Outcome, view.ConfiguredAction, view.ConfiguredRule = "rule", act, rule
			view.Sentence = fmt.Sprintf("Incoming to %s: %s by %s, not by this decision", sa.Application.Name, map[string]string{"allow": "allowed", "block": "denied"}[act], rule)
		} else {
			view.Sentence = fmt.Sprintf("Incoming to %s on %s: %s once for this connection when it arrives", sa.Application.Name, inFlow.Local, verb[action])
		}
	}
	// Mutation: both sides together.
	for _, v := range pending {
		partner := out.ID
		if v == out {
			partner = inFlow.Local.String()
			if in != nil {
				partner = in.ID
			}
		}
		v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		v.Reason = "explicit client decision for the verified local pair (with " + partner + "); FlowGate permission is not proof of network delivery"
		v.Rule = "once:" + v.ID
		v.Deadline = now.Add(30 * time.Second)
		reason := "explicit user decision for the verified local pair"
		if l := leases[v]; l != nil {
			e.storeLeaseLocked(l)
			v.Lease = l.ref()
			v.leaseID = l.ID
			if p, err := leaseOwner(attrs[v]); err == nil {
				v.Permission = forAWhilePreview(v.Flow, p, d)
			}
			reason += "; " + l.reason()
		}
		e.recordFinal(v, action, "user", scope, reason, nil, &uid, "deferred", "")
		e.markRetainedDecidedLocked(v.ID)
	}
	if adm != nil {
		if e.pairAdmissions == nil {
			e.pairAdmissions = map[string]*pairAdmission{}
		}
		e.pairAdmissions[pairKey(inFlow, out.Token)] = adm
	}
	if len(leases) > 0 {
		e.settlePendingLocked("for a while (local pair)")
	}
	result := PairDecision{IncomingAdmission: view}
	for _, v := range sides {
		row := *v
		row.RequestRule = e.requestRuleSourceLocked(v.ID)
		result.Events = append(result.Events, row)
	}
	verb := map[string]string{"allow": "Allowed", "block": "Denied"}[action]
	result.Sentence = fmt.Sprintf("%s both sides of the local connection %s -> %s", verb, out.Flow.Local, out.Flow.Remote)
	if view != nil && view.Outcome == "rule" && view.ConfiguredAction != action {
		result.Sentence += "; the incoming side is " + map[string]string{"allow": "allowed", "block": "denied"}[view.ConfiguredAction] + " by " + view.ConfiguredRule
	}
	e.followUpSettleLocked()
	return result, e.settledLocked(), nil
}
