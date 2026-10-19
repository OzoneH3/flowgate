package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"flowgate/internal/decisionlog"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/udpaccount"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID               string               `json:"id"`
	Flow             identity.Flow        `json:"flow"`
	Attribution      identity.Attribution `json:"attribution"`
	State            string               `json:"state"`
	Reason           string               `json:"reason"`
	Rule             string               `json:"rule"`
	Conflicts        []string             `json:"matching_rules"`
	FirstSeen        time.Time            `json:"first_seen"`
	Deadline         time.Time            `json:"deadline"`
	RememberedFilter *policy.Filter       `json:"remembered_filter,omitempty"`
	ScopePreviews    map[string]string    `json:"scope_previews,omitempty"`
	Permission       string               `json:"permission"`
	// RequestGroup groups equivalent repeated requests (same verified
	// application identity/UID, direction, protocol, remote address and
	// service port) for presentation. Decisions still target one event ID.
	RequestGroup string `json:"request_group,omitempty"`
	// AskRule identifies the stored Ask rule that caused this prompt (absent
	// when no rule matched and the default prompted).
	AskRule *RuleVersionRef `json:"ask_rule,omitempty"`
	Token   string          `json:"-"`

	Revalidation *identity.PendingRevalidation `json:"revalidation,omitempty"`
	// RequestRule reports whether an application rule for future connections
	// can be saved from this request's retained identity (request-rule-*).
	RequestRule *RequestRuleSource `json:"request_rule,omitempty"`

	// Decision-log bookkeeping (never serialized): the rule exactly as evaluated,
	// whether this result was a capacity refusal, and record-once flags so packet
	// retransmissions and repeated handling never produce duplicate records.
	decided       *policy.Rule
	capacity      bool
	pendingLogged bool
	finalLogged   bool
	logAttemptID  string
	logDeadline   time.Time
}
type TrafficManager interface {
	Status() udpaccount.Status
	Start(...string) (udpaccount.Status, error)
	Stop(...string) (udpaccount.Status, error)
}
type Engine struct {
	Essential         *essential.Manager
	essentialPreviews map[string]*essentialPreview
	Build             *BuildIdentity
	Zones             identity.NetworkZones
	ZoneSource        func() identity.NetworkZones
	zonePreviews      map[string]*zonePreview
	zoneMigrations    map[string]*zoneMigration
	decisionPreviews  map[string]*decisionPreview
	processHandles    map[identity.Instance]*identity.ProcessHandle
	// Decisions records decision-time evidence; nil disables recording.
	Decisions      *decisionlog.Log
	capacityLogged map[string]*capacityAggregate

	Protection           ProtectionManager
	ProtectionControlUID *uint32
	Evaluation           EvaluationManager
	EvaluationControlUID *uint32
	Traffic              TrafficManager
	TrafficControlUID    *uint32 // explicit root configuration, independent of rules/decisions

	creationMu       sync.Mutex // serializes bounded preview/replay lifecycle, never packet processing
	creationPreviews map[string]*creationPreview
	verifyObserved   func(string, identity.ActivityProcess) (identity.Process, error) // tests only; production uses identity verifier

	requestRules        map[string]*retainedRequest
	requestRulePreviews map[string]*requestRulePreview
	verifyRetained      func(identity.Application, uint32, string) error // tests only
	instanceRunning     func(int, string) bool                           // tests only

	policyQueryMu      sync.Mutex // serializes metadata health sampling with response ordering
	policyReadSequence uint64     // read-response ordering only, protected by mu
	StopMonitoring     func()     // configured only for non-enforcing root daemon; API requires root peer
	SaveRules          func([]policy.Rule) error
	Enforcement        func() EnforcementStatus
	AdministratorUID   *uint32
	APIUID             *uint32
	Activity           func() identity.ActivitySnapshot
	Generation         string
	Mode               string
	mu                 sync.Mutex
	events             map[string]*Event
	rules              []policy.Rule
	Resolve            func(identity.Flow) identity.Attribution
	Now                func() time.Time
	Timeout            time.Duration
	Max                int
	window             time.Time
	created            int
}

func New(timeout time.Duration) *Engine {
	return &Engine{Zones: identity.DefaultNetworkZones(), Generation: randomID(), events: map[string]*Event{}, Resolve: identity.Resolve, Now: time.Now, Timeout: timeout, Max: 256}
}
func randomID() string {
	var b [16]byte
	_, e := rand.Read(b[:])
	if e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func (e *Engine) expire(now time.Time) {
	e.flushCapacity(now, false)
	for key, v := range e.events {
		if !now.Before(v.Deadline) {
			if v.State == "awaiting-decision" {
				v.State = "expired"
				v.Reason = "decision timed out; retry creates a new request"
				e.recordFinal(v, "block", "timeout", "", "no decision before the deadline; held packets drop", nil, nil, "deferred", "")
			}
			if now.Sub(v.Deadline) > 5*time.Second {
				delete(e.events, key)
			}
		}
	}
}
func (e *Engine) Observe(f identity.Flow, token string) Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshZonesLocked()
	f.NetworkScope = e.Zones.ClassifyFlow(f)
	now := e.Now()
	e.expire(now)
	key := f.Key() + "|" + token
	// Every undecided/new attempt and every UDP datagram rechecks actual ownership.
	a := e.Resolve(f)
	action, rule, conflicts := e.evaluateLocked(e.rules, f, a, now)
	if old := e.events[key]; old != nil && now.Before(old.Deadline) && old.Attribution.Fingerprint == a.Fingerprint && a.Application != nil {
		valid := old.Rule == rule && ((old.State == "allowed" && action == "allow") || (old.State == "blocked" && action == "block") || (old.State == "awaiting-decision" && action == "ask"))
		if strings.HasPrefix(old.Rule, "once:") && action == "ask" {
			valid = true
		}
		if valid {
			return *old
		}
	}

	v := Event{ID: randomID(), Flow: f, Attribution: a, FirstSeen: now, Deadline: now.Add(e.Timeout), Rule: rule, Conflicts: conflicts, Token: token, Permission: "once: this TCP connection or UDP tuple for 30 seconds; exact application and remote endpoint"}
	v.logAttemptID, v.logDeadline = v.ID, v.Deadline
	// Unsafe ownership is deliberately re-evaluated for every packet. Preserve
	// only its logging identity within a fixed lease, never its verdict authority.
	if old := e.events[key]; old != nil && rule == "unsafe-attribution" && old.Rule == rule && old.Attribution.Fingerprint == a.Fingerprint && now.Before(old.logDeadline) {
		v.logAttemptID, v.logDeadline, v.finalLogged = old.logAttemptID, old.logDeadline, old.finalLogged
	}
	v.decided = e.ruleLocked(rule)
	if a.Principal() != nil {
		filter := policy.Remembered(f, a)
		v.RememberedFilter = &filter
		v.RequestGroup = requestGroup(filter)
		service := fmt.Sprintf("local service port %d; any remote source port", filter.LocalPort)
		if f.Direction == "outgoing" {
			service = fmt.Sprintf("remote service port %d; any local source port", filter.RemotePort)
		}
		v.ScopePreviews = map[string]string{
			"once":        fmt.Sprintf("Once: %s %s, local %s, remote %s; this application/revision/user only. TCP: one connection (30 seconds to admit); UDP: fixed 30-second flow lease.", f.Direction, f.Protocol, f.Local, f.Remote),
			"application": fmt.Sprintf("Remember for one hour (memory only): application %s; revision %s; user %d; %s %s; remote address %s; %s. Other local addresses may match. No permission for another application reusing this port.", filter.Application, filter.Revision, filter.UID, filter.Direction, filter.Protocol, filter.RemoteAddress, service),
		}
		if e.SaveRules != nil {
			v.ScopePreviews["application"] = strings.Replace(v.ScopePreviews["application"], "memory only", "saved to disk; absolute expiry survives restart", 1)
			v.ScopePreviews["persistent"] = strings.Replace(v.ScopePreviews["application"], "Remember for one hour (saved to disk; absolute expiry survives restart)", "Persistent until disabled/deleted (saved to disk)", 1)
		}
	}
	switch action {
	case "allow":
		v.State = "allowed"
		v.Reason = "allowed by rule; other firewall chains may still deny delivery"
	case "block":
		v.State = "blocked"
		v.Reason = "blocked by rule or unresolved ownership"
	default:
		v.State = "awaiting-decision"
		v.Reason = "initial packets retained within queue bounds until the decision deadline; excess packets drop"
		if v.decided != nil && v.decided.Action == "ask" {
			v.AskRule = &RuleVersionRef{v.decided.ID, v.decided.Version}
			v.Reason = "stored Ask rule " + v.decided.ID + " requires a decision; " + v.Reason
		}
	}
	if now.Sub(e.window) >= time.Second {
		e.window = now
		e.created = 0
	}
	if len(e.events) >= e.Max || e.created >= 20 {
		v.State = "blocked"
		v.Reason = "pending/history capacity or prompt rate exceeded"
		v.capacity = true
		return v
	}
	e.created++
	e.events[key] = &v
	e.retainRequestLocked(&v, a)
	return v
}
func (e *Engine) List(uid uint32, admin bool) []Event {
	rows, _ := e.ListWithZones(uid, admin)
	return rows
}
func (e *Engine) ListWithZones(uid uint32, admin bool) ([]Event, identity.NetworkZones) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshZonesLocked()
	e.expire(e.Now())
	out := []Event{}
	e.pruneRequestRulesLocked(e.Now())
	for _, v := range e.events {
		if admin || owned(v.Attribution, uid) {
			row := *v
			row.RequestRule = e.requestRuleSourceLocked(v.ID)
			out = append(out, row)
		}
	}
	return out, e.Zones
}
func owned(a identity.Attribution, uid uint32) bool {
	return a.Principal() != nil && a.Principal().UID == uid
}
func (e *Engine) Decide(id, action, scope string, uid uint32, admin bool) (Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.decideLocked(id, action, scope, uid, admin, nil, "", time.Time{})
}

func (e *Engine) decideLocked(id, action, scope string, uid uint32, admin bool, reviewed *policy.Rule, sentence string, reviewDeadline time.Time) (Event, error) {
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	if action != "allow" && action != "block" {
		return Event{}, fmt.Errorf("action must be allow or block")
	}
	if scope != "once" && scope != "application" && !(scope == "persistent" && e.SaveRules != nil) {
		return Event{}, fmt.Errorf("scope must be once or application")
	}
	for _, v := range e.events {
		if v.ID != id {
			continue
		}
		if !admin && !owned(v.Attribution, uid) {
			return Event{}, mutationError("forbidden", "not authorized")
		}
		if v.State != "awaiting-decision" || !now.Before(v.Deadline) {
			return Event{}, mutationError("stale_decision", "stale decision; retry required")
		}
		a := e.Resolve(v.Flow)
		if !e.Now().Before(v.Deadline) {
			return Event{}, e.rejectPendingDeadlineLocked(v)
		}
		if reviewed != nil && !e.Now().Before(reviewDeadline) {
			return Event{}, mutationError("preview_expired", "Preview expired during identity revalidation; review again")
		}
		if a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			return Event{}, e.rejectPendingBindingLocked(v, a)
		}
		if scope != "once" && len(e.rules) >= 256 {
			return Event{}, mutationError("capacity", "rule capacity reached")
		}
		var remembered *policy.Rule
		if scope != "once" {
			r := policy.Rule{Version: 1, Executable: a.Application.Executable, Schema: 2, ID: "user:" + v.ID, Priority: 100, Action: action, Filter: policy.Remembered(v.Flow, a), Created: now, Expires: now.Add(time.Hour)}
			if scope == "persistent" {
				r.Expires = time.Time{}
			}
			if reviewed != nil {
				r = *reviewed
			}
			if other := duplicate(e.rules, r); other != "" {
				return Event{}, fmt.Errorf("duplicate scope exists as %s; edit the existing rule", other)
			}
			next := append(append([]policy.Rule{}, e.rules...), r)
			for i, old := range e.rules {
				if reviewed != nil && old.ID == r.ID {
					if old.Version+1 != r.Version || canonicalFilter(old.Filter) != canonicalFilter(r.Filter) {
						return Event{}, mutationError("policy_conflict", "The remembered rule changed since review; review again")
					}
					next = append([]policy.Rule{}, e.rules...)
					next[i] = r
				}
			}
			if e.SaveRules != nil {
				if err := e.SaveRules(next); err != nil {
					return Event{}, mutationError("persistence_failed", "rule persistence failed: "+err.Error())
				}
			}
			e.rules = next
			remembered = &r
		}
		v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		v.Reason = "explicit client decision; FlowGate permission is not proof of network delivery"
		v.Rule = "once:" + v.ID
		v.Deadline = now.Add(30 * time.Second)
		e.recordFinal(v, action, "user", scope, "explicit user decision", remembered, &uid, "deferred", "")
		if remembered != nil {
			v.Rule = remembered.ID
			v.Permission = v.ScopePreviews[scope]
			if reviewed != nil {
				v.Permission = sentence
			}

			e.settlePendingLocked("remembered decision " + remembered.ID)
			for key, other := range e.events {
				if other.ID == v.ID || other.State == "awaiting-decision" {
					continue
				}
				action, effective, _ := e.evaluateLocked(e.rules, other.Flow, other.Attribution, now)
				// Unrelated rules must not discard a just-approved one-shot packet.
				if strings.HasPrefix(other.Rule, "once:") && action == "ask" {
					continue
				}
				if effective == other.Rule && ((other.State == "allowed" && action == "allow") || (other.State == "blocked" && action == "block")) {
					continue
				}
				delete(e.events, key)
			}
		}
		return *v, nil
	}
	return Event{}, fmt.Errorf("unknown or expired request")
}
func (e *Engine) SetRules(rules []policy.Rule) error {
	if len(rules) > 256 {
		return fmt.Errorf("too many rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule ID")
		}
		seen[r.ID] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	e.pruneHandlesLocked()
	e.resetCachedLocked("policy replaced")
	return nil
}

// RetainedState is used only for already queued packets, never to create prompts.
// Unknown/deleted/expired events drop. An Allow always rechecks the relationship.
func (e *Engine) RetainedState(id, fingerprint string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	for _, v := range e.events {
		if v.ID != id {
			continue
		}
		if !now.Before(v.Deadline) || v.Attribution.Fingerprint != fingerprint {
			return "drop"
		}
		if v.State == "awaiting-decision" {
			return "pending"
		}
		if v.State != "allowed" {
			return "drop"
		}
		a := e.Resolve(v.Flow)
		if !e.Now().Before(v.Deadline) || a.Application == nil || a.Fingerprint != fingerprint {
			v.State = "expired"
			v.Reason = "identity changed before retained verdict"
			if a.Application == nil {
				v.Reason = fmt.Sprintf("attribution unavailable before retained verdict: %s: %s", a.Status, a.Reason)
			} else if a.Fingerprint != fingerprint {
				v.Reason = fmt.Sprintf("identity changed before retained verdict (owners %d to %d, sockets %d to %d)", len(v.Attribution.Owners), len(a.Owners), len(v.Attribution.Sockets), len(a.Sockets))
			} else {
				v.Reason = "decision lease expired before retained verdict"
			}
			v.finalLogged = false // a revised disposition of an earlier Allow
			e.recordFinal(v, "block", "identity_changed", "", v.Reason+"; held packets drop", nil, nil, "deferred", "")
			return "drop"
		}
		// Current configured Block overrides even a cached Once grant. Process tier
		// and liveness are always reconsidered before a retained admission.
		if action, rule, matches := e.evaluateLocked(e.rules, v.Flow, a, e.Now()); action == "block" {
			v.State, v.Rule, v.Reason = "blocked", rule, "Current configured Block superseded retained admission"
			v.Conflicts, v.decided = matches, e.ruleLocked(rule)
			v.finalLogged = false
			e.recordFinal(v, "block", "policy_change", "", v.Reason, v.decided, nil, "deferred", "")
			return "drop"
		}
		// Once grants use the event lease; remembered grants must still be live.
		if !strings.HasPrefix(v.Rule, "once:") {
			act, rule, _ := e.evaluateLocked(e.rules, v.Flow, a, e.Now())
			if act != "allow" || rule != v.Rule {
				return "drop"
			}
		}
		return "allow"
	}
	return "drop"
}

// Rules returns only the authenticated user's policy unless explicitly admin.
func (e *Engine) Rules(uid uint32, admin bool) []policy.Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []policy.Rule{}
	for _, r := range e.rules {
		if admin || r.Filter.AllUIDs || r.Filter.UID == uid {
			out = append(out, r)
		}
	}
	return out
}
func (e *Engine) ChangeRule(id, action string, uid uint32, admin bool) error {
	active := false
	if e.Enforcement != nil {
		active = e.Enforcement().State != "stopped"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.SaveRules == nil {
		return fmt.Errorf("durable rules unavailable")
	}
	next := append([]policy.Rule{}, e.rules...)
	found := false
	for i, r := range next {
		if r.ID != id {
			continue
		}
		if !admin && (r.Filter.AllUIDs || r.Filter.UID != uid) {
			return fmt.Errorf("not authorized")
		}
		if r.Preset != nil && active {
			return mutationError("protection_active", "Stop protection before changing preset permissions")
		}
		found = true
		if action != "delete" && r.Version == ^uint64(0) {
			return fmt.Errorf("rule version exhausted; delete and create a new rule")
		}
		if action != "delete" {
			next[i].Version++
		}
		switch action {
		case "enable":
			if e.targetStateLocked(r).State != "active" {
				return mutationError("target_inactive", "Process target is inactive; create a fresh preview for a live instance")
			}
			next[i].Disabled = false
		case "disable":
			next[i].Disabled = true
		case "delete":
			next = append(next[:i], next[i+1:]...)
		default:
			return fmt.Errorf("action must be enable, disable or delete")
		}
		break
	}
	if !found {
		return fmt.Errorf("unknown rule")
	}
	if err := e.SaveRules(next); err != nil {
		return err
	}
	e.rules = next
	e.pruneHandlesLocked()
	// Cached verdicts are invalidated conservatively; awaiting requests are
	// re-evaluated against the new policy instead of being dropped.
	e.resetCachedLocked("rule " + action)
	return nil
}
