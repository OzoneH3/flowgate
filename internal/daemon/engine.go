package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"flowgate/internal/accounting"
	"flowgate/internal/decisionlog"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/queuehealth"
	"flowgate/internal/readiness"
	diagnostics "flowgate/internal/serveprofile"
	"flowgate/internal/udpaccount"
	"flowgate/internal/uploadshape"
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
	// RequestGroup groups destination bursts (same verified application
	// identity/UID, direction and protocol) for presentation only.
	// Decisions still target one event ID, never every group member.
	RequestGroup string `json:"request_group,omitempty"`
	// AskRule identifies the stored Ask rule that caused this prompt (absent
	// when no rule matched and the default prompted).
	AskRule *RuleVersionRef `json:"ask_rule,omitempty"`
	Token   string          `json:"-"`

	Revalidation *identity.PendingRevalidation `json:"revalidation,omitempty"`
	// RequestRule reports whether an application rule for future connections
	// can be saved from this request's retained identity (request-rule-*).
	RequestRule *RequestRuleSource `json:"request_rule,omitempty"`
	// Lease is set on the request decided For a while (decision-for-a-while-v1).
	Lease *LeaseRef `json:"lease,omitempty"`
	// PreviousRevisionRules lists enabled stored rules of the same application
	// key, user and direction that are bound to a DIFFERENT revision (for
	// example the executable was updated). Display only: never applied.
	PreviousRevisionRules []RevisionRuleRef `json:"previous_revision_rules,omitempty"`
	// LocalPeer identifies the other endpoint of a same-host connection from
	// the exact reversed tuple (local-pair-v1). Display/pairing only.
	LocalPeer *identity.LocalPeer `json:"local_peer,omitempty"`

	// Decision-log bookkeeping (never serialized): the rule exactly as evaluated,
	// whether this result was a capacity refusal, and record-once flags so packet
	// retransmissions and repeated handling never produce duplicate records.
	decided       *policy.Rule
	capacity      bool
	historyOnly   bool // immediate policy outcome; no held decision or Once lease depends on it
	pendingLogged bool
	finalLogged   bool
	logAttemptID  string
	logDeadline   time.Time
	leaseID       string
}
type TrafficManager interface {
	Status() udpaccount.Status
	Start(...string) (udpaccount.Status, error)
	Stop(...string) (udpaccount.Status, error)
}
type Engine struct {
	socketAuthorization    *socketAuthorization // guarded by mu
	zonePublisherInstalled bool
	QueueHealth            queuehealth.Registry
	// RuntimeChecks returns a cached read-only capability snapshot, independently of enforcement.
	RuntimeChecks     func() []readiness.Check
	Essential         *essential.Manager
	essentialPreviews map[string]*essentialPreview
	Build             *BuildIdentity
	Zones             identity.NetworkZones
	ZoneSource        func() identity.NetworkZones
	endpointPreviews  map[string]*endpointPreview
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
	processLeases       map[string]*processLease                         // For a while; memory only
	verifyRetained      func(identity.Application, uint32, string) error // tests only
	instanceRunning     func(int, string) bool                           // tests only
	inspectProcess      func(int) (identity.Process, error)              // tests only
	// captureExecutable retains executable evidence for a new prompt (tests
	// replace it; production uses identity.CaptureExecutable). See request_rule.go.
	captureExecutable func(identity.Process, identity.Application) (*identity.RetainedExecutable, error)
	// settledSink, when set by an API operation holding e.mu, collects requests
	// that leave awaiting-decision through policy re-evaluation (queue-reconcile-v1).
	settledSink *[]SettledRequest
	// local-pair-v1: same-host peer identification (nil disables) and
	// decide-pair admissions for the not-yet-requested incoming side.
	LocalPeer      func(identity.Flow) *identity.LocalPeer
	pairAdmissions map[string]*pairAdmission

	policyQueryMu      sync.Mutex // serializes metadata health sampling with response ordering
	policyReadSequence uint64     // read-response ordering only, protected by mu
	StopMonitoring     func()     // configured only for non-enforcing root daemon; API requires root peer
	SaveRules          func([]policy.Rule) error
	Enforcement        func() EnforcementStatus
	AdministratorUID   *uint32
	APIUID             *uint32
	Activity           func() identity.ActivitySnapshot
	UploadShaping      *uploadshape.Manager
	UsageHistory       *accounting.History
	ObservedUsage      *accounting.Ledger
	Generation         string
	Mode               string
	mu                 sync.Mutex
	events             map[string]*Event
	rules              []policy.Rule
	Resolve            func(identity.Flow) identity.Attribution
	// TryResolve, when set, reports false instead of waiting for a busy runtime census.
	TryResolve func(identity.Flow) (identity.Attribution, bool)
	// prefetched holds attributions resolved outside mu for the operation that
	// currently holds mu (see lockResolved); nil otherwise.
	prefetched      *prefetchSet
	peerPrefetched  *prefetchSet // packet-local peer evidence; not an interaction settlement
	settleScheduled bool         // a deferred settlePendingLocked is queued (guarded by mu)
	settleReason    string       // settle requested while mu is held; run after release
	settling        bool         // settleNow is running
	// listReads publishes immutable API list projections (list_snapshot.go).
	listReads listReadState
	Now       func() time.Time
	Timeout   time.Duration
	Max       int
	window    time.Time
	created   int
}

func New(timeout time.Duration) *Engine {
	return &Engine{Zones: identity.DefaultNetworkZones(), Generation: randomID(), events: map[string]*Event{}, Resolve: identity.NewUDPAttributionReuse(identity.Resolve).Resolve, LocalPeer: identity.ResolveLocalPeer, Now: time.Now, Timeout: timeout, Max: 256}
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
			// An ended request stays listed (state unchanged, never deliverable) while its
			// retained record still offers a future rule or For a while, so the card keeps
			// authoritative process state instead of vanishing 5 s after the deadline.
			if r := e.requestRules[v.ID]; r != nil && now.Before(r.Until) {
				continue
			}
			if now.Sub(v.Deadline) > 5*time.Second {
				delete(e.events, key)
			}
		}
	}
	e.trimEndedHistoryLocked(e.Max, now)
}

// Display history shares the client event bound with live prompts. Retained
// future-rule evidence has its own bound/lifetime and must not let ended rows
// overflow that contract. Never evict a live prompt or admission lease here.
func (e *Engine) trimEndedHistoryLocked(limit int, now time.Time) {
	for len(e.events) > limit {
		oldestKey := ""
		var oldest *Event
		for key, event := range e.events {
			if now.Before(event.Deadline.Add(5 * time.Second)) {
				continue
			}
			if oldest == nil || event.FirstSeen.Before(oldest.FirstSeen) || (event.FirstSeen.Equal(oldest.FirstSeen) && event.ID < oldest.ID) {
				oldestKey, oldest = key, event
			}
		}
		if oldest == nil {
			return // live-state admission bounds are enforced separately
		}
		delete(e.events, oldestKey) // requestRules and receipts stay intact
	}
}

// liveEventsLocked counts events that bound new prompts. Ended requests kept listed only
// for their retained record (bounded separately in requestRules) never consume capacity.
func (e *Engine) liveEventsLocked() int {
	now, n := e.Now(), 0
	for _, v := range e.events {
		if now.Before(v.Deadline.Add(5 * time.Second)) {
			n++
		}
	}
	return n
}

// Observe attributes a queued attempt and decides it. Ownership resolution can be
// slow (process scans, runtime censuses) and runs outside e.mu so prompts, API
// reads and independent flows are not held behind it.
func (e *Engine) Observe(f identity.Flow, token string) Event {
	if v, ok := e.tryNetworkEndpoint(f, token); ok {
		return v
	}
	// Every undecided/new attempt and every UDP datagram rechecks actual ownership.
	if e.defaultLoopback(f) {
		return e.ObserveResolved(f, token, identity.Attribution{Status: "localhost", Reason: "Localhost communication is allowed by default", ReasonCode: identity.ReasonLocalhostExempt})
	}
	return e.ObserveResolved(f, token, e.Resolve(f))
}

// TryObserve is Observe without waiting for a busy runtime census. false means
// attribution needs a census that cannot start now: no event is created and
// nothing is logged; the caller must use Observe later or drop explicitly.
func (e *Engine) TryObserve(f identity.Flow, token string) (Event, bool) {
	if v, ok := e.tryNetworkEndpoint(f, token); ok {
		return v, true
	}
	if e.defaultLoopback(f) {
		return e.Observe(f, token), true
	}
	if e.TryResolve == nil {
		return e.Observe(f, token), true
	}
	a, ok := e.TryResolve(f)
	if !ok {
		return Event{}, false
	}
	return e.ObserveResolved(f, token, a), true
}

// MaxUDPObservationBatch bounds a frozen group independently of queue capacity.
const MaxUDPObservationBatch = 16

// PrepareUDPBatch is for a frozen group of identical-flow datagrams already
// queued before this call. The caller must never add arrivals during resolution.
// One fresh ownership observation covers the group. The returned bounded
// decision function reads current policy immediately before each packet's verdict;
// it must not be stored or used for a subsequent group.
func (e *Engine) PrepareUDPBatch(f identity.Flow, token string, count int, census bool) (func() Event, bool) {
	if f.Protocol != "udp" || count < 1 || count > MaxUDPObservationBatch {
		return nil, false
	}
	var a identity.Attribution
	if e.defaultLoopback(f) {
		a = identity.Attribution{Status: "localhost", Reason: "Localhost communication is allowed by default", ReasonCode: identity.ReasonLocalhostExempt}
	} else if !census && e.TryResolve != nil {
		var ok bool
		a, ok = e.TryResolve(f)
		if !ok {
			return nil, false
		}
	} else {
		var shared bool
		if census {
			a, shared = e.resolveSocketBatch(f)
			if !shared {
				a, shared = e.resolveSocketInitialBatch(f)
			}
		}
		if !shared {
			a = e.Resolve(f)
		}
	}
	return func() Event {
		if count == 0 {
			return Event{}
		}
		count--
		return e.ObserveResolved(f, token, a)
	}, true
}

// ObserveResolved decides a queued attempt with attribution the trusted caller
// resolved for exactly this flow immediately before the call. Zones and policy
// are read under e.mu at decision time, so a rule changed during resolution
// applies to this attempt. Resolve must be safe for concurrent use.
func (e *Engine) ObserveResolved(f identity.Flow, token string, a identity.Attribution) Event {
	if e.UploadShaping != nil {
		e.UploadShaping.Offer(f, a)
	}
	var peers *prefetchSet
	// Peer prefetch resolves other flows outside e.mu and is the only reason to
	// check loopback before the locked decision. Without peer candidates (the
	// common UDP case) the decision's loopback observation is the one policy
	// evaluation makes under e.mu; TCP keeps its endpoint-scope lookups.
	if !e.hasPeerCandidates(f) {
		// Same shape resolvePeers returns for no candidates: an empty, non-nil
		// set, so a peer rule published between this check and the locked
		// decision finds no prefetched evidence and refuses as before.
		peers = &prefetchSet{flows: map[string]prefetchedAttribution{}}
	} else if !e.defaultLoopback(f) {
		peers = e.resolvePeers(f)
	}
	// This packet's kernel link query does not require the policy mutex. Keep
	// unrelated endpoints and rule publication progressing while netlink waits.
	// Only this call consumes the observation; policy/expiry/zones remain fresh
	// under the lock and the next datagram makes another kernel observation.
	device, known := observeLoopbackDevice(f)
	wait := diagnostics.Begin(diagnostics.PolicyLockWait)
	e.mu.Lock()
	wait.End()
	defer diagnostics.Begin(diagnostics.PolicyLocked).End()
	e.peerPrefetched = peers
	defer func() { e.peerPrefetched = nil; e.mu.Unlock() }()
	v := e.observeResolvedWithLinkLocked(f, token, a, &packetLinkObservation{device, known})
	// Deny/Ask/Once traffic must not create background census work. Only a
	// configured application Allow is a candidate; publication still requires
	// its own fresh observation and current policy check.
	if v.State == "allowed" && v.decided != nil && v.decided.Action == "allow" && v.decided.Filter.Application != "" {
		e.trackSocketFlowLocked(f)
		// The first complete identity proof and current Allow are enough for a
		// connection grant. Do not force a second ownership scan to authorize
		// the connection we just verified. Reused native evidence cannot seed.
		if s := e.socketAuthorization; s != nil && s.connectionScoped && a.FreshConnectionProof() {
			if tracked := s.flows[s.flowKey(f)]; tracked != nil && !tracked.haveKey {
				e.finishSocketAuthorizationLocked(s, tracked, s.store.Begin(), a)
				if tracked.haveKey {
					tracked.firstGrantSource = "initial_verified_decision"
					tracked.next = time.Now().Add(connectionCheckInterval)
				}
			}
		}
	}
	return v
}

// Caller holds e.mu. Shared by ordinary fresh attribution and explicit network
// authority, so rule publication and the final verdict cannot race a precheck.
func (e *Engine) observeResolvedLocked(f identity.Flow, token string, a identity.Attribution) Event {
	return e.observeResolvedWithLinkLocked(f, token, a, nil)
}

func (e *Engine) observeResolvedWithLinkLocked(f identity.Flow, token string, a identity.Attribution, link *packetLinkObservation) Event {
	e.refreshZonesLocked()
	f.NetworkScope = e.Zones.ClassifyFlow(f)
	now := e.Now()
	e.expire(now)
	e.pruneLeasesLocked(now, false)
	key := f.Key() + "|" + token
	base, rule, conflicts, nonLoopbackDevice := e.evaluateClassifiedLinkLocked(e.rules, f, a, now, link)
	action, rule, lease := e.leaseOverlayLocked(base, rule, f, a, now)
	if old := e.events[key]; old != nil && now.Before(old.Deadline) && old.Attribution.Fingerprint == a.Fingerprint && a.Application != nil {
		valid := old.Rule == rule && ((old.State == "allowed" && action == "allow") || (old.State == "blocked" && action == "block") || (old.State == "awaiting-decision" && action == "ask"))
		// Once and For-a-while flow admissions keep their own flow lease while no
		// configured rule decides the flow.
		if (strings.HasPrefix(old.Rule, "once:") || strings.HasPrefix(old.Rule, leaseRulePrefix)) && base == "ask" {
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
	// local-pair-v1: identify the same-host peer; a reviewed pair decision may
	// answer this (incoming) side when no configured rule decides it.
	var pair *pairHit
	if rule != policy.DefaultLoopback && !nonLoopbackDevice {
		pair = e.observeLocalPairLocked(&v, a, action, now)
	}
	if pair != nil {
		action, rule = pair.Action, v.Rule
	}
	v.decided = e.ruleLocked(rule)
	// Reuse only the bounded history identity after evaluating current network
	// policy again. No collector result, cached verdict or ownership authority
	// is reused. Sharing ID also serializes out-of-order packet log outcomes.
	if v.decided != nil && v.decided.NetworkEndpoint && a.ReasonCode == identity.ReasonAttributionNotRequired {
		if old := e.events[key]; old != nil && old.historyOnly && old.Attribution.ReasonCode == a.ReasonCode && old.decided != nil && *old.decided == *v.decided && now.Before(old.logDeadline) {
			v.ID = old.ID
			v.logAttemptID, v.logDeadline, v.finalLogged = old.logAttemptID, old.logDeadline, old.finalLogged
		}
	}
	if a.Principal() != nil {
		filter := policy.Remembered(f, a)
		v.RememberedFilter = &filter
		v.RequestGroup = requestGroup(filter)
		service := fmt.Sprintf("local service port %d; any remote source port", filter.LocalPort)
		if f.Direction == "outgoing" {
			service = fmt.Sprintf("remote service port %d; any local source port", filter.RemotePort)
		}
		v.ScopePreviews = map[string]string{
			"once": fmt.Sprintf("Once: %s %s, local %s, remote %s; this application/revision/user only. TCP: one connection (30 seconds to admit); UDP: fixed 30-second flow lease.", f.Direction, f.Protocol, f.Local, f.Remote),
		}
		if identity.RuntimeRuleBlocked(a.Application) == "" {
			v.ScopePreviews["application"] = fmt.Sprintf("Remember for one hour (memory only): program %s; captured revision %s; user %d; %s %s; remote address %s; %s. Other local addresses may match. Saved application permissions follow updates of the same verified program; other programs, users and prefixes stay separate.", filter.Application, filter.Revision, filter.UID, filter.Direction, filter.Protocol, filter.RemoteAddress, service)
		}
		if a.Application != nil && identity.BestEffortElectron(*a.Application) {
			v.ScopePreviews["application"] = strings.Replace(v.ScopePreviews["application"], "same verified program", "same best-effort matched application", 1)
		}
		if e.SaveRules != nil && v.ScopePreviews["application"] != "" {
			v.ScopePreviews["application"] = strings.Replace(v.ScopePreviews["application"], "memory only", "saved to disk; absolute expiry survives restart", 1)
			v.ScopePreviews["persistent"] = strings.Replace(v.ScopePreviews["application"], "Remember for one hour (saved to disk; absolute expiry survives restart)", "Persistent until disabled/deleted (saved to disk)", 1)
		}
		if identity.RuntimeRuleBlocked(a.Application) != "" && identity.NativeProcessAuthority(a) {
			v.ScopePreviews["process-remember"] = "Remember this process only; ends on process exit or backend restart. Other processes and relaunches are not covered."
			v.ScopePreviews["application"] = v.ScopePreviews["process-remember"] + " Selected expiry also applies; Process is mandatory."
			if e.SaveRules != nil {
				v.ScopePreviews["persistent"] = v.ScopePreviews["process-remember"] + " Saved with no time expiry; Process is mandatory."
			}
		}
		// Offered only when the request has one verified owning process.
		if p, err := leaseOwner(a); err == nil {
			v.ScopePreviews[ForAWhileScope] = forAWhilePreview(f, p, ForAWhileDuration)
		}
	}
	switch action {
	case "allow":
		v.State = "allowed"
		v.Reason = "allowed by rule; other firewall chains may still deny delivery"
		if rule == policy.DefaultLoopback {
			v.Reason = "Localhost communication is allowed by default; explicit localhost address rules can override"
		}
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
	if v.decided != nil && v.decided.NetworkEndpoint {
		v.Permission = endpointSentence(*v.decided)
		v.Reason = "Explicit network endpoint policy (all users/programs; application identity is not required): " + action + "; Allow overrides application policy, other firewall chains may still deny delivery"
	}
	if pair != nil {
		e.admitPairLocked(&v, pair, now)
	}
	if lease != nil {
		v.Reason = lease.reason()
		v.leaseID = lease.ID
		v.Permission = "for a while: this connection or UDP tuple for 30 seconds; new connections of the same process and direction until the lease ends"
		// The admitted connection/UDP tuple keeps a Once-style 30-second flow
		// lease; only new connections need the process lease to be live.
		v.Deadline = now.Add(30 * time.Second)
		v.logAttemptID, v.logDeadline = v.ID, v.Deadline
	}
	if now.Sub(e.window) >= time.Second {
		e.window = now
		e.created = 0
	}
	v.historyOnly = action != "ask" && pair == nil && lease == nil
	// Immediate verdicts do not spend prompt budget. At capacity, discard only
	// replaceable policy history; pending and explicitly decided flow leases stay.
	if e.liveEventsLocked() >= e.Max {
		oldestKey := ""
		var oldest *Event
		for k, event := range e.events {
			if event.historyOnly && (oldest == nil || event.FirstSeen.Before(oldest.FirstSeen)) {
				oldestKey, oldest = k, event
			}
		}
		if oldest != nil {
			delete(e.events, oldestKey)
		}
	}
	if (!v.historyOnly && e.liveEventsLocked() >= e.Max) || (v.State == "awaiting-decision" && e.created >= 20) {
		v.State = "blocked"
		v.Reason = "pending capacity or prompt rate exceeded"
		v.capacity = true
		return v
	}
	if e.liveEventsLocked() >= e.Max {
		// The queue submits this immediate verdict and logs the returned event.
		// Omit optional history instead of converting an Allow into a drop.
		return v
	}
	if v.State == "awaiting-decision" {
		e.created++
	}
	if _, replacing := e.events[key]; !replacing {
		e.trimEndedHistoryLocked(e.Max-1, now)
	}
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
			row.PreviousRevisionRules = e.previousRevisionRulesLocked(v)
			out = append(out, row)
		}
	}
	return out, e.Zones
}
func owned(a identity.Attribution, uid uint32) bool {
	return a.Principal() != nil && a.Principal().UID == uid
}
func (e *Engine) Decide(id, action, scope string, uid uint32, admin bool) (Event, error) {
	v, _, err := e.DecideSettled(id, action, scope, 0, uid, admin)
	return v, err
}

// DecideSettled is Decide plus the other requests the decision settled.
// leaseSeconds is the For a while duration (0 = 15 s); other scopes need 0.
func (e *Engine) DecideSettled(id, action, scope string, leaseSeconds int64, uid uint32, admin bool) (Event, []SettledRequest, error) {
	e.lockResolved(e.requestSelection(id, uid, admin, scope != "once"))
	defer e.unlockResolved()
	defer e.collectSettledLocked()()
	if leaseSeconds != 0 && scope != ForAWhileScope {
		return Event{}, nil, mutationError("invalid_request", "duration_seconds applies to For a while only; Remember durations need a reviewed decision")
	}
	d, err := forAWhileDuration(leaseSeconds)
	if err != nil {
		return Event{}, nil, err
	}
	v, err := e.decideLocked(id, action, scope, uid, admin, nil, "", time.Time{}, d)
	e.followUpSettleLocked()
	return v, e.settledLocked(), err
}

func (e *Engine) decideLocked(id, action, scope string, uid uint32, admin bool, reviewed *policy.Rule, sentence string, reviewDeadline time.Time, leaseDuration time.Duration) (Event, error) {
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	if action != "allow" && action != "block" {
		return Event{}, fmt.Errorf("action must be allow or block")
	}
	if scope != "once" && scope != ForAWhileScope && scope != "application" && !(scope == "persistent" && e.SaveRules != nil) {
		return Event{}, fmt.Errorf("scope must be once, for-a-while or application")
	}
	remember := scope == "application" || scope == "persistent"
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
		a, ok := e.resolvedEventLocked(v)
		if !ok {
			return Event{}, retryChangedRequest()
		}
		if !e.Now().Before(v.Deadline) {
			return Event{}, e.rejectPendingDeadlineLocked(v)
		}
		if reviewed != nil && !e.Now().Before(reviewDeadline) {
			return Event{}, mutationError("preview_expired", "Preview expired during identity revalidation; review again")
		}
		if a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			return Event{}, e.rejectPendingBindingLocked(v, a)
		}
		if remember && len(e.rules) >= 256 {
			return Event{}, mutationError("capacity", "rule capacity reached")
		}
		var lease *processLease
		if scope == ForAWhileScope {
			// Validated before any mutation: refusal leaves the request pending.
			l, err := e.newLeaseLocked(v, a, action, now, leaseDuration)
			if err != nil {
				return Event{}, err
			}
			lease = l
		}
		var remembered *policy.Rule
		if remember {
			if why := identity.RuntimeRuleBlocked(a.Application); why != "" && !(reviewed != nil && !reviewed.Filter.Process.IsZero() && identity.NativeProcessAuthority(a) && reviewed.Filter.Process.Matches(a.Owners[0])) {
				return Event{}, mutationError(identity.CodeIdentityUnverifiable, why)
			}
			r := policy.Rule{Version: 1, Executable: a.Application.KeyPath(), Invocation: attributionInvocation(a), Schema: 2, ID: "user:" + v.ID, Priority: 100, Action: action, Filter: policy.Remembered(v.Flow, a), Created: now, Expires: now.Add(time.Hour)}
			if scope == "persistent" {
				r.Expires = time.Time{}
			}
			if reviewed != nil {
				r = *reviewed
			}
			r = e.rootScope(r)
			if other := duplicate(e.rules, r, now, *a.Application); other != "" {
				return Event{}, fmt.Errorf("duplicate scope exists as %s; edit the existing rule", other)
			}
			next := append(append([]policy.Rule{}, e.rules...), r)
			for i, old := range e.rules {
				if reviewed != nil && old.ID == r.ID {
					if old.Version+1 != r.Version || canonicalRuleFilter(old, *a.Application) != canonicalRuleFilter(r, *a.Application) {
						return Event{}, mutationError("policy_conflict", "The remembered rule changed since review; review again")
					}
					next = append([]policy.Rule{}, e.rules...)
					next[i] = r
				}
			}
			if err := e.revokeSocketGrantsLocked(); err != nil {
				return Event{}, err
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
		reason := "explicit user decision"
		if lease != nil {
			e.storeLeaseLocked(lease)
			v.Lease = lease.ref()
			v.leaseID = lease.ID
			if p, err := leaseOwner(a); err == nil {
				v.Permission = forAWhilePreview(v.Flow, p, leaseDuration)
			}
			reason = "explicit user decision; " + lease.reason()
		}
		e.recordFinal(v, action, "user", scope, reason, remembered, &uid, "deferred", "")
		e.markRetainedDecidedLocked(v.ID)
		if lease != nil {
			// Other requests of this process and direction that are still waiting
			// are subsequent connections too; nothing else changes.
			e.settlePendingLocked("for a while " + lease.ID)
		}
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
	defer e.unlockAndSettle()
	rules = append([]policy.Rule{}, policy.LatestProgramRules(rules)...)
	changed := false
	for i := range rules {
		next := e.rootScope(rules[i])
		if next.RootApplication != rules[i].RootApplication {
			changed = true
			if next.Version == ^uint64(0) {
				return fmt.Errorf("rule version exhausted during root scope migration")
			}
			next.Version++
		}
		rules[i] = next
	}
	if err := e.revokeSocketGrantsLocked(); err != nil {
		return err
	}
	if changed && e.SaveRules != nil {
		if err := e.SaveRules(rules); err != nil {
			return err
		}
	}
	e.rules = rules
	e.pruneHandlesLocked()
	e.resetCachedLocked("policy replaced")
	// Wholesale replacement (startup load) also drops explicit Once/lease
	// admissions: their held packets drop and the client retries.
	for key, v := range e.events {
		if v.State != "awaiting-decision" && !strings.HasPrefix(v.Reason, "re-evaluated after policy change") {
			delete(e.events, key)
		}
	}
	return nil
}

// RetainedState is used only for already queued packets, never to create prompts.
// Unknown/deleted/expired events drop. An Allow always rechecks the relationship.
//
// Ownership is resolved outside e.mu; the same event must still be allowed with
// an unchanged deadline afterwards, so a decision or Block made meanwhile wins.
func (e *Engine) RetainedState(id, fingerprint string) string {
	e.mu.Lock()
	v, state := e.retainedEventLocked(id, fingerprint)
	if state != "allowed" {
		e.mu.Unlock()
		return state
	}
	flow, deadline := v.Flow, v.Deadline
	e.mu.Unlock()

	peers := e.resolvePeers(flow)
	a := e.Resolve(flow)

	e.mu.Lock()
	e.peerPrefetched = peers
	defer func() { e.peerPrefetched = nil; e.mu.Unlock() }()
	if current, state := e.retainedEventLocked(id, fingerprint); current != v || state != "allowed" || !v.Deadline.Equal(deadline) {
		if state == "allowed" {
			return "drop" // replaced or re-leased meanwhile; never reuse this resolution
		}
		return state
	}
	if !e.Now().Before(v.Deadline) || a.Application == nil || a.Fingerprint != fingerprint {
		// Preserve the actual recheck, not just the original successful evidence.
		// In particular, runtime holder changes otherwise appear as an opaque
		// fingerprint mismatch after an acknowledged Allow.
		if e.Now().Before(v.Deadline) {
			delta := identity.ComparePendingBinding(v.Attribution, a, e.Now())
			v.Revalidation = &delta
		}
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
		act, rule, _, _ := e.policyLocked(v.Flow, a, e.Now())
		if act != "allow" || rule != v.Rule {
			return "drop"
		}
	}
	return "allow"
}

// retainedEventLocked finds a retained packet's event and reports its current
// disposition: "pending", "drop", or "allowed" (which still needs ownership).
func (e *Engine) retainedEventLocked(id, fingerprint string) (*Event, string) {
	e.refreshZonesLocked()
	now := e.Now()
	e.expire(now)
	for _, v := range e.events {
		if v.ID != id {
			continue
		}
		if !now.Before(v.Deadline) || v.Attribution.Fingerprint != fingerprint {
			return v, "drop"
		}
		if v.State == "awaiting-decision" {
			return v, "pending"
		}
		if v.State != "allowed" {
			return v, "drop"
		}
		return v, "allowed"
	}
	return nil, "drop"
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
func (e *Engine) ChangeRule(generation, id, action string, expected *uint64, uid uint32, admin bool) error {
	active := false
	if e.Enforcement != nil {
		active = e.Enforcement().State != "stopped"
	}
	e.mu.Lock()
	defer e.unlockAndSettle()
	if generation == "" || generation != e.Generation {
		return mutationError("generation_conflict", "backend generation changed or missing; reload")
	}
	if id == "" || expected == nil {
		return mutationError("invalid_request", "rule ID and expected_version required")
	}
	if e.SaveRules == nil {
		return mutationError("unavailable", "durable rules unavailable")
	}
	next := append([]policy.Rule{}, e.rules...)
	found := false
	for i, r := range next {
		if r.ID != id {
			continue
		}
		if !admin && (r.Filter.AllUIDs || r.Filter.UID != uid) {
			return mutationError("forbidden", "not authorized")
		}
		if r.Version != *expected {
			return mutationError("version_conflict", "stale rule version; reload before changing")
		}
		if r.NetworkEndpoint {
			return mutationError("immutable_target", "Endpoint rules require exact conditional Delete; recreate through endpoint review to change")
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
		return mutationError("not_found", "rule no longer exists; reload authoritative state")
	}
	if err := e.revokeSocketGrantsLocked(); err != nil {
		return err
	}
	if err := e.SaveRules(next); err != nil {
		return mutationError("persistence_failed", "rule transaction failed; old policy retained: "+err.Error())
	}
	e.rules = next
	e.pruneHandlesLocked()
	// Cached verdicts are invalidated conservatively; awaiting requests are
	// re-evaluated against the new policy instead of being dropped.
	e.resetCachedLocked("rule " + action)
	return nil
}
