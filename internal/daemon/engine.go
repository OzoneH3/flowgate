package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
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
	Token            string               `json:"-"`
}
type Engine struct {
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
	return &Engine{Generation: randomID(), events: map[string]*Event{}, Resolve: identity.Resolve, Now: time.Now, Timeout: timeout, Max: 256}
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
	for key, v := range e.events {
		if !now.Before(v.Deadline) {
			if v.State == "awaiting-decision" {
				v.State = "expired"
				v.Reason = "decision timed out; retry creates a new request"
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
	now := e.Now()
	e.expire(now)
	key := f.Key() + "|" + token
	// Every undecided/new attempt and every UDP datagram rechecks actual ownership.
	a := e.Resolve(f)
	if old := e.events[key]; old != nil && now.Before(old.Deadline) && old.Attribution.Fingerprint == a.Fingerprint && a.Application != nil {
		valid := old.Rule == "default-ask" || strings.HasPrefix(old.Rule, "once:")
		for _, r := range e.rules {
			if !r.Disabled && r.ID == old.Rule && (r.Expires.IsZero() || now.Before(r.Expires)) {
				valid = true
			}
		}
		if valid {
			return *old
		}
	}
	action, rule, conflicts := policy.Evaluate(e.rules, f, a, now)
	v := Event{ID: randomID(), Flow: f, Attribution: a, FirstSeen: now, Deadline: now.Add(e.Timeout), Rule: rule, Conflicts: conflicts, Token: token, Permission: "once: this TCP connection or UDP tuple for 30 seconds; exact application and remote endpoint"}
	if a.Principal() != nil {
		filter := policy.Remembered(f, a)
		v.RememberedFilter = &filter
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
	}
	if now.Sub(e.window) >= time.Second {
		e.window = now
		e.created = 0
	}
	if len(e.events) >= e.Max || e.created >= 20 {
		v.State = "blocked"
		v.Reason = "pending/history capacity or prompt rate exceeded"
		return v
	}
	e.created++
	e.events[key] = &v
	return v
}
func (e *Engine) List(uid uint32, admin bool) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expire(e.Now())
	out := []Event{}
	for _, v := range e.events {
		if admin || owned(v.Attribution, uid) {
			out = append(out, *v)
		}
	}
	return out
}
func owned(a identity.Attribution, uid uint32) bool {
	return a.Principal() != nil && a.Principal().UID == uid
}
func (e *Engine) Decide(id, action, scope string, uid uint32, admin bool) (Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
			return Event{}, fmt.Errorf("not authorized")
		}
		if v.State != "awaiting-decision" || !now.Before(v.Deadline) {
			return Event{}, fmt.Errorf("stale decision; retry required")
		}
		a := e.Resolve(v.Flow)
		if !e.Now().Before(v.Deadline) || a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			v.State = "expired"
			v.Reason = "identity changed before decision"
			return Event{}, fmt.Errorf("identity changed; retry required")
		}
		if scope != "once" && len(e.rules) >= 256 {
			return Event{}, fmt.Errorf("rule capacity reached")
		}
		var remembered *policy.Rule
		if scope != "once" {
			r := policy.Rule{Version: 1, Executable: a.Application.Executable, Schema: 2, ID: "user:" + v.ID, Priority: 100, Action: action, Filter: policy.Remembered(v.Flow, a), Created: now, Expires: now.Add(time.Hour)}
			if scope == "persistent" {
				r.Expires = time.Time{}
			}
			if other := duplicate(e.rules, r); other != "" {
				return Event{}, fmt.Errorf("duplicate scope exists as %s; edit the existing rule", other)
			}
			next := append(append([]policy.Rule{}, e.rules...), r)
			if e.SaveRules != nil {
				if err := e.SaveRules(next); err != nil {
					return Event{}, fmt.Errorf("rule persistence failed: %w", err)
				}
			}
			e.rules = next
			remembered = &r
		}
		v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		v.Reason = "explicit client decision; FlowGate permission is not proof of network delivery"
		v.Rule = "once:" + v.ID
		v.Deadline = now.Add(30 * time.Second)
		if remembered != nil {
			v.Rule = remembered.ID
			v.Permission = v.ScopePreviews[scope]

			for key, other := range e.events {
				if other.ID == v.ID || other.State == "awaiting-decision" {
					continue
				}
				action, effective, _ := policy.Evaluate(e.rules, other.Flow, other.Attribution, now)
				// Unrelated rules must not discard a just-approved one-shot packet.
				if strings.HasPrefix(other.Rule, "once:") && effective == "default-ask" {
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
	e.events = map[string]*Event{}
	return nil
}

// RetainedState is used only for already queued packets, never to create prompts.
// Unknown/deleted/expired events drop. An Allow always rechecks the relationship.
func (e *Engine) RetainedState(id, fingerprint string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
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
			return "drop"
		}
		// Once grants use the event lease; remembered grants must still be live.
		if !strings.HasPrefix(v.Rule, "once:") {
			act, rule, _ := policy.Evaluate(e.rules, v.Flow, a, e.Now())
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
		if admin || r.Filter.UID == uid {
			out = append(out, r)
		}
	}
	return out
}
func (e *Engine) ChangeRule(id, action string, uid uint32, admin bool) error {
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
		if !admin && r.Filter.UID != uid {
			return fmt.Errorf("not authorized")
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
	// Invalidate pending as well as cached verdicts conservatively; retained packets drop.
	e.events = map[string]*Event{}
	return nil
}
