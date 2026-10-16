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
	ID          string               `json:"id"`
	Flow        identity.Flow        `json:"flow"`
	Attribution identity.Attribution `json:"attribution"`
	State       string               `json:"state"`
	Reason      string               `json:"reason"`
	Rule        string               `json:"rule"`
	Conflicts   []string             `json:"matching_rules"`
	FirstSeen   time.Time            `json:"first_seen"`
	Deadline    time.Time            `json:"deadline"`
	Permission  string               `json:"permission"`
	Token       string               `json:"-"`
}
type Engine struct {
	mu      sync.Mutex
	events  map[string]*Event
	rules   []policy.Rule
	Resolve func(identity.Flow) identity.Attribution
	Now     func() time.Time
	Timeout time.Duration
	Max     int
	window  time.Time
	created int
}

func New(timeout time.Duration) *Engine {
	return &Engine{events: map[string]*Event{}, Resolve: identity.Resolve, Now: time.Now, Timeout: timeout, Max: 256}
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
			if r.ID == old.Rule && (r.Expires.IsZero() || now.Before(r.Expires)) {
				valid = true
			}
		}
		if valid {
			return *old
		}
	}
	action, rule, conflicts := policy.Evaluate(e.rules, f, a, now)
	v := Event{ID: randomID(), Flow: f, Attribution: a, FirstSeen: now, Deadline: now.Add(e.Timeout), Rule: rule, Conflicts: conflicts, Token: token, Permission: "once: this TCP connection or UDP tuple for 30 seconds; exact application and remote endpoint"}
	switch action {
	case "allow":
		v.State = "allowed"
		v.Reason = "allowed by rule; other firewall chains may still deny delivery"
	case "block":
		v.State = "blocked"
		v.Reason = "blocked by rule or unresolved ownership"
	default:
		v.State = "awaiting-decision"
		v.Reason = "packet dropped pending approval; TCP retransmits, UDP sender must retry"
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
	return len(a.Owners) == 1 && a.Owners[0].UID == uid
}
func (e *Engine) Decide(id, action, scope string, uid uint32, admin bool) (Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	e.expire(now)
	if action != "allow" && action != "block" {
		return Event{}, fmt.Errorf("action must be allow or block")
	}
	if scope != "once" && scope != "application" {
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
		if a.Application == nil || a.Fingerprint != v.Attribution.Fingerprint {
			v.State = "expired"
			v.Reason = "identity changed before decision"
			return Event{}, fmt.Errorf("identity changed; retry required")
		}
		if scope == "application" && len(e.rules) >= 256 {
			return Event{}, fmt.Errorf("rule capacity reached")
		}
		v.State = map[string]string{"allow": "allowed", "block": "blocked"}[action]
		v.Reason = "explicit CLI decision; retry original attempt"
		v.Rule = "once:" + v.ID
		v.Deadline = now.Add(30 * time.Second)
		if scope == "application" {
			if len(e.rules) >= 256 {
				return Event{}, fmt.Errorf("rule capacity reached")
			}
			r := policy.Rule{ID: "user:" + v.ID, Priority: 100, Action: action, Filter: policy.Filter{Application: a.Application.Key, Revision: a.Application.Revision, UID: a.Owners[0].UID, Direction: v.Flow.Direction, Protocol: v.Flow.Protocol, Remote: v.Flow.Remote.String()}, Expires: now.Add(time.Hour)}
			e.rules = append(e.rules, r)
			v.Rule = r.ID
			v.Permission = "application + executable revision + user + direction + protocol + exact remote endpoint, one hour (memory only)"
			for key, other := range e.events {
				if other.ID != v.ID {
					delete(e.events, key)
				}
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
