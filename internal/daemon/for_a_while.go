package daemon

import (
	"flowgate/internal/identity"
	"fmt"
	"strings"
	"time"
)

// ForAWhileCapability: NetLimiter's Ask-window "For a while" checkbox. The
// current request is decided like Once, and the same action applies to new
// connections of the same direction created by the exact requesting process
// instance for the selected duration. No rule is created; leases live in memory
// only and are lost when the daemon restarts.
const ForAWhileCapability = "decision-for-a-while-v1"

// ForAWhileScope is the decide scope value.
const ForAWhileScope = "for-a-while"

// ForAWhileDuration is the legacy wire default when duration_seconds is absent.
// The current UI selects one hour explicitly when duration selection is supported.
const ForAWhileDuration = 15 * time.Second

// ForAWhileDurationsCapability (FlowGate extension): decide scope for-a-while
// and request-for-a-while accept duration_seconds from ForAWhileDurations
// (absent = 15). A lease still ends early when its process instance exits.
const ForAWhileDurationsCapability = "decision-for-a-while-durations-v1"

// ForAWhileDurations is the exact allowed set of lease durations in seconds.
var ForAWhileDurations = []int64{15, 60, 300, 600, 1800, 3600}

// forAWhileDuration validates a requested duration (0 = default 15 s).
func forAWhileDuration(seconds int64) (time.Duration, error) {
	if seconds == 0 {
		return ForAWhileDuration, nil
	}
	for _, d := range ForAWhileDurations {
		if d == seconds {
			return time.Duration(d) * time.Second, nil
		}
	}
	return 0, mutationError("invalid_request", "duration_seconds for For a while must be one of 15, 60, 300, 600, 1800 or 3600")
}

// ForAWhileSource is the decision-log source for connections decided by a lease.
const ForAWhileSource = "for_a_while"

const maxProcessLeases = 256
const leaseRulePrefix = "while:"

type processLease struct {
	ID, Action, Direction, EventID string
	Application                    identity.Application
	UID                            uint32
	PID                            int
	Start, BootID, PIDNS, MountNS  string
	Created, Until                 time.Time
	Duration                       time.Duration
}

// LeaseRef is attached to the request decided For a while.
type LeaseRef struct {
	ID      string    `json:"id"`
	Until   time.Time `json:"until"`
	Seconds int       `json:"seconds"`
}

// ProcessLease is the list view of a live For-a-while lease.
type ProcessLease struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	Direction   string    `json:"direction"`
	Application string    `json:"application"`
	Name        string    `json:"application_name"`
	Executable  string    `json:"executable"`
	UID         uint32    `json:"uid"`
	PID         int       `json:"pid"`
	Start       string    `json:"start"`
	Created     time.Time `json:"created"`
	Until       time.Time `json:"until"`
	RemainingMS int64     `json:"remaining_ms"`
	Seconds     int       `json:"seconds"`
	EventID     string    `json:"event_id"`
}

// leaseOwner returns the single verified owning process a lease can bind to.
func leaseOwner(a identity.Attribution) (identity.Process, error) {
	app := a.Application
	if app == nil || app.Key == "" || app.Revision == "" || a.Principal() == nil {
		return identity.Process{}, mutationError("process_scope_unavailable", "For a while needs a verified application identity")
	}
	if why := identity.RuntimeRuleBlocked(app); why != "" {
		return identity.Process{}, mutationError("process_scope_unavailable", why)
	}
	if a.Table != nil {
		return identity.Process{}, mutationError("process_scope_unavailable", "Runtime table identifies a Windows application; no verified Linux requester generation for a process lease")
	}
	if !a.VisibilityComplete {
		return identity.Process{}, mutationError("process_scope_unavailable", "For a while needs complete socket-holder visibility")
	}
	if len(a.Owners) != 1 {
		return identity.Process{}, mutationError("process_scope_unavailable", fmt.Sprintf("For a while needs exactly one verified owning process (%d visible)", len(a.Owners)))
	}
	p := a.Owners[0]
	if p.ThreadGroup != 0 && p.ThreadGroup != p.PID {
		return identity.Process{}, mutationError("process_scope_unavailable", "For a while requires a live process leader; a worker descriptor does not establish process-instance authority")
	}
	if p.PID <= 0 || p.Start == "" || p.BootID == "" || p.UID != a.Principal().UID {
		return identity.Process{}, mutationError("process_scope_unavailable", "For a while needs the owner's PID, start time and boot identity")
	}
	return p, nil
}

func (l *processLease) matches(f identity.Flow, a identity.Attribution, now time.Time) bool {
	if !now.Before(l.Until) || f.Direction != l.Direction {
		return false
	}
	p, err := leaseOwner(a)
	if err != nil {
		return false
	}
	app := a.Application
	return p.PID == l.PID && p.Start == l.Start && p.UID == l.UID && p.BootID == l.BootID &&
		(l.PIDNS == "" || p.PIDNS == l.PIDNS) && (l.MountNS == "" || p.MountNS == l.MountNS) &&
		app.Key == l.Application.Key && app.Revision == l.Application.Revision && app.Executable == l.Application.Executable
}

func (l *processLease) reason() string {
	return fmt.Sprintf("For a while (%s) for process %d until %s", l.Action, l.PID, l.Until.UTC().Format(time.RFC3339))
}

func (l *processLease) ref() *LeaseRef {
	return &LeaseRef{ID: l.ID, Until: l.Until, Seconds: l.seconds()}
}

func (l *processLease) seconds() int {
	if l.Duration == 0 {
		return int(ForAWhileDuration / time.Second)
	}
	return int(l.Duration / time.Second)
}

func leaseIDOf(rule string) string {
	if strings.HasPrefix(rule, leaseRulePrefix) {
		return strings.TrimPrefix(rule, leaseRulePrefix)
	}
	return ""
}

// pruneLeasesLocked removes expired leases and, when checkLiveness is set,
// leases whose exact process instance no longer exists. Matching never relies
// on pruning: a relaunched or reused PID has different start ticks.
func (e *Engine) pruneLeasesLocked(now time.Time, checkLiveness bool) {
	running := e.instanceRunning
	if running == nil {
		running = identity.InstanceRunning
	}
	for id, l := range e.processLeases {
		if !now.Before(l.Until) || (checkLiveness && !running(l.PID, l.Start)) {
			delete(e.processLeases, id)
		}
	}
}

func (e *Engine) leaseForLocked(f identity.Flow, a identity.Attribution, now time.Time) *processLease {
	for _, l := range e.processLeases {
		if l.matches(f, a, now) {
			return l
		}
	}
	return nil
}

// policyLocked is evaluateLocked plus live For-a-while leases. Leases only fill
// prompts: any configured Allow/Block (and unsafe attribution) wins.
func (e *Engine) policyLocked(f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string, *processLease) {
	action, rule, conflicts := e.evaluateLocked(e.rules, f, a, now)
	action, rule, lease := e.leaseOverlayLocked(action, rule, f, a, now)
	return action, rule, conflicts, lease
}

// leaseOverlayLocked applies a matching live lease to an "ask" result only.
func (e *Engine) leaseOverlayLocked(action, rule string, f identity.Flow, a identity.Attribution, now time.Time) (string, string, *processLease) {
	if action != "ask" {
		return action, rule, nil
	}
	if l := e.leaseForLocked(f, a, now); l != nil {
		return l.Action, leaseRulePrefix + l.ID, l
	}
	return action, rule, nil
}

// newLeaseLocked validates and creates (without storing) a lease for v.
func (e *Engine) newLeaseLocked(v *Event, a identity.Attribution, action string, now time.Time, d time.Duration) (*processLease, error) {
	p, err := leaseOwner(a)
	if err != nil {
		return nil, err
	}
	e.pruneLeasesLocked(now, false)
	l := &processLease{ID: randomID(), Action: action, Direction: v.Flow.Direction, EventID: v.ID, Application: *a.Application, UID: p.UID, PID: p.PID, Start: p.Start, BootID: p.BootID, PIDNS: p.PIDNS, MountNS: p.MountNS, Created: now, Until: now.Add(d), Duration: d}
	replaced := ""
	for id, o := range e.processLeases {
		if o.PID == l.PID && o.Start == l.Start && o.Direction == l.Direction {
			replaced = id
		}
	}
	if replaced == "" && len(e.processLeases) >= maxProcessLeases {
		return nil, mutationError("capacity", "For-a-while lease capacity reached; wait for expiry")
	}
	return l, nil
}

func (e *Engine) storeLeaseLocked(l *processLease) {
	if e.processLeases == nil {
		e.processLeases = map[string]*processLease{}
	}
	for id, o := range e.processLeases {
		// The latest decision for the same process instance and direction wins.
		if o.PID == l.PID && o.Start == l.Start && o.Direction == l.Direction {
			delete(e.processLeases, id)
		}
	}
	e.processLeases[l.ID] = l
}

// ProcessLeases lists live leases visible to the caller (admin or owning UID).
func (e *Engine) ProcessLeases(uid uint32, admin bool) []ProcessLease {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	e.pruneLeasesLocked(now, true)
	out := []ProcessLease{}
	for _, l := range e.processLeases {
		if !admin && l.UID != uid {
			continue
		}
		out = append(out, e.leaseViewLocked(l, now))
	}
	return out
}

func forAWhilePreview(f identity.Flow, p identity.Process, d time.Duration) string {
	return fmt.Sprintf("For a while: this connection and new %s connections of this process (PID %d) for %s, to any remote address and port (TCP and UDP), or until the process exits; no rule is created; not saved, lost on daemon restart. Configured rules still apply first.", f.Direction, p.PID, durationText(d))
}

func durationText(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		if d == time.Hour {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		if d == time.Minute {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", d/time.Minute)
	}
	return fmt.Sprintf("%d seconds", int(d/time.Second))
}
