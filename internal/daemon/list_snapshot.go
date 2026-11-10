package daemon

import (
	"context"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"log"
	"net"
	"runtime/pprof"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const ListSnapshotCapability = "request-list-snapshot-v1"
const listSnapshotInterval = 250 * time.Millisecond

var apiPublishProfileContext = pprof.WithLabels(context.Background(), pprof.Labels("flowgate_work", "api_publish"))

// ListSnapshot is presentation state, never permission authority. Publication
// captures one engine generation; each reader gets its own deeply copied view.
type ListSnapshot struct {
	Revision   string                     `json:"snapshot_revision"`
	At         time.Time                  `json:"snapshot_at"`
	Events     []Event                    `json:"events"`
	Zones      identity.NetworkZones      `json:"network_zones"`
	Rules      []policy.Rule              `json:"rules"`
	RuleStates map[string]RuleTargetState `json:"rule_states"`
	Leases     []ProcessLease             `json:"process_leases"`
	HasPresets bool                       `json:"has_presets"`
}

type publishedList struct {
	targets       map[string]identity.PermissionTarget // presentation only, immutable after publish
	data          []byte
	socketHints   socketFastPathHints
	socketStatus  []byte
	socketFailure string
	hasPresets    bool
	revision      string
	at            time.Time
}
type listReadState struct {
	published   atomic.Pointer[publishedList]
	publishMu   sync.Mutex // serializes capture through publication, including ack barriers
	revision    uint64
	lifecycleMu sync.Mutex
	users       int
	stop        chan struct{}
	done        chan struct{}
}

func (s *listReadState) publish(e *Engine) error {
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	e.mu.Lock()
	now := e.Now()
	e.refreshZonesLocked()
	e.expire(now)
	e.pruneRequestRulesLocked(now)
	e.pruneLeasesLocked(now, true)
	// Expiring previews is lifecycle work, not a side effect of list polling.
	e.pruneDecisionPreviews(now)
	view := ListSnapshot{Revision: strconv.FormatUint(s.revision+1, 10), At: now, Events: []Event{}, Zones: e.Zones, Rules: []policy.Rule{}, RuleStates: map[string]RuleTargetState{}, Leases: []ProcessLease{}}
	targets := map[string]identity.PermissionTarget{}
	for _, event := range e.events {
		if target := identity.DescribePermissionTarget(event.Attribution); target != nil {
			targets[event.ID] = *target
		}
		row := *event
		row.RequestRule = e.requestRuleSourceLocked(event.ID)
		row.PreviousRevisionRules = e.previousRevisionRulesLocked(event)
		view.Events = append(view.Events, row)
	}
	for _, rule := range e.rules {
		view.Rules = append(view.Rules, rule)
		view.RuleStates[rule.ID] = e.targetStateLocked(rule)
		if rule.Schema == 5 {
			view.HasPresets = true
		}
	}
	for _, lease := range e.processLeases {
		view.Leases = append(view.Leases, e.leaseViewLocked(lease, now))
	}
	// Serializing under the lock severs every nested pointer/map/slice. Neither
	// published bytes nor readers share mutable storage with the live engine.
	data, err := json.Marshal(view)
	status := e.socketAuthorizationSummaryLocked()
	socketHints := e.socketFastPathHintsLocked()
	socketData, socketErr := json.Marshal(status)
	var socketFailure string
	if current := e.socketAuthorization; current != nil {
		if current.failure != nil {
			socketFailure = current.failure.Error()
		} else if current.disabled {
			socketFailure = "socket authorization disabled"
		}
	}
	e.mu.Unlock()
	socketHints.sampleHits()
	if socketErr != nil {
		return fmt.Errorf("publish socket status: %w", socketErr)
	}
	if err != nil {
		return fmt.Errorf("publish request snapshot: %w", err)
	}
	s.revision++
	s.published.Store(&publishedList{socketHints: socketHints, targets: targets, data: data, socketStatus: socketData, socketFailure: socketFailure, hasPresets: view.HasPresets, revision: view.Revision, at: view.At})
	return nil
}

func (s *listReadState) read(uid uint32, admin bool, now time.Time) (ListSnapshot, error) {
	p := s.published.Load()
	if p == nil {
		return ListSnapshot{}, fmt.Errorf("request snapshot unavailable")
	}
	var view ListSnapshot
	if err := json.Unmarshal(p.data, &view); err != nil {
		return ListSnapshot{}, err
	}
	events := view.Events[:0]
	for _, event := range view.Events {
		if target, ok := p.targets[event.ID]; ok {
			event.Attribution = event.Attribution.WithPermissionPresentation(target)
		}
		if !admin && !owned(event.Attribution, uid) {
			continue
		}
		// Time passing never needs an engine mutation on this path. Live decision
		// handlers still validate the actual deadline and ownership themselves.
		if event.State == "awaiting-decision" && !now.Before(event.Deadline) {
			event.State = "expired"
			event.Reason = "decision deadline passed"
		}
		if event.RequestRule != nil && !now.Before(event.RequestRule.Until) {
			event.RequestRule = nil
		}
		events = append(events, event)
	}
	view.Events = events
	rules := view.Rules[:0]
	states := map[string]RuleTargetState{}
	for _, rule := range view.Rules {
		if admin || rule.Filter.AllUIDs || rule.Filter.UID == uid {
			rules = append(rules, rule)
			states[rule.ID] = view.RuleStates[rule.ID]
		}
	}
	view.Rules, view.RuleStates = rules, states
	leases := view.Leases[:0]
	for _, lease := range view.Leases {
		if (!admin && lease.UID != uid) || !now.Before(lease.Until) {
			continue
		}
		lease.RemainingMS = lease.Until.Sub(now).Milliseconds()
		leases = append(leases, lease)
	}
	view.Leases = leases
	return view, nil
}

// One lifecycle owner per engine, shared by primary/companion API listeners.
// It continues expiry/pruning without a GUI connection and stops on last Close.
func (s *listReadState) acquire(e *Engine) (func(), error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.users == 0 {
		if err := s.publish(e); err != nil {
			return nil, err
		}
		stop, done := make(chan struct{}), make(chan struct{})
		s.stop, s.done = stop, done
		go func() {
			pprof.SetGoroutineLabels(apiPublishProfileContext)
			defer close(done)
			ticker := time.NewTicker(listSnapshotInterval)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					if err := s.publish(e); err != nil {
						log.Print(err)
					}
				}
			}
		}()
	}
	s.users++
	return func() {
		s.lifecycleMu.Lock()
		s.users--
		var done chan struct{}
		if s.users == 0 {
			close(s.stop)
			done = s.done
		}
		s.lifecycleMu.Unlock()
		if done != nil {
			<-done
		}
	}, nil
}

type snapshotListener struct {
	net.Listener
	once    sync.Once
	release func()
}

func (l *snapshotListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(l.release)
	return err
}

// Pure queries need no acknowledgement barrier. Previews are deliberately not
// exempt: their revalidation may end a pending request. Unknown/future operations
// conservatively publish so adding a mutation cannot silently omit its barrier.
func (s *listReadState) publishAfter(e *Engine, operation string) error {
	switch operation {
	case "profile-status", "profile-start", "profile-stop", "profile-fetch",
		"decision-log", "decision-log-get", "traffic-status", "essential-status",
		"evaluation-readiness", "protection-readiness", "policy-view", "policy-explain", "decision-status":
		return nil
	default:
		return s.publish(e)
	}
}

// PublishedSocketAuthorizationStatus is a detached presentation snapshot. It
// never waits for the policy lock and must not be used as authorization evidence.
func (e *Engine) PublishedSocketAuthorizationStatus() map[string]any {
	p := e.listReads.published.Load()
	if p == nil {
		return nil
	}
	var status map[string]any
	if json.Unmarshal(p.socketStatus, &status) != nil {
		return nil
	}
	return status
}

// PublishedSocketAuthorizationFailure is presentation-only, refreshed with the
// list snapshot; live revocation remains synchronous under the policy lock.
func (e *Engine) PublishedSocketAuthorizationFailure() error {
	p := e.listReads.published.Load()
	if p == nil || p.socketFailure == "" {
		return nil
	}
	return fmt.Errorf("%s", p.socketFailure)
}
