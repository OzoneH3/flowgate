package daemon

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"runtime/pprof"
	"sync"
	"time"
)

type socketFlow struct {
	observationDone                  chan struct{}
	alignmentAttempted               bool
	alignmentLastAttempt             time.Time
	alignmentPublications            uint64
	alignmentPeer                    *socketFlow
	alignmentStarted, alignmentUntil time.Time
	verificationStarted              time.Time
	renewalDurations                 [16]time.Duration
	renewalDurationIndex             int
	scheduledDue                     uint64
	runtime                          bool
	deadline                         uint64
	observationStart                 uint64
	publishedAt                      uint64
	firstGrantSource                 string
	lastPacket                       uint64
	application                      string
	flow                             identity.Flow
	key                              socketgrant.Key
	haveKey, busy                    bool
	batchPending, batchRunning       *socketBatchRequest
	next                             time.Time
}
type socketAuthorization struct {
	cancel                                                                                                         context.CancelFunc
	done                                                                                                           chan struct{}
	jobs                                                                                                           *sync.WaitGroup
	productionSession                                                                                              bool
	routeBound                                                                                                     bool // enabled only with a verified actual-oif kernel gate
	routeMoves                                                                                                     uint64
	ordinaryYield                                                                                                  bool
	ordinaryAdmission                                                                                              func(identity.Flow, func()) (identity.Attribution, uint64)
	ordinaryYieldCount, ordinaryYieldNS, ordinaryYieldMaxNS, ordinaryYieldCaps                                     uint64
	ordinaryObserved                                                                                               func(identity.Flow) (identity.Attribution, uint64)
	initialMergeChecks, initialMergeFresh, initialMergePublished                                                   uint64
	batchCoordination                                                                                              bool
	ctx                                                                                                            context.Context
	batchClaims, batchDelivered, batchTimeouts, batchWaitNS, batchMaxWaitNS, batchSecondClaimant, batchMissingEmit uint64
	alignmentDeferrals, alignmentSuccesses, alignmentWaitNS, alignmentMaxWaitNS, alignmentLapses                   uint64
	wake                                                                                                           chan struct{}
	trace                                                                                                          []socketRenewalTrace
	traceCount                                                                                                     uint64
	resolveGroup                                                                                                   func([]identity.Flow, func(int, *identity.Attribution))
	groups, groupFlows                                                                                             uint64
	observerDiagnostics                                                                                            func() map[string]any
	renewalGaps, maxGapNS                                                                                          uint64
	disabled                                                                                                       bool
	checks, published, refused                                                                                     uint64
	store                                                                                                          *socketgrant.Store
	resolve                                                                                                        func(identity.Flow) identity.Attribution
	flows                                                                                                          map[string]*socketFlow
	failure                                                                                                        error
	active                                                                                                         int
}

// StartSocketAuthorization is intentionally restricted to the isolated lab.
// Dynamic zones and configured shaping are not yet supported by this prototype:
// rejecting activation preserves their normal enforcement instead of bypassing it.
func (e *Engine) StartSocketAuthorization(ctx context.Context, b socketgrant.Backend, resolve func(identity.Flow) identity.Attribution, diagnostics ...func() map[string]any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Mode != "isolated-lab" || e.ZoneSource != nil || e.UploadShaping != nil || resolve == nil || e.socketAuthorization != nil {
		return fmt.Errorf("socket authorization requires isolated lab, static zones and no shaping manager")
	}
	return e.startSocketAuthorizationLocked(ctx, b, resolve, diagnostics...)
}

func (e *Engine) startSocketAuthorizationLocked(ctx context.Context, b socketgrant.Backend, resolve func(identity.Flow) identity.Attribution, diagnostics ...func() map[string]any) error {
	store, err := socketgrant.New(b)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &socketAuthorization{cancel: cancel, done: make(chan struct{}), jobs: &sync.WaitGroup{}, ctx: ctx, wake: make(chan struct{}, 1), store: store, resolve: resolve, flows: map[string]*socketFlow{}}
	if len(diagnostics) > 0 {
		s.observerDiagnostics = diagnostics[0]
	}
	e.socketAuthorization = s
	go e.runSocketAuthorization(ctx, s)
	return nil
}

// resolveSocketBatch shares one full fresh observation with this frozen queue
// batch and its optional kernel certificate. It never publishes from ordinary
// cached attribution or a dispatch hint. The expiry ticket precedes the scan.
func (e *Engine) resolveSocketBatch(flow identity.Flow) (identity.Attribution, bool) {
	e.mu.Lock()
	s := e.socketAuthorization
	if s == nil || s.failure != nil || s.disabled || s.resolve == nil ||
		flow.Protocol != "udp" || flow.Direction != "outgoing" || !flow.Local.Addr().Is4() ||
		!flow.Remote.Addr().Is4() || flow.NetNS != identity.NetNS() {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	if !s.observeQueueRoute(flow) {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	f := s.flows[s.flowKey(flow)]
	// Only previously rule-Allowed flows may use renewal priority. Unknown,
	// Ask and Deny flows stay on ordinary census admission; this check is
	// scheduling eligibility, never permission authority.
	if f == nil {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	if s.batchCoordination {
		a, ok := e.awaitSocketBatchLocked(s, f)
		e.mu.Unlock()
		return a, ok
	}
	if f.busy || s.active >= 2 {
		e.mu.Unlock()
		return identity.Attribution{}, false
	}
	f.busy = true
	f.lastPacket = socketgrant.BootNow()
	s.active++
	if s.jobs != nil {
		s.jobs.Add(1)
	}
	ticket := s.store.Begin()
	started := time.Now()
	f.verificationStarted = started
	if f.observationDone == nil {
		f.observationDone = make(chan struct{})
	}
	e.mu.Unlock()
	var a identity.Attribution
	pprof.Do(context.Background(), pprof.Labels("flowgate_work", "socket_initial"), func(context.Context) { a = s.resolve(flow) })
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		f.busy = false
		f.completeObservationWait()
		s.active--
		if s.jobs != nil {
			s.jobs.Done()
		}
		f.next = started.Add(100 * time.Millisecond)
		s.wakeScheduler()
	}()
	if s.failure == nil && !s.disabled {
		e.finishSocketAuthorizationLocked(s, f, ticket, a)
	}
	s.checks++
	return a, true
}

func (e *Engine) trackSocketFlowLocked(f identity.Flow) {
	s := e.socketAuthorization
	if s == nil || s.failure != nil || f.Direction != "outgoing" || f.Protocol != "udp" ||
		!f.Local.Addr().Is4() || !f.Remote.Addr().Is4() || f.NetNS != identity.NetNS() {
		return
	}
	if !s.observeQueueRoute(f) {
		return
	}
	if old, ok := s.flows[s.flowKey(f)]; ok {
		old.lastPacket = socketgrant.BootNow()
		return
	}
	if len(s.flows) >= socketgrant.MaxEntries {
		return
	}
	s.flows[s.flowKey(f)] = &socketFlow{flow: f, lastPacket: socketgrant.BootNow()}
	s.wakeScheduler()
}
func (e *Engine) revokeSocketGrantsLocked() error {
	s := e.socketAuthorization
	if s == nil {
		return nil
	}
	if s.disabled {
		return nil
	}
	if s.failure != nil {
		if closeErr := s.store.Close(); closeErr == nil {
			s.disabled = true
			return nil
		}
		return fmt.Errorf("socket authorization unavailable: %w", s.failure)
	}
	if err := s.store.Revoke(); err != nil {
		s.failure = err
		// Disable the gate instead of making ordinary policy edits depend on
		// a broken accelerator. Only a confirmed kernel epoch=0 is sufficient.
		if closeErr := s.store.Close(); closeErr == nil {
			s.disabled = true
			return nil
		}
		return fmt.Errorf("kernel revocation failed: %w", err)
	}
	return nil
}
func (e *Engine) runSocketAuthorization(ctx context.Context, s *socketAuthorization) {
	if s.done != nil {
		defer close(s.done)
	}
	pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("flowgate_work", "socket_scheduler")))
	defer pprof.SetGoroutineLabels(ctx)
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			s.failure = ctx.Err()
			if err := s.store.Close(); err != nil {
				s.failure = err
			}
			e.mu.Unlock()
			return
		case <-timer.C:
		case <-s.wake:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		e.mu.Lock()
		for key, f := range s.flows {
			if f.busy || f.batchPending != nil {
				continue
			}
			if f.haveKey {
				stats, err := s.store.Stats(f.key)
				if err != nil {
					s.failure = err
					break
				}
				if stats.LastSeen > f.lastPacket {
					f.lastPacket = stats.LastSeen
				}
			}
			if boot := socketgrant.BootNow(); boot >= f.lastPacket && boot-f.lastPacket > uint64(time.Second) {
				if f.haveKey {
					if err := s.store.Forget(f.key); err != nil {
						s.failure = err
						break
					}
				}
				f.completeObservationWait()
				delete(s.flows, key)
			}
		}
		for s.failure == nil && !s.disabled && s.active < 2 {
			now := time.Now()
			boot := socketgrant.BootNow()
			chosen := s.nextRenewal(now, boot)
			if chosen == nil {
				break
			}
			group := s.renewalGroup(chosen, now)
			if chosen.batchPending == nil && len(group) == 1 && s.alignRenewal(chosen, now, boot) {
				continue
			}
			s.finishAlignment(group, now)
			for _, f := range group {
				f.busy = true
			}
			s.active++
			if s.jobs != nil {
				s.jobs.Add(1)
			}
			ticket := s.store.Begin()
			started := time.Now()
			for _, f := range group {
				f.verificationStarted = started
				if f.observationDone == nil {
					f.observationDone = make(chan struct{})
				}
				s.startSocketBatchLocked(f, started)
				f.scheduledDue = ticket.Deadline() - uint64(socketgrant.Window)
				if !f.next.IsZero() {
					late := started.Sub(f.next)
					if late > 0 && uint64(late) < f.scheduledDue {
						f.scheduledDue -= uint64(late)
					}
				}
			}
			if len(group) > 1 {
				s.groups++
				s.groupFlows += uint64(len(group))
			}
			go e.resolveSocketRenewalGroup(ctx, s, group, ticket, started)

		}

		delay := s.nextRenewalWake(time.Now())
		e.mu.Unlock()
		timer.Reset(delay)
	}
}

// Wakes are coalesced; neither queue admission nor completion waits for the
// scheduler. Timer eligibility uses a fresh clock after acquiring the lock.
func (s *socketAuthorization) wakeScheduler() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *socketAuthorization) nextRenewalWake(now time.Time) time.Duration {
	delay := 25 * time.Millisecond
	if s.failure != nil || s.disabled || s.active >= 2 {
		return delay
	}
	for _, f := range s.flows {
		if f.busy {
			continue
		}
		d := f.renewalEligibleAt().Sub(now)
		if d <= 0 {
			return time.Nanosecond
		}
		if d < delay {
			delay = d
		}
	}
	return delay
}

func (e *Engine) finishSocketAuthorizationLocked(s *socketAuthorization, f *socketFlow, ticket socketgrant.Ticket, a identity.Attribution) {
	remove := func() {
		if f.haveKey {
			if err := s.store.Forget(f.key); err != nil {
				s.failure = err
			}
			f.haveKey = false
		}
	}
	if s.routeBound && s.flows[s.flowKey(f.flow)] != f {
		return
	}
	k, ok := socketgrant.KeyFor(f.flow, a)
	if s.routeBound {
		k, ok = socketgrant.KeyForQueuedOutput(f.flow, a)
	}
	if !ok {
		remove()
		f.completeObservationWait()
		delete(s.flows, s.flowKey(f.flow))
		return
	}
	flow := f.flow
	flow.NetworkScope = e.Zones.ClassifyFlow(flow)
	now := e.Now()
	action, id, _ := e.evaluateClassifiedLocked(e.rules, flow, a, now)
	action, id, _ = e.leaseOverlayLocked(action, id, flow, a, now)
	r := e.ruleLocked(id)
	// Scope-limited first implementation: only explicit application rules; all
	// Once/Ask/presets/network/peer/process grants keep the ordinary queue path.
	if e.leaseForLocked(flow, a, now) != nil || action != "allow" || r == nil || r.NetworkEndpoint || r.Preset != nil ||
		r.Filter.Application != a.Application.Key || r.Filter.UID != a.Principal().UID ||
		!r.Filter.Process.IsZero() || r.Filter.InterfaceIndex != 0 || r.Filter.InterfaceName != "" ||
		r.Filter.PeerService.Application != "" || r.Filter.AllPrograms || r.Filter.AllUIDs {
		remove()
		f.completeObservationWait()
		delete(s.flows, s.flowKey(f.flow))
		return
	}
	if f.haveKey && f.key != k {
		remove()
	}
	count := 0
	for _, other := range s.flows {
		if other != f && other.application == a.Application.Key {
			count++
		}
	}
	if count >= 8 {
		remove()
		f.completeObservationWait()
		delete(s.flows, s.flowKey(f.flow))
		return
	}
	if s.failure != nil {
		return
	}
	horizon := uint64(0)
	if !r.Expires.IsZero() {
		remaining := r.Expires.Sub(now)
		if remaining <= 0 {
			remove()
			return
		}
		horizon = socketgrant.BootNow() + uint64(remaining)
	}
	allowed, err := s.store.Publish(ticket, k, horizon)
	if err != nil {
		s.failure = err
		remove()
		return
	}
	if allowed {
		boot := socketgrant.BootNow()
		if f.deadline != 0 && boot > f.deadline {
			s.renewalGaps++
			if f.alignmentAttempted {
				s.alignmentLapses++
			}
			if gap := boot - f.deadline; gap > s.maxGapNS {
				s.maxGapNS = gap
			}
		}
		f.alignmentPublications++
		f.observationStart = ticket.Deadline() - uint64(socketgrant.Window)
		f.publishedAt = boot
		if f.firstGrantSource == "" {
			f.firstGrantSource = "separate_scan"
		}
		f.deadline = ticket.Deadline()
		if horizon != 0 && horizon < f.deadline {
			f.deadline = horizon
		}
		s.published++
		f.application = a.Application.Key
		f.runtime = a.Application.Kind == "wine"
		f.key = k
		f.haveKey = true
	} else {
		s.refused++
	}
}

// Aggregate prototype diagnostics. Hits bypass queue verdict logs, so the
// kernel totals must be reported separately rather than inferred from the queue.
func (e *Engine) SocketAuthorizationStatus() map[string]any {
	e.mu.Lock()
	enabled := e.socketAuthorization != nil
	e.mu.Unlock()
	if !enabled {
		return nil
	}
	gc := socketGCDiagnostics() // sample without holding the policy lock
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.socketAuthorizationStatusLocked(gc)
}

func (e *Engine) socketAuthorizationStatusLocked(gc map[string]any) map[string]any {
	s := e.socketAuthorization
	if s == nil {
		return nil
	}
	out := map[string]any{"window_ms": 250, "entries": len(s.flows), "active": s.active, "checks": s.checks, "published": s.published, "late_or_capacity": s.refused, "scope": "isolated-ipv4-udp-output"}
	if s.productionSession {
		out["scope"] = "ipv4-udp-output-queue-interface"
		out["new_interfaces"] = "queue-until-next-protection-session"
	}
	out["batch_coordination"] = map[string]any{"enabled": s.batchCoordination, "claims": s.batchClaims, "scheduler_delivered": s.batchDelivered, "timeouts": s.batchTimeouts, "wait_ns": s.batchWaitNS, "max_wait_ns": s.batchMaxWaitNS, "second_claimant": s.batchSecondClaimant, "missing_emit": s.batchMissingEmit}
	out["first_grant_merge"] = map[string]any{"enabled": s.ordinaryObserved != nil, "checks": s.initialMergeChecks, "fresh": s.initialMergeFresh, "published": s.initialMergePublished}
	out["gc_pause_history"] = gc
	out["renewal_timeline"], out["renewal_timeline_overwritten"] = s.renewalTrace()
	out["alignment"] = map[string]uint64{"deferrals": s.alignmentDeferrals, "successes": s.alignmentSuccesses, "wait_ns": s.alignmentWaitNS, "max_wait_ns": s.alignmentMaxWaitNS, "subsequent_lapses": s.alignmentLapses}
	out["renewal_groups"] = s.groups
	out["grouped_flows"] = s.groupFlows
	out["renewal_gaps"] = s.renewalGaps
	out["max_renewal_gap_ms"] = float64(s.maxGapNS) / 1e6
	out["ordinary_yield"] = map[string]any{"enabled": s.ordinaryYield, "count": s.ordinaryYieldCount, "wait_ns": s.ordinaryYieldNS, "max_wait_ns": s.ordinaryYieldMaxNS, "cap_hits": s.ordinaryYieldCaps}
	out["route_bound"] = s.routeBound
	out["route_moves"] = s.routeMoves
	out["disabled"] = s.disabled
	if s.observerDiagnostics != nil {
		out["renewal_observer"] = s.observerDiagnostics()
	}
	// Bounded lab-only evidence for transfer/renewal timing. Counters never
	// alter deadlines or policy; a read error is explicit, not a zero hit count.
	flows := []map[string]any{}
	for _, f := range s.flows {
		row := map[string]any{"flow": f.flow, "application": f.application, "has_grant": f.haveKey, "first_grant_source": f.firstGrantSource,
			"observation_start_boot_ns": f.observationStart, "published_boot_ns": f.publishedAt, "deadline_boot_ns": f.deadline}
		if f.haveKey {
			row["cookie"] = f.key.Cookie
			stats, err := s.store.Stats(f.key)
			if err != nil {
				row["counter_error"] = err.Error()
			} else {
				row["packets"] = stats.Packets
				row["bytes"] = stats.Bytes
			}
		}
		flows = append(flows, row)
	}
	out["flows"] = flows
	if s.failure != nil {
		out["failure"] = s.failure.Error()
	} else {
		totals, err := s.store.Totals()
		if err != nil {
			out["counter_error"] = err.Error()
		} else {
			out["fast_packets"] = totals.Packets
			out["fast_bytes"] = totals.Bytes
		}
	}
	return out
}

// EnableSocketRenewalGroups only shares fresh observations of scheduler-frozen
// due runtime flows. Ordinary queue batches and later arrivals are not included.
func (e *Engine) EnableSocketRenewalGroups(resolve func([]identity.Flow, func(int, *identity.Attribution))) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketAuthorization == nil || (e.Mode != "isolated-lab" && !e.socketAuthorization.productionSession) || resolve == nil {
		return fmt.Errorf("isolated socket authorization required")
	}
	e.socketAuthorization.resolveGroup = resolve
	return nil
}
func (e *Engine) resolveSocketRenewalGroup(ctx context.Context, s *socketAuthorization, group []*socketFlow, ticket socketgrant.Ticket, started time.Time) {
	pprof.SetGoroutineLabels(pprof.WithLabels(ctx, pprof.Labels("flowgate_work", "socket_renewal")))
	defer pprof.SetGoroutineLabels(ctx)
	e.mu.Lock()
	requests := make([]*socketBatchRequest, len(group))
	completions := make([]chan struct{}, len(group))
	for i, f := range group {
		requests[i] = f.batchRunning
		completions[i] = f.observationDone
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		// A resolver that returns without an emit cannot strand a frozen waiter.
		// No observation is invented; its ordinary fallback must verify afresh.
		for i, f := range group {
			if requests[i] != nil && f.batchRunning == requests[i] {
				s.completeSocketBatchLocked(f, nil, false)
				f.busy = false
				f.next = started.Add(100 * time.Millisecond)
				s.batchMissingEmit++
			}
		}
		for i, f := range group {
			if f.observationDone == completions[i] {
				f.completeObservationWait()
			}
		}
		s.active--
		if s.jobs != nil {
			s.jobs.Done()
		}
		e.mu.Unlock()
		s.wakeScheduler()
	}()
	emit := func(i int, a *identity.Attribution) {
		// Resolver is trusted and emits once per frozen index; never accept a
		// later flow or renew the shared ticket while completing the group.
		f := group[i]
		if a == nil {
			fresh := s.resolve(f.flow)
			a = &fresh
		}
		resolved := socketgrant.BootNow()
		e.mu.Lock()
		defer e.mu.Unlock()
		defer func() {
			s.completeSocketBatchLocked(f, a, ctx.Err() == nil && s.failure == nil && !s.disabled)
			if f.observationDone == completions[i] {
				f.completeObservationWait()
			}
			f.noteRenewalDuration(time.Since(started))
			f.busy = false
			f.next = started.Add(100 * time.Millisecond)
		}()
		if ctx.Err() != nil || s.failure != nil || s.disabled {
			return
		}
		s.traceCompletion(f, ticket, resolved, string(a.ReasonCode), func() { e.finishSocketAuthorizationLocked(s, f, ticket, *a) })
		s.checks++
	}
	if len(group) == 1 {
		a := s.resolve(group[0].flow)
		emit(0, &a)
		return
	}
	flows := make([]identity.Flow, len(group))
	for i, f := range group {
		flows[i] = f.flow
	}
	s.resolveGroup(flows, emit)
}

// renewalGroup freezes existing eligible work without waiting for arrivals.
// Bringing an idle peer forward by at most one renewal cadence aligns subsequent renewals;
// all members still require fresh evidence and the same start-anchored expiry.
func (s *socketAuthorization) renewalGroup(chosen *socketFlow, now time.Time) []*socketFlow {
	group := []*socketFlow{chosen}
	if s.resolveGroup == nil || !chosen.runtime || !chosen.haveKey {
		return group
	}
	for _, f := range s.flows {
		if len(group) >= identity.MaxRuntimeObservationFlows {
			break
		}
		if !f.busy && !f.next.After(now.Add(100*time.Millisecond)) && renewalPeers(chosen, f) {
			group = append(group, f)
		}
	}
	return group
}

// Among due work, protect the earliest kernel expiry first. New flows have
// no authorization to preserve and use a fresh-window scheduling target only;
// this target grants no permission and never changes a ticket's expiry.
func (s *socketAuthorization) nextRenewal(now time.Time, boot uint64) *socketFlow {
	var chosen *socketFlow
	var earliest uint64
	for _, f := range s.flows {
		if f.busy || now.Before(f.renewalEligibleAt()) {
			continue
		}
		target := f.deadline
		if !f.haveKey || target == 0 {
			target = boot + uint64(socketgrant.Window)
		}
		if chosen == nil || target < earliest || (target == earliest && f.next.Before(chosen.next)) {
			chosen = f
			earliest = target
		}
	}
	return chosen
}

// SocketAuthorizationFailure retains a disabled accelerator's cause even after
// a later network snapshot publishes successfully. Queue policy is independent.
func (e *Engine) SocketAuthorizationFailure() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.socketAuthorization; s != nil {
		if s.failure != nil {
			return s.failure
		}
		if s.disabled {
			return fmt.Errorf("socket authorization disabled")
		}
	}
	return nil
}

// socketAuthorizationSummaryLocked is the bounded production presentation view.
// Do not add per-flow rows, observer/renewal rings, or GC history here: this is
// captured by the periodic list publisher while holding the policy lock.
func (e *Engine) socketAuthorizationSummaryLocked() map[string]any {
	s := e.socketAuthorization
	if s == nil {
		return nil
	}
	scope := "isolated-ipv4-udp-output"
	if s.productionSession {
		scope = "ipv4-udp-output-queue-interface"
	}
	out := map[string]any{
		"window_ms": 250, "scope": scope, "route_bound": s.routeBound,
		"disabled": s.disabled, "entries": len(s.flows), "active": s.active,
		"checks": s.checks, "published": s.published, "late_or_capacity": s.refused,
		"renewal_groups": s.groups, "grouped_flows": s.groupFlows,
		"renewal_gaps": s.renewalGaps, "max_renewal_gap_ms": float64(s.maxGapNS) / 1e6,
		"route_moves": s.routeMoves,
	}
	if s.productionSession {
		out["new_interfaces"] = "queue-until-next-protection-session"
	}
	if s.failure != nil {
		out["failure"] = s.failure.Error()
	} else {
		totals, err := s.store.Totals()
		if err != nil {
			out["counter_error"] = err.Error()
		} else {
			out["fast_packets"] = totals.Packets
			out["fast_bytes"] = totals.Bytes
		}
	}
	return out
}
