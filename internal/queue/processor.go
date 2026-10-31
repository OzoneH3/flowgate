package queue

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"flowgate/internal/queuehealth"
	"runtime/pprof"
	"sync/atomic"
	"time"
)

// Function boundaries allow testing packet lifetime without a privileged queue.
// Only observe may create a prompt; verdict reports the action actually sent.
type packetProcessor struct {
	decisionObserved func(daemon.Event, bool)
	batchObserve     func(identity.Flow, string, int, bool) (func() daemon.Event, bool)
	ctx              context.Context
	observe          func(identity.Flow, string) daemon.Event
	tryObserve       func(identity.Flow, string) (daemon.Event, bool)
	retain           func(uint32, int, daemon.Event) bool
	record           func(daemon.Event, string, error)
	verdict          func(uint32, bool) (bool, error)
	expired          *atomic.Uint64
	diagnostic       func(queuehealth.Cause)
}

func (p *packetProcessor) process(j packetJob, stopping bool) {
	p.processStage(j, stopping, true)
}

// False hands the untouched packet to the census lane; no event or verdict
// exists yet. The scheduler keeps ownership and endpoint ordering across lanes.
func (p *packetProcessor) processStage(j packetJob, stopping, census bool) bool {
	if stopping || p.ctx.Err() != nil || !time.Now().Before(j.deadline) {
		p.expired.Add(1)
		p.rejection(stoppingOrCancelled(p.ctx, stopping))
		p.verdict(j.id, false)
		return true
	}
	// Observe resolves fresh ownership, then evaluates current policy. Never
	// pre-resolve a queued job: its socket may have been replaced while waiting.
	var v daemon.Event
	if census {
		v = p.observe(j.flow, j.token)
	} else {
		var ok bool
		v, ok = p.tryObserve(j.flow, j.token)
		if !ok {
			return false
		}
	}
	p.finish(j, v)
	return true
}

func (p *packetProcessor) finish(j packetJob, v daemon.Event) {
	live := p.ctx.Err() == nil && time.Now().Before(j.deadline) && time.Now().Before(v.Deadline)
	if live && v.State == "awaiting-decision" {
		if p.retain(j.id, j.size, v) {
			if p.decisionObserved != nil {
				p.decisionObserved(v, false)
			}
			p.record(v, daemon.VerdictHeld, nil)
			return
		}
		p.rejection(queuehealth.RetentionCapacity)
	}
	if !live {
		p.expired.Add(1)
		p.rejection(stoppingOrCancelled(p.ctx, false))
	}
	allowed, err := p.verdict(j.id, live && v.State == "allowed")
	if p.decisionObserved != nil && err == nil {
		p.decisionObserved(v, allowed)
	}
	outcome := daemon.VerdictDropped
	if err != nil {
		outcome = daemon.VerdictFailed
	} else if allowed {
		outcome = daemon.VerdictAccepted
	}
	p.record(v, outcome, err)
}

func (p *packetProcessor) processBatch(jobs []packetJob, stopping, census bool) bool {
	work := "queue_general"
	if census {
		work = "queue_census"
	}
	var done bool
	pprof.Do(p.ctx, pprof.Labels("flowgate_work", work), func(context.Context) { done = p.processBatchProfiled(jobs, stopping, census) })
	return done
}
func (p *packetProcessor) processBatchProfiled(jobs []packetJob, stopping, census bool) bool {
	live := make([]packetJob, 0, len(jobs))
	for _, j := range jobs {
		if !stopping && p.ctx.Err() == nil && time.Now().Before(j.deadline) {
			live = append(live, j)
		}
	}
	var decide func() daemon.Event
	if len(live) != 0 {
		var ok bool
		decide, ok = p.batchObserve(live[0].flow, live[0].token, len(live), census)
		if !ok {
			return false
		} // no side effects, including for expired members
	}
	index := 0
	for _, j := range jobs {
		if index < len(live) && live[index].id == j.id {
			p.finish(j, decide())
			index++
		} else {
			p.expired.Add(1)
			p.rejection(stoppingOrCancelled(p.ctx, stopping))
			p.verdict(j.id, false)
		}
	}
	return true
}

func stoppingOrCancelled(ctx context.Context, stopping bool) queuehealth.Cause {
	if stopping || ctx.Err() != nil {
		return queuehealth.Shutdown
	}
	return queuehealth.Deadline
}
func (p *packetProcessor) rejection(c queuehealth.Cause) {
	if p.diagnostic != nil {
		p.diagnostic(c)
	}
}
