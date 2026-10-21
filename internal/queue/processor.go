package queue

import (
	"context"
	"flowgate/internal/daemon"
	"flowgate/internal/identity"
	"sync/atomic"
	"time"
)

// Function boundaries allow testing packet lifetime without a privileged queue.
// Only observe may create a prompt; verdict reports the action actually sent.
type packetProcessor struct {
	ctx        context.Context
	observe    func(identity.Flow, string) daemon.Event
	tryObserve func(identity.Flow, string) (daemon.Event, bool)
	retain     func(uint32, int, daemon.Event) bool
	record     func(daemon.Event, string, error)
	verdict    func(uint32, bool) (bool, error)
	expired    *atomic.Uint64
}

func (p *packetProcessor) process(j packetJob, stopping bool) {
	p.processStage(j, stopping, true)
}

// False hands the untouched packet to the census lane; no event or verdict
// exists yet. The scheduler keeps ownership and endpoint ordering across lanes.
func (p *packetProcessor) processStage(j packetJob, stopping, census bool) bool {
	if stopping || p.ctx.Err() != nil || !time.Now().Before(j.deadline) {
		p.expired.Add(1)
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
	live := p.ctx.Err() == nil && time.Now().Before(j.deadline) && time.Now().Before(v.Deadline)
	if live && v.State == "awaiting-decision" && p.retain(j.id, j.size, v) {
		p.record(v, daemon.VerdictHeld, nil)
		return true
	}
	if !live {
		p.expired.Add(1)
	}
	allowed, err := p.verdict(j.id, live && v.State == "allowed")
	outcome := daemon.VerdictDropped
	if err != nil {
		outcome = daemon.VerdictFailed
	} else if allowed {
		outcome = daemon.VerdictAccepted
	}
	p.record(v, outcome, err)
	return true
}
