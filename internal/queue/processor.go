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
	ctx     context.Context
	observe func(identity.Flow, string) daemon.Event
	retain  func(uint32, int, daemon.Event) bool
	record  func(daemon.Event, string, error)
	verdict func(uint32, bool) (bool, error)
	expired *atomic.Uint64
}

func (p *packetProcessor) process(j packetJob, stopping bool) {
	if stopping || p.ctx.Err() != nil || !time.Now().Before(j.deadline) {
		p.expired.Add(1)
		p.verdict(j.id, false)
		return
	}
	// Observe resolves fresh ownership, then evaluates current policy. Never
	// pre-resolve a queued job: its socket may have been replaced while waiting.
	v := p.observe(j.flow, j.token)
	live := p.ctx.Err() == nil && time.Now().Before(j.deadline) && time.Now().Before(v.Deadline)
	if live && v.State == "awaiting-decision" && p.retain(j.id, j.size, v) {
		p.record(v, daemon.VerdictHeld, nil)
		return
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
}
