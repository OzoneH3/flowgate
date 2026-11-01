package daemon

import (
	"flowgate/internal/identity"
	"time"
)

// SocketQueueHandoff tracks only packet lifetime, never permission. The queue
// installs one instance before activating the production socket gate.
// A sequence fence covers packets already enqueued but not yet delivered to
// userspace. Packets crossing the hook between the fence and publication remain
// a residual race; this is not a transport ordering guarantee.
type SocketQueueHandoff struct {
	failure                         string
	fenceReads, fenceNS, fenceMaxNS uint64
	engine                          *Engine
	fence                           func() (uint32, bool)
	received                        uint32
	haveReceived                    bool
	jobs                            map[uint32]string
	pending                         map[string]int
	failed                          bool
}

func (e *Engine) StartSocketQueueHandoff(fence func() (uint32, bool)) *SocketQueueHandoff {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := &SocketQueueHandoff{engine: e, fence: fence, jobs: map[uint32]string{}, pending: map[string]int{}}
	e.socketQueueHandoff = h
	return h
}
func (h *SocketQueueHandoff) Close() {
	if h == nil {
		return
	}
	e := h.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketQueueHandoff == h {
		e.socketQueueHandoff = nil
	}
}

// Received is called once for every packet, after parsing and before dispatch.
// High-water and the pending job become visible under the same policy lock.
func (h *SocketQueueHandoff) Received(id uint32, flow identity.Flow) {
	if h == nil {
		return
	}
	e := h.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketQueueHandoff != h {
		return
	}
	h.received = id
	h.haveReceived = true
	if flow.Protocol != "udp" || flow.Direction != "outgoing" {
		return
	}
	if len(h.jobs) >= 4096 {
		h.failed = true
		h.failure = "queue pending registry exhausted or duplicate packet id"
		return
	}
	if _, duplicate := h.jobs[id]; duplicate {
		h.failed = true
		h.failure = "queue pending registry exhausted or duplicate packet id"
		return
	}
	key := flow.Key()
	h.jobs[id] = key
	h.pending[key]++
}

// Verdicted runs only after the final kernel write returns. An unsuccessful
// write cannot complete the handoff; normal fail-closed recovery still owns it.
func (h *SocketQueueHandoff) Verdicted(id uint32, success bool) {
	if h == nil {
		return
	}
	e := h.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socketQueueHandoff != h {
		return
	}
	key, ok := h.jobs[id]
	if !ok {
		return
	}
	delete(h.jobs, id)
	h.pending[key]--
	if h.pending[key] == 0 {
		delete(h.pending, key)
	}
	if !success {
		h.failed = true
		h.failure = "kernel verdict write failed"
		return
	}
	s := e.socketAuthorization
	if s == nil || s.disabled || s.failure != nil {
		return
	}
	for _, f := range s.flows {
		if f.flow.Key() != key || f.haveKey || f.deferredGrant == nil {
			continue
		}
		d := f.deferredGrant
		e.finishSocketAuthorizationLocked(s, f, d.ticket, d.attribution)
	}
}
func (e *Engine) socketHandoffReadyLocked(s *socketAuthorization, f *socketFlow) bool {
	h := e.socketQueueHandoff
	if h == nil || h.failed || !h.haveReceived || h.pending[f.flow.Key()] != 0 || h.fence == nil {
		return false
	}
	started := time.Now()
	sequence, ok := h.fence()
	elapsed := uint64(time.Since(started))
	h.fenceReads++
	h.fenceNS += elapsed
	if elapsed > h.fenceMaxNS {
		h.fenceMaxNS = elapsed
	}
	// Queue IDs wrap. Equality is conservative and does not infer unseen packets.
	return ok && h.received == sequence
}

func (e *Engine) socketHandoffStatusLocked(out map[string]any, s *socketAuthorization) {
	deferred := 0
	for _, f := range s.flows {
		if f.deferredGrant != nil {
			deferred++
		}
	}
	out["deferred_grants"] = deferred
	if h := e.socketQueueHandoff; h != nil {
		out["handoff_failed"] = h.failed
		out["handoff_failure"] = h.failure
		out["handoff_fence_reads"] = h.fenceReads
		out["handoff_fence_ns"] = h.fenceNS
		out["handoff_fence_max_ns"] = h.fenceMaxNS
	}
}
