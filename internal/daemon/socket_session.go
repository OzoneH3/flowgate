package daemon

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
)

// SocketInterface identifies a link for presentation, not authorization.
type SocketInterface struct {
	Index uint32 `json:"index"`
	Name  string `json:"name"`
}

// SocketInterfaceCoverage is a bounded snapshot from session activation.
// New interfaces remain queue-only until the next protection session.
type SocketInterfaceCoverage struct {
	Installed          []SocketInterface `json:"installed"`
	QueueOnly          []SocketInterface `json:"queue_only"`
	QueueOnlyTotal     int               `json:"queue_only_total"`
	QueueOnlyTruncated bool              `json:"queue_only_truncated"`
	Retired            []SocketInterface `json:"retired,omitempty"`
	Maximum            int               `json:"maximum"`
}

// SocketSessionResolvers are trusted in-process resolvers, never API input.
type SocketSessionResolvers struct {
	Fresh             func(identity.Flow) identity.Attribution
	Observed          func(identity.Flow) (identity.Attribution, uint64)
	Group             func([]identity.Flow, func(int, *identity.Attribution))
	Diagnostics       func() map[string]any
	InterfaceCoverage *SocketInterfaceCoverage
}

// StartSessionSocketAuthorization is only called by the protection-session
// owner after queue binding and route-gate installation. It does not install
// firewall rules. The session retains actual resource cleanup ownership.
func (e *Engine) StartSessionSocketAuthorization(ctx context.Context, b *socketgrant.SessionBackend, r SocketSessionResolvers) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Mode != "daemon-monitor" || e.ZoneSource == nil || !e.zonePublisherInstalled || b == nil || r.Fresh == nil || r.Observed == nil || e.socketAuthorization != nil {
		return errors.New("session authorization requires daemon, zone publication transaction, routed backend and fresh resolvers")
	}
	if err := e.startSocketAuthorizationLocked(ctx, b, r.Fresh, true, r.Diagnostics); err != nil {
		return err
	}
	s := e.socketAuthorization
	s.productionSession = true
	s.routeBound = true
	if r.InterfaceCoverage != nil {
		coverage := *r.InterfaceCoverage
		coverage.Installed = append([]SocketInterface(nil), coverage.Installed...)
		coverage.QueueOnly = append([]SocketInterface(nil), coverage.QueueOnly...)
		coverage.Retired = append([]SocketInterface(nil), coverage.Retired...)
		s.interfaceCoverage = &coverage
	}
	s.batchCoordination = !s.connectionScoped
	s.ordinaryObserved = r.Observed
	s.resolveGroup = r.Group
	return nil
}

// DisableSocketAuthorization does not mutate audited firewall rules when used
// with a SessionBackend. It prevents every new publication before revoking.
func (e *Engine) DisableSocketAuthorization(reason error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.socketAuthorization
	if s == nil {
		return nil
	}
	s.disabled = true
	if reason == nil {
		reason = errors.New("acceleration disabled for this protection session")
	}
	s.failure = reason
	if err := s.store.Close(); err != nil {
		s.failure = fmt.Errorf("KERNEL REVOCATION UNCONFIRMED: %v; disabling epoch: %w", reason, err)
		s.revocationUnconfirmed = s.connectionScoped
		return s.failure
	}
	return nil
}

// StopSocketAuthorization joins the scheduler and observations before the owner
// releases its backend. A later session gets new maps, tickets and flow state.
func (e *Engine) StopSocketAuthorization() error {
	err := e.DisableSocketAuthorization(errors.New("protection session stopped"))
	e.mu.Lock()
	s := e.socketAuthorization
	if s == nil {
		e.mu.Unlock()
		return err
	}
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	jobs := s.jobs
	e.mu.Unlock()
	if done != nil {
		<-done
	}
	if jobs != nil {
		jobs.Wait()
	}
	e.mu.Lock()
	if e.socketAuthorization == s {
		e.socketAuthorization = nil
	}
	e.mu.Unlock()
	return err
}

// RetireSocketInterface preserves all unrelated grants. It mutates maps only,
// never the session's audited firewall rules or application policy.
func (e *Engine) RetireSocketInterface(index uint32, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.socketAuthorization
	if s == nil || s.disabled {
		return nil
	}
	if err := s.store.RetireInterface(index); err != nil {
		e.failConnectionAuthorizationLocked(s, fmt.Errorf("retire interface %d: %w", index, err))
		return s.failure
	}
	if s.retiredInterfaces == nil {
		s.retiredInterfaces = map[uint32]string{}
	}
	if reason == "" {
		reason = "interface retired"
	}
	s.retiredInterfaces[index] = reason
	for key, f := range s.flows {
		outdev, ok := f.flow.QueueOutputInterface()
		if (ok && outdev == index) || (f.haveKey && f.key.Interface == index) {
			f.haveKey = false
			f.completeObservationWait()
			s.completeSocketBatchLocked(f, nil, false)
			delete(s.flows, key)
		}
	}
	if c := s.interfaceCoverage; c != nil {
		kept := c.Installed[:0]
		for _, link := range c.Installed {
			if link.Index == index {
				c.Retired = append(c.Retired, link)
			} else {
				kept = append(kept, link)
			}
		}
		c.Installed = kept
	}
	return nil
}

func (c *SocketInterfaceCoverage) clone() *SocketInterfaceCoverage {
	v := *c
	v.Installed = append([]SocketInterface(nil), c.Installed...)
	v.QueueOnly = append([]SocketInterface(nil), c.QueueOnly...)
	v.Retired = append([]SocketInterface(nil), c.Retired...)
	return &v
}
