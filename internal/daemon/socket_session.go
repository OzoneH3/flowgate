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
	if err := e.startSocketAuthorizationLocked(ctx, b, r.Fresh, r.Diagnostics); err != nil {
		return err
	}
	s := e.socketAuthorization
	s.productionSession = true
	s.routeBound = true
	if r.InterfaceCoverage != nil {
		coverage := *r.InterfaceCoverage
		coverage.Installed = append([]SocketInterface(nil), coverage.Installed...)
		coverage.QueueOnly = append([]SocketInterface(nil), coverage.QueueOnly...)
		s.interfaceCoverage = &coverage
	}
	s.batchCoordination = true
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
		s.failure = fmt.Errorf("%v; disabling epoch: %w", reason, err)
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
