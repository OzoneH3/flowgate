package hostfirewall

import (
	"context"
	"errors"
	"flowgate/internal/socketgrant"
	"time"
)

// SocketSessionResources belongs to one exact protection session. Stop must
// join observations and disable permission without changing audited rules.
// ReleaseAfterTableDeletion must independently confirm its rules are absent.
// Failed cleanup stays attached to Evaluation for explicit cleanup retries.
type SocketSessionResources interface {
	Disable() error
	Stop() error
	ReleaseAfterTableDeletion() error
}

func (m *Evaluation) stopSocketSession() error {
	m.mu.Lock()
	s := m.socketSession
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	return s.Stop()
}

func (m *Evaluation) releaseSocketSession() error {
	m.mu.Lock()
	s := m.socketSession
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	if err := s.ReleaseAfterTableDeletion(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.socketSession == s {
		m.socketSession = nil
	}
	m.mu.Unlock()
	return nil
}

// SocketSessionFactory is trusted startup wiring, not an API option. On any
// partial installation it must return the cleanup owner even alongside an error.
// Rules may only be installed into the supplied, already-owned regular chain.
type SocketSessionFactory func(context.Context, string, string) (SocketSessionResources, error)

func (m *Evaluation) ConfigureSocketSession(factory SocketSessionFactory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil || m.socketSession != nil || m.status.Cleanup == "unconfirmed" {
		return errors.New("socket session configuration requires stopped protection")
	}
	m.socketFactory = factory
	return nil
}

func (m *Evaluation) prepareSocketSession(ctx context.Context) error {
	m.mu.Lock()
	factory := m.socketFactory
	m.mu.Unlock()
	if factory == nil {
		return nil
	}
	owner, err := factory(ctx, Table, "socket_output")
	m.mu.Lock()
	m.socketSession = owner
	m.mu.Unlock()
	if err == nil && owner == nil {
		err = errors.New("socket session factory returned no owner")
	}
	if err == nil {
		return nil
	}
	// Acceleration is optional. Keep partial rules in the final audited table,
	// stop all publishers and continue queue protection with a retained failure.
	if owner != nil {
		if stopErr := owner.Stop(); stopErr != nil {
			err = errors.Join(err, stopErr)
			// Stop has joined publishers. Even a failed epoch write cannot leave a
			// grant beyond its fixed hard window; wait before removing startup guard.
			timer := time.NewTimer(socketgrant.Window)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	m.mu.Lock()
	m.socketFailure = err
	m.mu.Unlock()
	return nil
}

func (m *Evaluation) SocketSessionFailure() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socketFailure
}
