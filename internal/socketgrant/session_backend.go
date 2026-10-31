package socketgrant

import (
	"errors"
	"sync"
)

// SessionBackend separates permission shutdown from resource destruction. The
// owning firewall session includes the installed rules in its exact digest;
// Engine.Close must not mutate those rules behind the session's audit. After
// verified owned-table cleanup the session calls Release to close the resources.
type SessionBackend struct {
	mu                          sync.Mutex
	backend                     Backend
	closing, disabled, released bool
}

func RetainForSession(b Backend) *SessionBackend { return &SessionBackend{backend: b} }
func (s *SessionBackend) Put(k Key, v Value) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errors.New("session gate closed")
	}
	return s.backend.Put(k, v)
}
func (s *SessionBackend) Delete(k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return errors.New("session gate released")
	}
	return s.backend.Delete(k)
}
func (s *SessionBackend) Epoch(n uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released || (s.closing && n != 0) {
		return errors.New("session gate closed")
	}
	return s.backend.Epoch(n)
}
func (s *SessionBackend) Stats(k Key) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return Stats{}, errors.New("session gate released")
	}
	return s.backend.Stats(k)
}
func (s *SessionBackend) Totals() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return Stats{}, errors.New("session gate released")
	}
	return s.backend.Totals()
}
func (s *SessionBackend) closeLocked() error {
	s.closing = true
	if s.disabled {
		return nil
	}
	if err := s.backend.Epoch(0); err != nil {
		return err
	}
	s.disabled = true
	return nil
}
func (s *SessionBackend) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.closeLocked() }

// Release is called by the table owner after its audit/cleanup phase. Failed
// cleanup remains retryable and no subsequent call can publish permission.
func (s *SessionBackend) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return nil
	}
	if err := s.closeLocked(); err != nil {
		return err
	}
	if err := s.backend.Close(); err != nil {
		return err
	}
	s.released = true
	return nil
}

// ReleaseAfterTableDeletion is used only after the owning firewall session has
// confirmed deletion. The routed backend independently verifies rule absence.
func (s *SessionBackend) ReleaseAfterTableDeletion() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	if s.released {
		return nil
	}
	releaser, ok := s.backend.(interface{ CloseAfterTableDeletion() error })
	if !ok {
		return errors.New("backend cannot verify removed rules")
	}
	if err := releaser.CloseAfterTableDeletion(); err != nil {
		return err
	}
	s.disabled = true
	s.released = true
	return nil
}

// CloseAfterGrantDeletion is called only by Store after every owned grant key
// was positively deleted. Resource release remains the firewall session owner's
// responsibility. No audited rule changes and no further publication are allowed.
func (s *SessionBackend) CloseAfterGrantDeletion() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	s.disabled = true
	return nil
}

// EmergencyDisable bypasses a broken epoch/map write only by positively
// removing the exact owned accelerator references. A failed detach is explicit.
func (s *SessionBackend) EmergencyDisable() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	emergency, ok := s.backend.(interface{ EmergencyDisable() error })
	if !ok {
		return errors.New("kernel revocation unconfirmed: backend cannot detach accelerator")
	}
	if err := emergency.EmergencyDisable(); err != nil {
		return err
	}
	s.disabled = true
	return nil
}
