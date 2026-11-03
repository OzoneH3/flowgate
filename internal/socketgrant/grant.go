// Package socketgrant contains the isolated socket-authorization prototype.
// It is not enabled by ordinary host startup.
package socketgrant

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flowgate/internal/identity"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const Window = 250 * time.Millisecond
const MaxEntries = 64

// Key matches the kernel ABI. Address/port fields contain network-order bytes.
// Namespace and direction are fixed by the private gate instance, not a hint.
type Key struct {
	Cookie                      uint64
	Source, Destination         [4]byte
	SourcePort, DestinationPort [2]byte
	Interface                   uint32
}
type Value struct{ Deadline, Generation uint64 }
type Stats struct{ Packets, Bytes, LastSeen uint64 }
type Backend interface {
	Put(Key, Value) error
	Delete(Key) error
	Epoch(uint64) error
	Stats(Key) (Stats, error)
	Totals() (Stats, error)
	Close() error
}

func BootNow() uint64 {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t); err != nil {
		panic(err)
	}
	return uint64(t.Nano())
}

// KeyFor only projects already-verified evidence; it cannot establish identity.
func KeyFor(f identity.Flow, a identity.Attribution) (Key, bool) {
	var k Key
	if f.Protocol != "udp" || f.Direction != "outgoing" || f.NetNS != identity.NetNS() ||
		!f.Local.Addr().Is4() || !f.Remote.Addr().Is4() ||
		f.Local.Port() == 0 || f.Remote.Port() == 0 || !a.VisibilityComplete ||
		a.Application == nil || a.Application.Key == "" || a.Application.Revision == "" ||
		a.Principal() == nil || a.Fingerprint == "" || len(a.Sockets) != 1 {
		return k, false
	}
	if a.Status != "directly-associated" && a.Status != "corroborated-runtime-table" {
		return k, false
	}
	if a.Application.Kind == "wine" && (a.Table == nil || a.Status != "corroborated-runtime-table") {
		return k, false
	}
	s := a.Sockets[0]
	if s.NetNS != f.NetNS || s.Inode == 0 || s.Protocol != "udp" || s.Local.Port() != f.Local.Port() ||
		(!s.Local.Addr().IsUnspecified() && s.Local.Addr().Unmap() != f.Local.Addr()) ||
		(s.Remote.Port() != 0 && s.Remote != f.Remote) {
		return k, false
	}
	uid := a.Principal().UID
	if a.Application.Key != identity.ApplicationKey(uid, *a.Application) || identity.RuntimeRuleBlocked(a.Application) != "" {
		return k, false
	}
	switch a.Application.Kind {
	case "wine":
		if !filepath.IsAbs(a.Application.Prefix) || a.Table.Prefix != a.Application.Prefix ||
			a.Table.SocketCookie != s.Cookie || a.Table.UID != uid || a.Table.Generation == "" || len(a.Table.Owners) != 1 {
			return k, false
		}
	case "native":
		if a.Status != "directly-associated" || len(a.Owners) != 1 {
			return k, false
		}
	default:
		return k, false
	}
	cookie, err := hex.DecodeString(s.Cookie)
	if err != nil || len(cookie) != 8 {
		return k, false
	}
	k.Cookie = binary.NativeEndian.Uint64(cookie)
	if k.Cookie == 0 || k.Cookie == ^uint64(0) {
		return Key{}, false
	}
	k.Source = f.Local.Addr().As4()
	k.Destination = f.Remote.Addr().As4()
	binary.BigEndian.PutUint16(k.SourcePort[:], f.Local.Port())
	binary.BigEndian.PutUint16(k.DestinationPort[:], f.Remote.Port())
	return k, true
}

func (s *Store) Stats(k Key) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Stats{}, errors.New("gate closed")
	}
	return s.backend.Stats(k)
}
func (s *Store) Totals() (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Stats{}, errors.New("gate closed")
	}
	return s.backend.Totals()
}

// Ticket anchors a grant to the beginning of a new full observation. No API
// deserializer creates tickets. A policy edit invalidates outstanding tickets.
type Ticket struct{ start, generation uint64 }

func (t Ticket) Start() uint64 { return t.start }

func (t Ticket) Deadline() uint64 { return t.start + uint64(Window) }

type Store struct {
	mu                sync.Mutex
	backend           Backend
	generation        uint64
	policyGeneration  uint64
	now               func() uint64
	entries           map[Key]Value
	retiredInterfaces map[uint32]bool
	closed            bool
	cleanupDone       bool
	closing           bool
	connection        bool
}

func New(b Backend) (*Store, error) {
	if err := b.Epoch(1); err != nil {
		return nil, err
	}
	return &Store{backend: b, generation: 1, policyGeneration: 1, now: BootNow, entries: make(map[Key]Value)}, nil
}

// NewConnection retains a verified connection until explicit revocation, closure
// or its allowing rule's horizon. Observation latency never supplies an expiry.
func NewConnection(b Backend) (*Store, error) {
	s, err := New(b)
	if err == nil {
		s.connection = true
	}
	return s, err
}

func (s *Store) Begin() Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Ticket{s.now(), s.policyGeneration}
}

// Publish is called only after successful fresh identity and current policy
// evaluation, under the engine's policy mutex. horizon is an earlier rule expiry
// in the same BOOTTIME domain, or zero for no earlier expiry.
func (s *Store) Publish(t Ticket, k Key, horizon uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.closing || s.closed || s.retiredInterfaces[k.Interface] || t.start == 0 || t.generation != s.policyGeneration || now < t.start ||
		t.start > ^uint64(0)-uint64(Window) {
		return false, nil
	}
	deadline := t.start + uint64(Window)
	if s.connection {
		deadline = 0
	}
	if horizon != 0 && (deadline == 0 || horizon < deadline) {
		deadline = horizon
	}
	if deadline != 0 && now >= deadline {
		return false, nil
	}
	if _, exists := s.entries[k]; !exists && len(s.entries) >= MaxEntries {
		return false, nil
	}
	if err := s.backend.Put(k, Value{deadline, s.generation}); err != nil {
		return false, err
	}
	s.entries[k] = Value{deadline, s.generation}
	return true, nil
}

// InvalidateTickets rejects observations begun under the preceding policy.
// Existing kernel entries and their permission horizons are unchanged.
func (s *Store) InvalidateTickets() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connection || s.closing || s.closed || s.policyGeneration == ^uint64(0) {
		return errors.New("cannot invalidate connection tickets")
	}
	s.policyGeneration++
	return nil
}

// Limit only shortens an EXISTING connection permission; it cannot create a
// grant, resurrect an old epoch, or extend its original allowing horizon.
func (s *Store) Limit(k Key, horizon uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, exists := s.entries[k]
	if !s.connection || s.closing || s.closed || !exists || value.Generation != s.generation {
		return errors.New("connection permission absent")
	}
	if horizon == 0 || (value.Deadline != 0 && value.Deadline <= horizon) {
		return nil
	}
	value.Deadline = horizon
	if err := s.backend.Put(k, value); err != nil {
		return err
	}
	s.entries[k] = value
	return nil
}

func (s *Store) Forget(k Key) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if err := s.backend.Delete(k); err != nil {
		connection := s.connection
		s.mu.Unlock()
		if connection {
			return errors.Join(err, s.Close())
		}
		return err
	}
	delete(s.entries, k)
	s.mu.Unlock()
	return nil
}

func (s *Store) Revoke() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.closed {
		return errors.New("socket gate closed")
	}
	if s.generation == ^uint64(0) || s.policyGeneration == ^uint64(0) {
		return errors.New("socket gate generation exhausted")
	}
	next := s.generation + 1
	// Do not acknowledge revocation if the packet-path generation write fails.
	if err := s.backend.Epoch(next); err != nil {
		return err
	}
	s.generation = next
	s.policyGeneration++
	// Keep the bounded key set: epoch revocation alone doesn't remove map slots.
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	if s.cleanupDone {
		return nil
	}
	if !s.closed {
		if err := s.backend.Epoch(0); err != nil {
			// A lifetime grant has no ownership timeout to rescue revocation.
			// Delete every owned key when the epoch write fails. The session
			// wrapper then blocks further writes without mutating audited rules.
			if !s.connection {
				return err
			}
			for k := range s.entries {
				if deleteErr := s.backend.Delete(k); deleteErr != nil {
					return s.emergencyCloseLocked(errors.Join(err, deleteErr))
				}
				delete(s.entries, k)
			}
			closer, ok := s.backend.(interface{ CloseAfterGrantDeletion() error })
			if !ok {
				return err
			}
			if closeErr := closer.CloseAfterGrantDeletion(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
			s.closed = true
			s.cleanupDone = true
			return nil
		}
		s.closed = true
	}
	// Permission remains disabled after epoch0 even when resource cleanup fails.
	// Retry cleanup on the next Close instead of hiding a leaked owned rule.
	if err := s.backend.Close(); err != nil {
		return err
	}
	s.cleanupDone = true
	return nil
}

// Emergency detachment is the last resort when both map revocation paths fail.
// It removes only exact owned accelerator rules; the session audit must report
// the resulting change rather than claiming its original digest still matches.
func (s *Store) emergencyCloseLocked(cause error) error {
	emergency, ok := s.backend.(interface{ EmergencyDisable() error })
	if !ok {
		return cause
	}
	if err := emergency.EmergencyDisable(); err != nil {
		return errors.Join(cause, err)
	}
	s.closed = true
	s.cleanupDone = true
	return nil
}

// RetireInterface first confirms a kernel instance disable, then removes only
// its grants. Tombstones reject both old tickets and future publications.
// Unrelated connection grants, horizons and tickets remain unchanged.
func (s *Store) RetireInterface(index uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index == 0 || s.closing || s.closed {
		return errors.New("cannot retire interface")
	}
	if s.retiredInterfaces[index] {
		return nil
	}
	r, ok := s.backend.(interface{ RetireInterface(uint32) error })
	if !ok {
		return errors.New("backend cannot retire one interface")
	}
	if err := r.RetireInterface(index); err != nil {
		return err
	}
	if s.retiredInterfaces == nil {
		s.retiredInterfaces = map[uint32]bool{}
	}
	s.retiredInterfaces[index] = true
	for k := range s.entries {
		if k.Interface == index {
			if err := s.backend.Delete(k); err != nil {
				return err
			}
			delete(s.entries, k)
		}
	}
	return nil
}
