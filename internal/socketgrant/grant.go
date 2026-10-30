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
	mu          sync.Mutex
	backend     Backend
	generation  uint64
	now         func() uint64
	entries     map[Key]struct{}
	closed      bool
	cleanupDone bool
	closing     bool
}

func New(b Backend) (*Store, error) {
	if err := b.Epoch(1); err != nil {
		return nil, err
	}
	return &Store{backend: b, generation: 1, now: BootNow, entries: make(map[Key]struct{})}, nil
}
func (s *Store) Begin() Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Ticket{s.now(), s.generation}
}

// Publish is called only after successful fresh identity and current policy
// evaluation, under the engine's policy mutex. horizon is an earlier rule expiry
// in the same BOOTTIME domain, or zero for no earlier expiry.
func (s *Store) Publish(t Ticket, k Key, horizon uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.closing || s.closed || t.start == 0 || t.generation != s.generation || now < t.start ||
		t.start > ^uint64(0)-uint64(Window) {
		return false, nil
	}
	deadline := t.start + uint64(Window)
	if horizon != 0 && horizon < deadline {
		deadline = horizon
	}
	if now >= deadline {
		return false, nil
	}
	if _, exists := s.entries[k]; !exists && len(s.entries) >= MaxEntries {
		return false, nil
	}
	if err := s.backend.Put(k, Value{deadline, s.generation}); err != nil {
		return false, err
	}
	s.entries[k] = struct{}{}
	return true, nil
}
func (s *Store) Forget(k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.backend.Delete(k); err != nil {
		return err
	}
	delete(s.entries, k)
	return nil
}
func (s *Store) Revoke() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.closed {
		return errors.New("socket gate closed")
	}
	if s.generation == ^uint64(0) {
		return errors.New("socket gate generation exhausted")
	}
	next := s.generation + 1
	// Do not acknowledge revocation if the packet-path generation write fails.
	if err := s.backend.Epoch(next); err != nil {
		return err
	}
	s.generation = next
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
			return err
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
