package socketgrant

import (
	"errors"
	"testing"
)

type memoryGate struct {
	values map[Key]Value
	epoch  uint64
	fail   bool
}

func (m *memoryGate) Put(k Key, v Value) error { m.values[k] = v; return nil }
func (m *memoryGate) Delete(k Key) error       { delete(m.values, k); return nil }
func (m *memoryGate) Epoch(n uint64) error {
	if m.fail {
		return errors.New("injected epoch failure")
	}
	m.epoch = n
	return nil
}
func (m *memoryGate) Close() error             { return nil }
func (m *memoryGate) Stats(Key) (Stats, error) { return Stats{}, nil }
func (m *memoryGate) Totals() (Stats, error)   { return Stats{}, nil }
func (m *memoryGate) matches(k Key, now uint64) bool {
	v, ok := m.values[k]
	return ok && m.epoch != 0 && v.Generation == m.epoch && now < v.Deadline
}
func model(t *testing.T) (*Store, *memoryGate, *uint64) {
	t.Helper()
	m := &memoryGate{values: map[Key]Value{}}
	s, err := New(m)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(1)
	s.now = func() uint64 { return now }
	return s, m, &now
}
func TestHardDeadlineStartsBeforeVerification(t *testing.T) {
	s, m, n := model(t)
	ticket := s.Begin()
	k := Key{Cookie: 1}
	*n += 100000000
	ok, err := s.Publish(ticket, k, 0)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if m.values[k].Deadline != 250000001 {
		t.Fatal(m.values[k])
	}
	for *n < 250000001 {
		*n += 1000000
		_ = m.matches(k, *n)
	}
	if m.matches(k, *n) {
		t.Fatal("hits extended expiry")
	}
	if ok, _ = s.Publish(ticket, k, 0); ok {
		t.Fatal("late verification republished expired evidence")
	}
}
func TestPolicyEditDuringVerificationAndExpiry(t *testing.T) {
	s, m, n := model(t)
	ticket := s.Begin()
	k := Key{Cookie: 1}
	if err := s.Revoke(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Publish(ticket, k, 0); ok {
		t.Fatal("old policy ticket published")
	}
	ticket = s.Begin()
	if ok, err := s.Publish(ticket, k, *n+100); !ok || err != nil {
		t.Fatal(ok, err)
	}
	*n += 100
	if m.matches(k, *n) {
		t.Fatal("rule expiry ignored")
	}
}
func TestRevocationFailureNotAcknowledged(t *testing.T) {
	s, m, _ := model(t)
	m.fail = true
	if s.Revoke() == nil {
		t.Fatal("failed kernel write acknowledged")
	}
	if s.Close() == nil {
		t.Fatal("failed disable acknowledged")
	}
}
func TestSocketAndDestinationSeparationAndBound(t *testing.T) {
	s, m, n := model(t)
	k := Key{Cookie: 1, DestinationPort: [2]byte{1, 1}}
	if ok, err := s.Publish(s.Begin(), k, 0); !ok || err != nil {
		t.Fatal(ok, err)
	}
	other := k
	other.Cookie = 2
	if m.matches(other, *n) {
		t.Fatal("replacement inherited grant")
	}
	other = k
	other.DestinationPort[1]++
	if m.matches(other, *n) {
		t.Fatal("other destination inherited grant")
	}
	for i := 2; i <= MaxEntries; i++ {
		if ok, err := s.Publish(s.Begin(), Key{Cookie: uint64(i)}, 0); !ok || err != nil {
			t.Fatal(i, ok, err)
		}
	}
	if ok, _ := s.Publish(s.Begin(), Key{Cookie: 1000}, 0); ok {
		t.Fatal("unbounded map")
	}
	if err := s.Forget(k); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Publish(s.Begin(), Key{Cookie: 1000}, 0); !ok {
		t.Fatal("deleted capacity not reusable")
	}
}

type cleanupGate struct {
	memoryGate
	closeCalls int
}

func (m *cleanupGate) Close() error {
	m.closeCalls++
	if m.closeCalls == 1 {
		return errors.New("owned rule removal failed")
	}
	return nil
}
func TestCloseRetriesCleanupWithoutReenablingAuthorization(t *testing.T) {
	b := &cleanupGate{memoryGate: memoryGate{values: map[Key]Value{}}}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	before := s.Begin()
	if s.Close() == nil || b.epoch != 0 {
		t.Fatal("failed cleanup or revocation hidden")
	}
	for _, ticket := range []Ticket{before, s.Begin()} {
		if ok, err := s.Publish(ticket, Key{Cookie: 1}, 0); ok || err != nil {
			t.Fatalf("closed grant published: %v %v", ok, err)
		}
	}
	if err := s.Close(); err != nil || b.closeCalls != 2 || b.epoch != 0 {
		t.Fatal("cleanup not retried")
	}
	if err := s.Close(); err != nil || b.closeCalls != 2 {
		t.Fatal("successful cleanup not idempotent")
	}
}

func TestCloseFailedEpochPreventsNewPublicationAndRetries(t *testing.T) {
	s, b, _ := model(t)
	ticket := s.Begin()
	b.fail = true
	if s.Close() == nil {
		t.Fatal("epoch failure hidden")
	}
	b.fail = false
	if s.Revoke() == nil {
		t.Fatal("revoke enabled closing gate")
	}
	if ok, err := s.Publish(ticket, Key{Cookie: 2}, 0); ok || err != nil {
		t.Fatal("publication after attempted close")
	}
	if err := s.Close(); err != nil || b.epoch != 0 {
		t.Fatal("failed epoch not retried")
	}
}
