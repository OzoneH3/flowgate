package socketgrant

import (
	"errors"
	"fmt"
	"testing"
	"time"
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

func TestConnectionGrantObservationLatencyDoesNotExpire(t *testing.T) {
	m := &memoryGate{values: map[Key]Value{}}
	s, err := NewConnection(m)
	if err != nil {
		t.Fatal(err)
	}
	n := uint64(1)
	s.now = func() uint64 { return n }
	ticket := s.Begin()
	n += uint64(30 * time.Second)
	k := Key{Cookie: 7}
	ok, err := s.Publish(ticket, k, 0)
	if err != nil || !ok || m.values[k].Deadline != 0 {
		t.Fatal("slow initial proof produced an ownership expiry", err, m.values)
	}
	if err = s.Revoke(); err != nil {
		t.Fatal(err)
	}
	if m.values[k].Generation == m.epoch {
		t.Fatal("policy revocation failed")
	}
	if ok, _ = s.Publish(ticket, k, 0); ok {
		t.Fatal("pre-policy ticket resurrected permission")
	}
	horizon := n + uint64(time.Second)
	if ok, err = s.Publish(s.Begin(), k, horizon); err != nil || !ok || m.values[k].Deadline != horizon {
		t.Fatal("temporary horizon lost")
	}
	n = horizon
	if ok, _ = s.Publish(s.Begin(), k, horizon); ok {
		t.Fatal("expired temporary rule granted")
	}
}

func TestConnectionEpochFailureDeletesBeforeConfirmingDisable(t *testing.T) {
	m := &memoryGate{values: map[Key]Value{}}
	b := RetainForSession(m)
	s, err := NewConnection(b)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Publish(s.Begin(), Key{Cookie: 1}, 0); err != nil || !ok {
		t.Fatal(err)
	}
	m.fail = true
	if err = s.Close(); err != nil {
		t.Fatal("known keys not cleared on epoch failure", err)
	}
	if len(m.values) != 0 {
		t.Fatal("permission remained")
	}
	if b.Put(Key{Cookie: 2}, Value{}) == nil {
		t.Fatal("closed session accepted publication")
	}
}

type brokenConnectionGate struct {
	memoryGate
	deleteFails, detachFails bool
	detached                 int
}

func (g *brokenConnectionGate) Delete(k Key) error {
	if g.deleteFails {
		return errors.New("delete failed")
	}
	return g.memoryGate.Delete(k)
}
func (g *brokenConnectionGate) EmergencyDisable() error {
	g.detached++
	if g.detachFails {
		return errors.New("detach failed")
	}
	g.values = map[Key]Value{}
	return nil
}
func TestConnectionRevocationFallbackAndUnconfirmedFailure(t *testing.T) {
	for _, detachFails := range []bool{false, true} {
		t.Run(fmt.Sprint(detachFails), func(t *testing.T) {
			g := &brokenConnectionGate{memoryGate: memoryGate{values: map[Key]Value{}}}
			s, err := NewConnection(RetainForSession(g))
			if err != nil {
				t.Fatal(err)
			}
			k := Key{Cookie: 5}
			if ok, err := s.Publish(s.Begin(), k, 0); err != nil || !ok {
				t.Fatal(err)
			}
			g.fail = true
			g.deleteFails = true
			g.detachFails = detachFails
			err = s.Close()
			if (err != nil) != detachFails || g.detached != 1 {
				t.Fatal("incorrect revocation acknowledgement", err)
			}
			if !detachFails && len(g.values) != 0 {
				t.Fatal("detached grant survived")
			}
			if ok, _ := s.Publish(s.Begin(), k, 0); ok {
				t.Fatal("failure reopened publication")
			}
		})
	}
}

func TestConnectionPolicyTicketsIndependentOfLiveKernelEpoch(t *testing.T) {
	m := &memoryGate{values: map[Key]Value{}}
	s, err := NewConnection(m)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Cookie: 1}
	old := s.Begin()
	if ok, err := s.Publish(old, key, 0); err != nil || !ok {
		t.Fatal(err)
	}
	before := m.values[key]
	epoch := m.epoch
	if err = s.InvalidateTickets(); err != nil {
		t.Fatal(err)
	}
	if m.epoch != epoch || m.values[key] != before {
		t.Fatal("ticket invalidation changed live authorization")
	}
	if ok, _ := s.Publish(old, Key{Cookie: 2}, 0); ok {
		t.Fatal("old policy observation published")
	}
	if ok, err := s.Publish(s.Begin(), Key{Cookie: 2}, 0); err != nil || !ok {
		t.Fatal(err)
	}
	if m.values[Key{Cookie: 2}].Generation != epoch {
		t.Fatal("new grant mismatches live epoch")
	}
	limit := BootNow() + uint64(time.Second)
	if err = s.Limit(key, limit); err != nil {
		t.Fatal(err)
	}
	if err = s.Limit(key, limit+uint64(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = s.Limit(key, 0); err != nil {
		t.Fatal(err)
	}
	if m.values[key].Deadline != limit {
		t.Fatal("policy re-evaluation lengthened permission")
	}
	if err = s.Limit(Key{Cookie: 3}, limit); err == nil {
		t.Fatal("limit created new permission")
	}
	if err = s.Revoke(); err != nil {
		t.Fatal(err)
	}
	if err = s.Limit(key, limit); err == nil {
		t.Fatal("limit resurrected old epoch")
	}
}

type retiringGate struct {
	memoryGate
	retired   map[uint32]bool
	retireErr error
}

func (g *retiringGate) RetireInterface(i uint32) error {
	if g.retireErr != nil {
		return g.retireErr
	}
	g.retired[i] = true
	return nil
}
func TestInterfaceRetirementPreservesOtherLifetimeGrants(t *testing.T) {
	g := &retiringGate{memoryGate: memoryGate{values: map[Key]Value{}}, retired: map[uint32]bool{}}
	s, err := NewConnection(RetainForSession(g))
	if err != nil {
		t.Fatal(err)
	}
	a, b := Key{Cookie: 1, Interface: 7}, Key{Cookie: 2, Interface: 8}
	ticket := s.Begin()
	for _, k := range []Key{a, b} {
		if ok, err := s.Publish(ticket, k, 0); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	before := g.values[b]
	if err = s.RetireInterface(7); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.values[a]; ok || g.values[b] != before || !g.retired[7] || g.retired[8] {
		t.Fatal("unrelated grant changed")
	}
	for _, ticket := range []Ticket{ticket, s.Begin()} {
		if ok, err := s.Publish(ticket, a, 0); ok || err != nil {
			t.Fatal("retired index reused", ok, err)
		}
	}
	b.Cookie = 3
	if ok, err := s.Publish(ticket, b, 0); !ok || err != nil {
		t.Fatal("unrelated in-flight ticket invalidated", ok, err)
	}
	if err = s.Revoke(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Publish(s.Begin(), a, 0); ok {
		t.Fatal("policy epoch resurrected retired interface")
	}
	fresh, err := NewConnection(&retiringGate{memoryGate: memoryGate{values: map[Key]Value{}}, retired: map[uint32]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := fresh.Publish(fresh.Begin(), a, 0); !ok || err != nil {
		t.Fatal("retirement leaked into next session", err)
	}
}
func TestInterfaceRetirementRequiresConfirmedKernelBarrier(t *testing.T) {
	g := &retiringGate{memoryGate: memoryGate{values: map[Key]Value{}}, retired: map[uint32]bool{}, retireErr: errors.New("epoch write failed")}
	s, err := NewConnection(g)
	if err != nil {
		t.Fatal(err)
	}
	if s.RetireInterface(7) == nil {
		t.Fatal("unconfirmed kernel barrier accepted")
	}
}
