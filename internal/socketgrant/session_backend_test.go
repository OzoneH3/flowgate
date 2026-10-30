package socketgrant

import (
	"errors"
	"testing"
)

func TestSessionBackendPreservesAuditedRulesUntilOwnerRelease(t *testing.T) {
	b := &cleanupGate{memoryGate: memoryGate{values: map[Key]Value{}}}
	session := RetainForSession(b)
	store, err := New(session)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if b.epoch != 0 || b.closeCalls != 0 {
		t.Fatal("engine shutdown mutated audited resources", b)
	}
	if err = session.Put(Key{Cookie: 1}, Value{Generation: 1}); err == nil {
		t.Fatal("disabled session published")
	}
	if err = session.Epoch(2); err == nil {
		t.Fatal("disabled session re-enabled")
	}
	if err = session.Release(); err == nil || b.closeCalls != 1 {
		t.Fatal("cleanup error hidden", err)
	}
	if err = session.Release(); err != nil || b.closeCalls != 2 {
		t.Fatal("cleanup not retried", err)
	}
	if err = session.Release(); err != nil || b.closeCalls != 2 {
		t.Fatal("cleanup not idempotent", err)
	}
}
func TestSessionDisableFailureStillBlocksPublish(t *testing.T) {
	b := &memoryGate{values: map[Key]Value{}, epoch: 1, fail: true}
	session := RetainForSession(b)
	if session.Close() == nil {
		t.Fatal("epoch failure hidden")
	}
	if session.Put(Key{Cookie: 1}, Value{}) == nil || session.Epoch(2) == nil {
		t.Fatal("closing session still grants")
	}
	b.fail = false
	if err := session.Close(); err != nil || b.epoch != 0 {
		t.Fatal("disable not retried", err)
	}
}

type removedRuleGate struct {
	memoryGate
	absent       bool
	releaseCalls int
}

func (g *removedRuleGate) CloseAfterTableDeletion() error {
	g.releaseCalls++
	if !g.absent {
		return errors.New("rule still present")
	}
	return nil
}
func TestSessionReleaseAfterDeletionRequiresBackendAbsenceProof(t *testing.T) {
	b := &removedRuleGate{memoryGate: memoryGate{values: map[Key]Value{}, fail: true}}
	s := RetainForSession(b)
	if s.Close() == nil {
		t.Fatal("expected epoch failure")
	}
	if s.ReleaseAfterTableDeletion() == nil {
		t.Fatal("released live rule")
	}
	if s.Put(Key{}, Value{}) == nil || s.Epoch(1) == nil {
		t.Fatal("failed release reopened grants")
	}
	b.absent = true
	if err := s.ReleaseAfterTableDeletion(); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseAfterTableDeletion(); err != nil || b.releaseCalls != 2 {
		t.Fatal("release not idempotent", err, b.releaseCalls)
	}
	if s.Epoch(0) == nil {
		t.Fatal("used released backend")
	}
}
func TestSessionReleaseAfterDeletionRejectsUnverifiableBackend(t *testing.T) {
	s := RetainForSession(&memoryGate{values: map[Key]Value{}})
	if s.ReleaseAfterTableDeletion() == nil {
		t.Fatal("accepted unsupported absence proof")
	}
	if s.Put(Key{}, Value{}) == nil {
		t.Fatal("failed release reopened grants")
	}
}
