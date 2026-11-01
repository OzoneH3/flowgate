package udpaccount

import (
	"flowgate/internal/identity"
	"fmt"
	"testing"
	"time"
)

func TestFinalSnapshotsConsumeOnceAndBounded(t *testing.T) {
	s := &session{state: identity.UDPSnapshot{Collected: time.Now()}}
	first := map[string]identity.UDPCount{"one": {Uploaded: 24}}
	s.publishSnapshot(identity.UDPSnapshot{Collected: time.Now()}, first)
	if len(s.snapshot().Retired) != 1 || len(s.snapshot().Retired) != 1 {
		t.Fatal("status consumed final")
	}
	if s.accountingSnapshot().Retired["one"].Uploaded != 24 || len(s.accountingSnapshot().Retired) != 0 {
		t.Fatal("consume not exactly once")
	}
	s.publishSnapshot(identity.UDPSnapshot{Collected: time.Now()}, map[string]identity.UDPCount{"two": {Uploaded: 12}})
	if _, replayed := s.accountingSnapshot().Retired["one"]; replayed {
		t.Fatal("old consumed final resurrected")
	}
	many := map[string]identity.UDPCount{}
	for i := 0; i < 2050; i++ {
		many[fmt.Sprint(i)] = identity.UDPCount{Uploaded: 1}
	}
	s.publishSnapshot(identity.UDPSnapshot{Collected: time.Now()}, many)
	v := s.accountingSnapshot()
	if len(v.Retired) != 2048 || v.FinalsLost != 2 {
		t.Fatal("overflow hidden or unbounded", len(v.Retired), v.FinalsLost)
	}
}
