package accounting

import (
	"bytes"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"strings"
	"testing"
	"time"
)

func rawUDP(seq, up uint64) identity.ActivitySnapshot {
	s := udp(seq, up, "collector")
	zero := uint64(0)
	s.UDP.TracingSkipped = &zero
	s.Rows[0].Socket.NetNS = s.UDP.NetNS
	s.UDP.AccountingRows = map[string]identity.UDPCount{"cookie": {Uploaded: up, Since: fixtureStart}}
	return s
}
func TestIncompleteActivityConservesRegisteredUDPAsUnattributed(t *testing.T) {
	l := New()
	l.Observe(rawUDP(1, 0))
	s := rawUDP(2, 120000)
	s.Complete = false
	s.Issues = []string{"fault-injected incomplete FD census"}
	l.Observe(s)
	if got := unassigned(l, UDP); got != "120000" {
		t.Fatalf("incomplete identity census erased registered counters: got%s want120000", got)
	}
	if sum(l, 1000) != 0 {
		t.Fatal("incomplete owner received bytes")
	}
}

func TestRawUDPOwnershipBookendsTailAndGenerationConserve(t *testing.T) {
	l := New()
	l.Observe(rawUDP(1, 0))
	l.Observe(rawUDP(2, 100))
	if sum(l, 1000) != 100 {
		t.Fatal("registered application usage missing", l.Snapshot(0, true))
	}
	closed := rawUDP(3, 0)
	closed.Rows = nil
	closed.UDP.AccountingRows = map[string]identity.UDPCount{}
	closed.UDP.Retired = map[string]identity.UDPCount{"cookie": {Uploaded: 125, Since: fixtureStart}}
	l.Observe(closed)
	l.Observe(closed)
	if sum(l, 1000) != 100 || unassigned(l, UDP) != "25" {
		t.Fatal("tail lost, assigned stale owner, or counted twice", l.Snapshot(0, true))
	}
	restart := rawUDP(4, 7)
	restart.UDP.Generation = "new"
	l.Observe(restart)
	restart = rawUDP(5, 17)
	restart.UDP.Generation = "new"
	l.Observe(restart)
	if sum(l, 1000) != 110 || unassigned(l, UDP) != "32" {
		t.Fatal("new generation donated old lifetime", l.Snapshot(0, true))
	}
}
func TestRawUDPIncompleteAndChangedOwnerNeverDonate(t *testing.T) {
	l := New()
	l.Observe(rawUDP(1, 0))
	s := rawUDP(2, 100)
	s.Complete = false
	l.Observe(s)
	l.Observe(rawUDP(3, 150))
	l.Observe(rawUDP(4, 180))
	if sum(l, 1000) != 30 || unassigned(l, UDP) != "150" {
		t.Fatal(l.Snapshot(0, true))
	}
	s = rawUDP(5, 200)
	p := s.Processes["10:100"]
	p.UID = 1001
	p.Application.Key = "other"
	s.Processes[p.ID] = p
	l.Observe(s)
	if sum(l, 1000) != 30 || sum(l, 1001) != 0 || unassigned(l, UDP) != "170" {
		t.Fatal("cross-user interval donated", l.Snapshot(0, true))
	}
}
func TestPrivateRawUDPCountersAreNotSerialized(t *testing.T) {
	s := rawUDP(1, 42)
	s.UDP.AccountingRows["private-foreign-cookie"] = identity.UDPCount{Uploaded: 999}
	s.UDP.Retired = s.UDP.AccountingRows
	b, _ := json.Marshal(s)
	if bytes.Contains(b, []byte("private-foreign-cookie")) {
		t.Fatal("private counter inventory exposed")
	}
}

func TestRawUDPAbsentCookieExpiryUsesCollectorTime(t *testing.T) {
	l := New()
	l.Observe(rawUDP(1, 0))
	l.Observe(rawUDP(2, 100))
	s := rawUDP(3, 0)
	s.UDP.AccountingRows = map[string]identity.UDPCount{}
	s.Rows = nil
	s.Collected = s.Collected.Add(20 * time.Second)
	l.Observe(s)
	if len(l.udpRawPrevious) != 1 {
		t.Fatal("slow observation discarded live collector cursor")
	}
	s = rawUDP(7, 0)
	s.UDP.AccountingRows = map[string]identity.UDPCount{}
	s.Rows = nil
	l.Observe(s)
	if len(l.udpRawPrevious) != 0 {
		t.Fatal("legacy omitted final cursor retained without bound")
	}
}
func TestRawUDPWineTwoApplicationsTwoPrefixesNoCrossCredit(t *testing.T) {
	l := New()
	for seq := uint64(1); seq <= 3; seq++ {
		s := rawUDP(seq, 0)
		s.Rows = nil
		s.Processes = map[string]identity.ActivityProcess{}
		s.UDP.AccountingRows = map[string]identity.UDPCount{}
		for i := 0; i < 4; i++ {
			label := fmt.Sprint(i)
			prefix := []string{"prefix-a", "prefix-b"}[i/2]
			app := identity.Application{Kind: "wine", Key: "app-" + label, Revision: "revision", Prefix: prefix}
			broker := identity.ActivityProcess{ID: "broker-" + label, PID: 100 + i, Start: "broker-start", BootID: "boot", NetNS: s.UDP.NetNS, UID: 1000, ExecutableRevision: "broker", Application: identity.Application{Kind: "wine-unresolved", Prefix: prefix}}
			co := broker
			co.ID = "app-" + label
			co.PID = 200 + i
			co.Application = app
			co.ExecutableRevision = "loader"
			s.Processes[broker.ID] = broker
			s.Processes[co.ID] = co
			row := rawUDP(seq, 0).Rows[0]
			row.Socket.Cookie = label
			row.Owners = []string{broker.ID, co.ID}
			row.OwnershipCategory = "shared"
			row.RuntimeApplication = &identity.RuntimeApplication{Application: app, UID: 1000, Evidence: identity.TableEvidence{UID: 1000, Prefix: prefix, Generation: "helper-" + prefix, BrokerPID: broker.PID, BrokerStart: broker.Start, SocketCookie: label, Owners: []identity.WindowsOwner{{PID: uint32(300 + i), Created: 12, Image: label}}}}
			if seq == 3 && i == 0 {
				co.Application.Prefix = "prefix-b"
				s.Processes[co.ID] = co
			}
			s.Rows = append(s.Rows, row)
			s.UDP.AccountingRows[label] = identity.UDPCount{Uploaded: uint64(i+1) * 100 * (seq - 1), Since: fixtureStart}
		}
		l.Observe(s)
	}
	if sum(l, 1000) != 1900 || unassigned(l, UDP) != "100" {
		t.Fatal("cross-app/prefix bytes or missing conservation", l.Snapshot(0, true))
	}
	for _, e := range l.Snapshot(0, true).Entries {
		want := map[string]string{"app-0": "100", "app-1": "400", "app-2": "600", "app-3": "800"}[e.Application.Key]
		if e.Uploaded != want {
			t.Fatal(e)
		}
	}
}

func TestTracingSkipsReportGapWithoutEstimatingBytes(t *testing.T) {
	l := New()
	l.Observe(rawUDP(1, 0))
	before := l.Snapshot(0, true)
	s := rawUDP(2, 1200)
	skips := uint64(7)
	s.UDP.TracingSkipped = &skips
	l.Observe(s)
	got := l.Snapshot(0, true)
	if got.Gaps == before.Gaps || len(got.Entries) != 1 || got.Entries[0].Uploaded != "1200" {
		t.Fatal(got)
	}
	if !strings.Contains(l.sources[1].Reason, "missing bytes are unknown") {
		t.Fatal(got.Sources)
	}
	s = rawUDP(3, 2400)
	s.UDP.TracingSkipped = &skips
	l.Observe(s)
	again := l.Snapshot(0, true)
	if again.Gaps != got.Gaps || again.Entries[0].Uploaded != "2400" {
		t.Fatal(again)
	}
}
