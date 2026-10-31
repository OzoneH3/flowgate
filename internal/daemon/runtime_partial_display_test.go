package daemon

import (
	"flowgate/internal/identity"
	"net/netip"
	"testing"
	"time"
)

func TestRuntimePartialDisplayStillRequiresFreshRuleProof(t *testing.T) {
	e := New(time.Second)
	now := time.Now()
	e.Now = func() time.Time { return now }
	app := identity.Application{Kind: "wine", Key: "synthetic-app-A-prefix-A", Revision: "r", Prefix: "/prefix-A"}
	broker := identity.ActivityProcess{ID: "101:100", PID: 101, Start: "100", UID: 1000, Application: identity.Application{Kind: "wine-unresolved"}}
	socket := identity.Socket{Protocol: "tcp", NetNS: "ns", Cookie: "cookie", Inode: 7, UID: 1000, Local: netip.MustParseAddrPort("127.0.0.1:1234"), Remote: netip.MustParseAddrPort("127.0.0.1:5678")}
	table := identity.TableEvidence{BrokerPID: 101, BrokerStart: "100", UID: 1000, SocketCookie: "cookie", Prefix: "/prefix-A"}
	row := identity.ActivityRow{ID: "socket", Socket: socket, Owners: []string{broker.ID}, RuntimeApplication: &identity.RuntimeApplication{Application: app, UID: 1000, Evidence: table, DisplaySource: "last-verified-partial-snapshot"}}
	s := identity.ActivitySnapshot{Complete: false, Collected: now, Rows: []identity.ActivityRow{row}, Processes: map[string]identity.ActivityProcess{broker.ID: broker}}
	e.Activity = func() identity.ActivitySnapshot { return s }
	expected, ok := runtimeActivityOwner(s, row)
	if !ok {
		t.Fatal("display target unavailable")
	}
	calls := 0
	fresh := identity.Attribution{}
	e.Resolve = func(identity.Flow) identity.Attribution { calls++; return fresh }
	target := ObservedTarget{RowID: row.ID, ProcessID: broker.ID}
	if _, err := e.verifyCreation(target, expected, 1000, false); err == nil || calls != 1 {
		t.Fatal("retained label bypassed fresh verification", calls, err)
	}
	fresh = identity.Attribution{Status: "corroborated-runtime-table", VisibilityComplete: true, Application: &app, Table: &table, Owners: []identity.Process{{PID: 101, Start: "100", UID: 1000}}, Sockets: []identity.Socket{socket}}
	if _, err := e.verifyCreation(target, expected, 1000, false); err != nil || calls != 2 {
		t.Fatal("full fresh proof was not used", calls, err)
	}
	fresh.VisibilityComplete = false
	if _, err := e.verifyCreation(target, expected, 1000, false); err == nil || calls != 3 {
		t.Fatal("incomplete proof was accepted", calls, err)
	}
}
