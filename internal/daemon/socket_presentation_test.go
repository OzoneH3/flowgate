package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/socketgrant"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestFastPathPresentationExactSocketAndScope(t *testing.T) {
	e := New(time.Second)
	base := identity.ActivityRow{Socket: identity.Socket{Protocol: "udp", NetNS: "ns", Cookie: "0100000000000000", Local: netip.MustParseAddrPort("192.0.2.1:1234"), Remote: netip.MustParseAddrPort("198.51.100.1:5678")}}
	hints := socketFastPathHints{available: true, grants: []socketGrantHint{{netns: "ns", cookie: base.Socket.Cookie, local: base.Socket.Local.String(), remote: base.Socket.Remote.String()}}}
	p := &publishedList{at: time.Now(), socketHints: hints}
	e.listReads.published.Store(p)
	for _, tc := range []struct {
		name, code, state string
		change            func(*identity.ActivityRow)
	}{
		{"exact", "grant_installed", "authorized", func(*identity.ActivityRow) {}},
		{"other cookie same tuple", "no_grant_observed", "inactive", func(r *identity.ActivityRow) { r.Socket.Cookie = "0200000000000000" }},
		{"other destination same cookie", "no_grant_observed", "inactive", func(r *identity.ActivityRow) { r.Socket.Remote = netip.MustParseAddrPort("198.51.100.2:5678") }},
		{"other namespace", "no_grant_observed", "inactive", func(r *identity.ActivityRow) { r.Socket.NetNS = "other" }},
		{"tcp", "protocol_outside_scope", "unsupported", func(r *identity.ActivityRow) { r.Socket.Protocol = "tcp" }},
		{"ipv6", "family_outside_scope", "unsupported", func(r *identity.ActivityRow) { r.Socket.Remote = netip.MustParseAddrPort("[2001:db8::1]:5678") }},
		{"unconnected", "destination_not_observed", "unknown", func(r *identity.ActivityRow) { r.Socket.Remote = netip.MustParseAddrPort("0.0.0.0:0") }},
		{"incoming", "direction_outside_scope", "unsupported", func(r *identity.ActivityRow) {
			r.Initiation = identity.Initiation{State: "known", Direction: "incoming"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			in := identity.ActivitySnapshot{Rows: []identity.ActivityRow{r}}
			out := e.annotateSocketFastPath(in)
			h := out.Rows[0].FastPath
			if h.State != tc.state || h.Code != tc.code {
				t.Fatal(h)
			}
			if in.Rows[0].FastPath != nil {
				t.Fatal("modified shared observer row")
			}
		})
	}
	// This API reader must never reacquire the packet engine lock.
	e.mu.Lock()
	done := make(chan bool, 1)
	go func() {
		e.annotateSocketFastPath(identity.ActivitySnapshot{Rows: []identity.ActivityRow{base}})
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("presentation blocked on engine lock")
	}
	e.mu.Unlock()
	p.socketHints.grants[0].deadline = socketgrant.BootNow() - 1
	if got := e.annotateSocketFastPath(identity.ActivitySnapshot{Rows: []identity.ActivityRow{base}}).Rows[0].FastPath; got.Code != "permission_expired" {
		t.Fatal(got)
	}
	p.at = time.Now().Add(-2 * time.Second)
	if got := e.annotateSocketFastPath(identity.ActivitySnapshot{Rows: []identity.ActivityRow{base}}).Rows[0].FastPath; got.State != "unknown" {
		t.Fatal(got)
	}
}
func TestFastPathPresentationUIDProjectionNoPermissionTransfer(t *testing.T) {
	e := New(time.Second)
	s := identity.ActivitySnapshot{Processes: map[string]identity.ActivityProcess{}}
	hints := socketFastPathHints{available: true}
	// Two synthetic apps, two prefixes, two UIDs. Equal tuple strings do not let
	// any app/user/prefix row borrow another socket's descriptor.
	for i := 0; i < 8; i++ {
		id := string(rune('a' + i))
		cookie := id + "cookie"
		uid := uint32(1000 + i/4)
		app := identity.Application{Key: "synthetic-" + string(rune('A'+i%2)), Kind: "wine", Prefix: "/fixture/prefix-" + string(rune('A'+(i/2)%2))}
		s.Processes[id] = identity.ActivityProcess{UID: uid, Application: app}
		r := identity.ActivityRow{ID: id, Owners: []string{id}, Socket: identity.Socket{UID: uid, Protocol: "udp", Cookie: cookie, NetNS: "ns", Local: netip.MustParseAddrPort("192.0.2.1:12"), Remote: netip.MustParseAddrPort("198.51.100.1:34")}}
		s.Rows = append(s.Rows, r)
		if i == 0 {
			hints.grants = append(hints.grants, socketGrantHint{cookie: cookie, netns: "ns", local: r.Socket.Local.String(), remote: r.Socket.Remote.String()})
		}
	}
	e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: hints})
	got := e.annotateSocketFastPath(activityFor(s, 1000, false))
	if len(got.Rows) != 4 {
		t.Fatal("foreign rows leaked")
	}
	for i, r := range got.Rows {
		if (r.FastPath.State == "authorized") != (i == 0) {
			t.Fatal("borrowed another identity's grant", r)
		}
	}
	other := e.annotateSocketFastPath(activityFor(s, 1001, false))
	for _, r := range other.Rows {
		if r.FastPath.State == "authorized" {
			t.Fatal("cross-user grant")
		}
	}
}

func TestFastPathPresentationDisabledAndDetached(t *testing.T) {
	e := New(time.Second)
	flow := identity.Flow{Protocol: "udp", NetNS: "ns", Local: netip.MustParseAddrPort("192.0.2.1:12"), Remote: netip.MustParseAddrPort("198.51.100.1:34")}
	f := &socketFlow{haveKey: true, flow: flow, key: socketgrant.Key{Cookie: 1, Interface: 2}}
	e.socketAuthorization = &socketAuthorization{productionSession: true, routeBound: true, flows: map[string]*socketFlow{"f": f}}
	hints := e.socketFastPathHintsLocked()
	f.key.Interface = 3
	f.haveKey = false
	if len(hints.grants) != 1 || hints.grants[0].ifindex != 2 {
		t.Fatal("mutable grant descriptor")
	}
	e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: hints})
	row := identity.ActivityRow{Socket: identity.Socket{Protocol: "udp", NetNS: "ns", Cookie: "0100000000000000", Local: flow.Local, Remote: flow.Remote}}
	hints.disabled = true
	e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: hints})
	if got := e.annotateSocketFastPath(identity.ActivitySnapshot{Rows: []identity.ActivityRow{row}}).Rows[0].FastPath; got.State != "inactive" || got.Code != "session_disabled" {
		t.Fatal(got)
	}
}

func TestFastPathBusySnapshotRetainsOnlyExactLiveGrantedRuntime(t *testing.T) {
	e := New(time.Second)
	row := identity.ActivityRow{ID: "live", Socket: identity.Socket{Protocol: "udp", NetNS: "ns", UID: 1000, Inode: 7, Cookie: "cookie", Local: netip.MustParseAddrPort("0.0.0.0:1234"), Remote: netip.MustParseAddrPort("0.0.0.0:0")}}
	runtime := &identity.RuntimeApplication{UID: 1000, Application: identity.Application{Key: "synthetic-A", Revision: "rev-A", Prefix: "prefix-A", Kind: "wine"}, DisplaySource: "established-grant"}
	grant := socketGrantHint{netns: "ns", cookie: "cookie", inode: 7, uid: 1000, application: "synthetic-A", revision: "rev-A", prefix: "prefix-A", runtime: runtime, active: true, statsKnown: true}
	h := socketFastPathHints{available: true, grants: []socketGrantHint{grant}}
	e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: h})
	// The Wine activity observer yielded to admission, leaving this NEW snapshot
	// unannotated. The existing live authorization can supply display identity only.
	for i := 0; i < 3; i++ {
		out := e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{row}})
		if out.Rows[0].RuntimeApplication == nil || out.Rows[0].RuntimeApplication.Application.Key != "synthetic-A" || out.Rows[0].FastPath.State != "in_use" {
			t.Fatal("busy snapshot lost app/UDP activity", out.Rows[0])
		}
		if row.RuntimeApplication != nil {
			t.Fatal("mutated source observer row")
		}
	}
	for _, field := range []string{"cookie", "inode", "uid", "namespace"} {
		other := row
		switch field {
		case "cookie":
			other.Socket.Cookie = "other"
		case "inode":
			other.Socket.Inode = 8
		case "uid":
			other.Socket.UID = 1001
		case "namespace":
			other.Socket.NetNS = "other"
		}
		out := e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{other}})
		if out.Rows[0].RuntimeApplication != nil || out.Rows[0].FastPath.State == "in_use" {
			t.Fatal("cross-socket/user projection", field)
		}
	}
	foreign := row
	foreign.Owners = []string{"foreign"}
	foreignSnapshot := identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{foreign}, Processes: map[string]identity.ActivityProcess{"foreign": {UID: 1001}}}
	foreignView := e.annotateSocketFastPath(activityFor(foreignSnapshot, 1001, false))
	if len(foreignView.Rows) != 1 || foreignView.Rows[0].RuntimeApplication != nil || foreignView.Rows[0].FastPath.State != "unknown" {
		t.Fatal("prior UID identity leaked through passed descriptor")
	}
	if len(e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true}).Rows) != 0 {
		t.Fatal("resurrected closed row")
	}
	// A different exe OR prefix on this same cookie is ambiguous, never borrowed.
	for _, prefix := range []string{"prefix-A", "prefix-B"} {
		other := grant
		other.application = "synthetic-B"
		other.prefix = prefix
		b := *runtime
		b.Application.Key = "synthetic-B"
		b.Application.Prefix = prefix
		other.runtime = &b
		h.grants = []socketGrantHint{grant, other}
		e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: h})
		out := e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{row}}).Rows[0]
		if out.RuntimeApplication != nil || out.FastPath.State != "unknown" {
			t.Fatal("conflicting app/prefix borrowed identity", out)
		}
	}
	h.grants = nil
	e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: h})
	if out := e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{row}}).Rows[0]; out.RuntimeApplication != nil {
		t.Fatal("association survived grant removal")
	}
}

func TestFastPathHitSamplingBoundedRecentAndReadFailure(t *testing.T) {
	now := socketgrant.BootNow()
	reads := 0
	h := socketFastPathHints{available: true, grants: make([]socketGrantHint, 64), stats: func(k socketgrant.Key) (socketgrant.Stats, error) {
		reads++
		if k.Cookie == 2 {
			return socketgrant.Stats{}, fmt.Errorf("unavailable")
		}
		last := now - uint64(5*time.Second)
		if k.Cookie == 1 {
			last = now
		}
		return socketgrant.Stats{LastSeen: last}, nil
	}}
	h.grants[0].key.Cookie = 1
	h.grants[1].key.Cookie = 2
	h.sampleHits()
	if reads != 64 || !h.grants[0].active || !h.grants[0].statsKnown || h.grants[1].statsKnown || h.grants[2].active || h.stats != nil {
		t.Fatal("invalid hit sample or live reader retained", reads)
	}
}
