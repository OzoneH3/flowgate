package accounting

import (
	"bytes"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"maps"
	"reflect"
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
			app := identity.Application{Kind: "wine", Key: "app-" + label, Revision: "revision", Executable: "/fixture/app-" + label + ".exe", Prefix: prefix}
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

func TestRawUDPWineRequiresFreshMatchingOwner(t *testing.T) {
	wine := func(seq, up uint64) identity.ActivitySnapshot {
		s := rawUDP(seq, up)
		row := &s.Rows[0]
		broker := s.Processes[row.Owners[0]]
		broker.Application = identity.Application{Kind: "wine-unresolved", Prefix: "/fixture/pfx"}
		s.Processes[broker.ID] = broker
		app := identity.Application{Kind: "wine", Key: "alpha", Name: "alpha.exe",
			Executable: "/fixture/alpha.exe", Revision: "stamp", Prefix: "/fixture/pfx"}
		row.RuntimeApplication = &identity.RuntimeApplication{
			Application: app, UID: broker.UID,
			Evidence: identity.TableEvidence{UID: broker.UID, Prefix: app.Prefix, Generation: "helper",
				BrokerPID: broker.PID, BrokerStart: broker.Start, SocketCookie: row.Socket.Cookie,
				Owners: []identity.WindowsOwner{{PID: 6, Created: 1, Image: app.Executable}}},
		}
		return s
	}
	retainLabel := func(app *identity.RuntimeApplication) {
		app.DisplaySource = "last-verified-snapshot"
		app.DisplayVerifiedAt = fixtureStart.Format(time.RFC3339Nano)
	}
	for _, tc := range []struct {
		name string
		edit func(before, after *identity.RuntimeApplication)
		want uint64
	}{
		{name: "fresh stable owner", want: 100},
		{name: "cached ending label", edit: func(_, after *identity.RuntimeApplication) { retainLabel(after) }},
		{name: "cached starting label", edit: func(before, _ *identity.RuntimeApplication) { retainLabel(before) }},
		{name: "different executable same prefix", edit: func(_, after *identity.RuntimeApplication) {
			after.Application.Executable = "/fixture/beta.exe"
			after.Application.Name = "beta.exe"
			// Keep the runtime's image label identical. The mapped executable
			// path itself must match even when the runtime name does.
		}},
		{name: "same executable different prefix", edit: func(_, after *identity.RuntimeApplication) {
			after.Application.Prefix = "/fixture/other-pfx"
			after.Evidence.Prefix = after.Application.Prefix
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := wine(1, 0), wine(2, 100)
			if tc.edit != nil {
				tc.edit(before.Rows[0].RuntimeApplication, after.Rows[0].RuntimeApplication)
			}
			l := New()
			l.Observe(before)
			l.Observe(after)
			l.Observe(after) // The same counter sample cannot credit the interval again.
			credited, unattributed := sum(l, 1000), unassigned(l, UDP)
			t.Logf("Windows application=%d B, unattributed=%s B, registered delta=100 B", credited, unattributed)
			if credited != tc.want || unattributed != decimal(100-tc.want) {
				t.Fatalf("wrong bucket or lost bytes: %+v", l.Snapshot(0, true))
			}
			if tc.want > 0 {
				entries := l.Snapshot(1000, false).Entries
				if len(entries) != 1 || entries[0].Application.Name != "alpha.exe" || entries[0].Source != UDP {
					t.Fatalf("stable bytes credited to the wrong application: %+v", entries)
				}
			}
		})
	}
}

func TestRawUDPCapacityFreezesBeforeAnyTotalsOrCursorsMove(t *testing.T) {
	sample := func(seq uint64, order []string, mixed bool) identity.ActivitySnapshot {
		s := rawUDP(seq, 0)
		base := s.Rows[0]
		baseProcess := s.Processes[base.Owners[0]]
		s.Rows = nil
		clear(s.Processes)
		clear(s.UDP.AccountingRows)
		for _, name := range order {
			process := baseProcess
			process.ID = name
			process.Application.Key = name
			s.Processes[name] = process
			row := base
			row.Socket.Cookie = name
			row.Owners = []string{name}
			uploaded := map[string]uint64{"a": 100, "b": 200}[name] * (seq - 1)
			if mixed && name == "b" {
				row.Socket.Protocol = "tcp"
				row.Traffic.Definition = TCP
				row.Traffic.Uploaded = uploaded
			} else {
				s.UDP.AccountingRows[name] = identity.UDPCount{Uploaded: uploaded, Since: fixtureStart}
			}
			s.Rows = append(s.Rows, row)
		}
		return s
	}

	type state struct {
		Entries         int
		Attributed      uint64
		Unattributed    string
		TCPUnattributed string
		Sequence        uint64
		RawSample       int64
		RawCursors      map[string]uint64
		RowCursors      int
		Frozen          bool
		Gaps            uint64
	}
	read := func(l *Ledger) state {
		cursors := make(map[string]uint64)
		for cookie, cursor := range l.udpRawPrevious {
			cursors[cookie] = cursor.up
		}
		return state{
			Entries: len(l.entries), Attributed: sum(l, 1000), Unattributed: unassigned(l, UDP),
			TCPUnattributed: unassigned(l, TCP), Sequence: l.sequence, RawSample: l.udpRawSample,
			RawCursors: cursors, RowCursors: len(l.previous), Frozen: l.frozen, Gaps: l.gaps,
		}
	}

	for _, tc := range []struct {
		name  string
		order []string
		free  int
		mixed bool
	}{
		{name: "one_slot_a_then_b", order: []string{"a", "b"}, free: 1},
		{name: "one_slot_b_then_a", order: []string{"b", "a"}, free: 1},
		{name: "both_fit", order: []string{"a", "b"}, free: 2},
		{name: "shared_limit_udp_and_tcp", order: []string{"a", "b"}, free: 1, mixed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := New()
			for i := 0; i < MaxEntries-tc.free; i++ {
				l.entries[fmt.Sprint(i)] = &retained{counts: counts{up: 7}}
			}
			l.Observe(sample(1, tc.order, tc.mixed))
			before := read(l)
			rawBefore, rowBefore := maps.Clone(l.udpRawPrevious), maps.Clone(l.previous)
			next := sample(2, tc.order, tc.mixed)
			if tc.mixed {
				// Neither an unattributed lifetime count nor a TCP delta may
				// commit before the combined identity capacity is decided.
				next.UDP.AccountingRows["first"] = identity.UDPCount{Uploaded: 17, Since: fixtureStart}
			}
			l.Observe(next)
			after := read(l)
			rawAfter, rowAfter := maps.Clone(l.udpRawPrevious), maps.Clone(l.previous)
			l.Observe(next)
			replay := read(l)
			if !reflect.DeepEqual(rawAfter, l.udpRawPrevious) || !reflect.DeepEqual(rowAfter, l.previous) {
				t.Fatal("replay moved a counter cursor")
			}
			if tc.free == 1 && (!reflect.DeepEqual(rawBefore, rawAfter) || !reflect.DeepEqual(rowBefore, rowAfter)) {
				t.Error("capacity freeze did not preserve the accepted counter cursors")
			}
			t.Logf("before=%+v after=%+v replay=%+v", before, after, replay)
			want := before
			if tc.free == 1 {
				want.Frozen = true
				want.Gaps++
			} else {
				want.Entries = MaxEntries
				want.Attributed = 300
				want.Sequence = next.Sequence
				want.RawSample = next.UDP.SampleNS
				want.RawCursors = map[string]uint64{"a": 100, "b": 200}
				for _, entry := range l.Snapshot(1000, false).Entries {
					if decimal(want.RawCursors[entry.Application.Key]) != entry.Uploaded {
						t.Errorf("wrong credit for %s: %s", entry.Application.Key, entry.Uploaded)
					}
				}
			}
			if !reflect.DeepEqual(after, want) || !reflect.DeepEqual(replay, want) {
				t.Fatalf("capacity changed part of a sample or replay: want %+v", want)
			}
			if l.entries["0"].counts.up != 7 {
				t.Fatal("retained credits changed")
			}
		})
	}
}

func TestRawUDPCursorCapacityFreezesWholeSample(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(fmt.Sprintf("retirement_%t", retire), func(t *testing.T) {
			l := New()
			open := rawUDP(1, 0)
			open.Rows = nil
			open.UDP.AccountingRows = make(map[string]identity.UDPCount)
			for i := 0; i < MaxBaselines; i++ {
				open.UDP.AccountingRows[fmt.Sprint(i)] = identity.UDPCount{Since: fixtureStart}
			}
			l.Observe(open)
			next := rawUDP(2, 0)
			next.Rows = nil
			next.UDP.AccountingRows = map[string]identity.UDPCount{"new": {Since: fixtureStart, Uploaded: 7}}
			if retire {
				next.UDP.Retired = map[string]identity.UDPCount{"0": {Since: fixtureStart, Uploaded: 11}}
			}
			before := maps.Clone(l.udpRawPrevious)
			l.Observe(next)
			t.Logf("cursor count %d, watermark %d -> %d, frozen=%t, unattributed=%s B",
				len(l.udpRawPrevious), open.UDP.SampleNS, l.udpRawSample, l.frozen, unassigned(l, UDP))
			if len(l.udpRawPrevious) != MaxBaselines {
				t.Fatal("cursor table out of bounds")
			}
			if retire {
				if l.frozen || l.udpRawSample != next.UDP.SampleNS || l.udpRawPrevious["new"].up != 7 ||
					!l.udpRawPrevious["0"].since.IsZero() || unassigned(l, UDP) != "18" {
					t.Fatal("retirement did not free space before applying the new cursor")
				}
			} else if !l.frozen || l.udpRawSample != open.UDP.SampleNS ||
				!reflect.DeepEqual(l.udpRawPrevious, before) || unassigned(l, UDP) != "0" {
				t.Fatal("cursor capacity committed part of the rejected sample")
			}
		})
	}
}
