package accounting

import (
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixtureStart = time.Now().UTC().Add(-time.Minute)

func observed(seq uint64, up uint64) identity.ActivitySnapshot {
	at := fixtureStart.Add(time.Duration(seq) * time.Second)
	p := identity.ActivityProcess{ID: "10:100", PID: 10, Start: "100", BootID: "boot", NetNS: "net", PIDNS: "pid", MountNS: "mount", UID: 1000, Executable: "/synthetic/alpha", ExecutableRevision: "revision", Application: identity.Application{Key: "alpha-key", Revision: "revision", Kind: "native", Name: "Alpha"}}
	r := identity.ActivityRow{ID: "row", OwnershipCategory: "visible-holder", Owners: []string{p.ID}, Socket: identity.Socket{NetNS: "net", Protocol: "tcp", Cookie: "cookie", Inode: 90, Family: 2}, Traffic: identity.Traffic{Available: true, Definition: TCP, Since: fixtureStart, Uploaded: up, Downloaded: up / 2}}
	return identity.ActivitySnapshot{Sequence: seq, Started: at, Collected: at, Complete: true, Rows: []identity.ActivityRow{r}, Processes: map[string]identity.ActivityProcess{p.ID: p}}
}
func sum(l *Ledger, uid uint32) uint64 {
	var n uint64
	for _, e := range l.Snapshot(uid, false).Entries {
		v, _ := strconv.ParseUint(e.Uploaded, 10, 64)
		n += v
	}
	return n
}
func unassigned(l *Ledger, source string) string {
	for _, v := range l.Snapshot(0, true).Unattributed {
		if v.Source == source {
			return v.Uploaded
		}
	}
	return "missing"
}
func TestRetainsOnlyDeltasAndClosedSockets(t *testing.T) {
	l := New()
	l.Observe(observed(1, 100))
	l.Observe(observed(2, 180))
	for i := 0; i < 10; i++ {
		l.Observe(observed(2, 999))
		l.Snapshot(1000, false)
	}
	l.Observe(observed(1, 999))
	if sum(l, 1000) != 80 {
		t.Fatal(l.Snapshot(1000, false))
	}
	closed := observed(3, 0)
	closed.Rows = nil
	l.Observe(closed)
	if sum(l, 1000) != 80 || l.Snapshot(0, true).Gaps != "1" {
		t.Fatal("closure erased totals or hid tail gap")
	}
	l.Observe(observed(4, 500))
	l.Observe(observed(5, 530))
	if sum(l, 1000) != 110 {
		t.Fatal("reappeared cookie donated lifetime", sum(l, 1000))
	}
}
func TestSharedChangedAndDisplayOwnersNeverDonate(t *testing.T) {
	l := New()
	l.Observe(observed(1, 0))
	l.Observe(observed(2, 10))
	changed := observed(3, 30)
	p := changed.Processes["10:100"]
	p.Application.Key = "beta"
	p.UID = 1001
	changed.Processes[p.ID] = p
	l.Observe(changed)
	changed.Sequence = 4
	changed.Collected = fixtureStart.Add(4 * time.Second)
	changed.Rows[0].Traffic.Uploaded = 50
	l.Observe(changed)
	if sum(l, 1000) != 10 || sum(l, 1001) != 20 || unassigned(l, TCP) != "20" {
		t.Fatal(l.Snapshot(0, true))
	}
	shared := observed(5, 70)
	shared.Rows[0].OwnershipCategory = "shared"
	shared.Rows[0].DisplayApplication = &p.Application
	l.Observe(shared)
	shared.Sequence = 6
	shared.Collected = fixtureStart.Add(6 * time.Second)
	shared.Rows[0].Traffic.Uploaded = 90
	l.Observe(shared)
	if unassigned(l, TCP) != "60" {
		t.Fatal("shared display metadata attributed", l.Snapshot(0, true))
	}
}
func TestDiscontinuitiesRebaseline(t *testing.T) {
	for _, kind := range []string{"incomplete", "sequence", "backward", "since", "clock", "gap", "cookie", "exec", "pid"} {
		t.Run(kind, func(t *testing.T) {
			l := New()
			l.Observe(observed(1, 100))
			l.Observe(observed(2, 110))
			s := observed(3, 150)
			switch kind {
			case "incomplete":
				s.Complete = false
			case "sequence":
				s.Sequence = 4
			case "backward":
				s.Rows[0].Traffic.Uploaded = 1
			case "since":
				s.Rows[0].Traffic.Since = s.Collected
			case "clock":
				s.Collected = fixtureStart
			case "gap":
				s.Collected = s.Collected.Add(61 * time.Second)
			case "cookie":
				s.Rows[0].Socket.Cookie = "new"
			case "exec":
				p := s.Processes["10:100"]
				p.ExecutableRevision = "new"
				s.Processes[p.ID] = p
			case "pid":
				p := s.Processes["10:100"]
				p.Start = "new"
				s.Processes[p.ID] = p
			}
			l.Observe(s)
			if sum(l, 1000) != 10 {
				t.Fatal("discontinuity attributed", l.Snapshot(0, true))
			}
		})
	}
}
func udp(seq, up uint64, generation string) identity.ActivitySnapshot {
	s := observed(seq, up)
	s.Rows[0].Socket.Protocol = "udp"
	s.Rows[0].Traffic.Definition = UDP
	s.UDP = &identity.UDPSnapshot{State: "active", NetNS: "net", Machine: true, Generation: generation, Collected: s.Collected, SampleNS: int64(seq) * 1000000000}
	return s
}
func TestUDPSourcesGenerationMissedAndRepeatedSample(t *testing.T) {
	l := New()
	l.Observe(udp(1, 100, "collector"))
	l.Observe(udp(2, 150, "collector"))
	s := udp(3, 180, "new")
	l.Observe(s)
	s = udp(4, 200, "new")
	s.UDP.Missed = 1
	l.Observe(s)
	if sum(l, 1000) != 50 {
		t.Fatal("collector loss donated", sum(l, 1000))
	}
	s = udp(5, 200, "new")
	s.UDP.Missed = 1
	s.UDP.SampleNS = 4e9
	p := s.Processes["10:100"]
	p.Application.Key = "beta"
	s.Processes[p.ID] = p
	l.Observe(s)
	s.Sequence = 6
	s.Collected = fixtureStart.Add(6 * time.Second)
	s.UDP.Collected = s.Collected
	s.UDP.SampleNS = 6e9
	s.Rows[0].Traffic.Uploaded = 240
	l.Observe(s)
	if unassigned(l, UDP) != "40" || sum(l, 1000) != 50 {
		t.Fatal("repeated sample advanced owner baseline", l.Snapshot(0, true))
	}
	for _, e := range l.Snapshot(1000, false).Entries {
		if e.Source != UDP {
			t.Fatal(e)
		}
	}
}
func TestProjectionExactCountersSaturationAndNewEpoch(t *testing.T) {
	l := New()
	l.Observe(observed(1, 0))
	l.Observe(observed(2, 9007199254740993))
	got := l.Snapshot(1000, false)
	if got.Entries[0].Uploaded != "9007199254740993" || got.Gaps != "" || got.Unattributed != nil || got.Scope != "user" {
		t.Fatal(got)
	}
	if len(l.Snapshot(1001, false).Entries) != 0 {
		t.Fatal("foreign totals disclosed")
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"uploaded":"9007199254740993"`) {
		t.Fatal(string(b))
	}
	if New().Snapshot(1000, false).Epoch == got.Epoch {
		t.Fatal("epoch reused")
	}
	c := counts{up: math.MaxUint64 - 1}
	c.add(5, 0)
	if c.up != math.MaxUint64 || !c.saturated {
		t.Fatal(c)
	}
	// Returned records are copies.
	got.Entries[0].Application.Key = "tamper"
	got.Sources[0].State = "tamper"
	if l.Snapshot(1000, false).Entries[0].Application.Key == "tamper" || l.Snapshot(1000, false).Sources[0].State == "tamper" {
		t.Fatal("mutable snapshot")
	}
}
func TestBoundsFreezeWithoutEvictingAndDuplicateSocketAtomicity(t *testing.T) {
	l := New()
	s := observed(1, 0)
	base := s.Rows[0]
	s.Rows = nil
	for i := 0; i < MaxEntries; i++ {
		id := fmt.Sprint(i)
		p := s.Processes["10:100"]
		p.ID = id
		p.Application.Key = id
		s.Processes[id] = p
		r := base
		r.Socket.Cookie = id
		r.Owners = []string{id}
		s.Rows = append(s.Rows, r)
	}
	l.Observe(s)
	s.Sequence = 2
	s.Collected = s.Collected.Add(time.Second)
	for i := range s.Rows {
		s.Rows[i].Traffic.Uploaded = 1
	}
	l.Observe(s)
	if len(l.entries) != MaxEntries {
		t.Fatal(len(l.entries))
	}
	s = observed(3, 0)
	l.Observe(s)
	l.Observe(observed(4, 10))
	if !l.Snapshot(0, true).CapacityLimited || sum(l, 1000) != MaxEntries {
		t.Fatal("overflow changed totals", l.Snapshot(0, true))
	}
	l.Observe(observed(5, 99))
	if sum(l, 1000) != MaxEntries {
		t.Fatal("frozen accumulator advanced")
	}
	l = New()
	l.Observe(observed(1, 0))
	dup := observed(2, 20)
	dup.Rows = append(dup.Rows, dup.Rows[0])
	l.Observe(dup)
	if sum(l, 1000) != 0 || len(l.previous) != 0 {
		t.Fatal("duplicate observation partly consumed")
	}
}
func TestWinePrefixesAndHelperGenerationDoNotTransfer(t *testing.T) {
	wine := func(seq, up uint64, prefix, generation string) identity.ActivitySnapshot {
		s := observed(seq, up)
		p := s.Processes["10:100"]
		p.Application.Kind = "wine-unresolved"
		s.Processes[p.ID] = p
		a := identity.Application{Key: "same-synthetic-key", Revision: "pe-revision", Kind: "wine", Name: "Synthetic", Prefix: prefix}
		s.Rows[0].RuntimeApplication = &identity.RuntimeApplication{Application: a, UID: 1000, Evidence: identity.TableEvidence{Prefix: prefix, Generation: generation, UID: 1000, BrokerPID: 10, BrokerStart: "100", SocketCookie: "cookie", Owners: []identity.WindowsOwner{{PID: 5, Created: 123, Image: "synthetic"}}}}
		return s
	}
	l := New()
	l.Observe(wine(1, 0, "prefix-a", "one"))
	l.Observe(wine(2, 10, "prefix-a", "one"))
	l.Observe(wine(3, 30, "prefix-b", "one"))
	l.Observe(wine(4, 60, "prefix-b", "one"))
	l.Observe(wine(5, 90, "prefix-b", "two"))
	if len(l.entries) != 2 || sum(l, 1000) != 40 || unassigned(l, TCP) != "50" {
		t.Fatal(l.Snapshot(0, true))
	}
	// A different synthetic executable in the same prefix also cannot inherit.
	s := wine(6, 100, "prefix-b", "two")
	s.Rows[0].RuntimeApplication.Application.Key = "second-app"
	l.Observe(s)
	if sum(l, 1000) != 40 || unassigned(l, TCP) != "60" {
		t.Fatal("application transferred")
	}
}
func TestConcurrentReadAndObserve(t *testing.T) {
	l := New()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				l.Snapshot(1000, false)
			}
		}()
	}
	for n := uint64(1); n <= 200; n++ {
		l.Observe(observed(n, n))
	}
	wg.Wait()
	if sum(l, 1000) != 199 {
		t.Fatal(sum(l, 1000))
	}
}

func TestPartialOversizedAndFailedTimestampRetainTotals(t *testing.T) {
	l := New()
	l.Observe(observed(1, 0))
	l.Observe(observed(2, 5))
	before := *l.Snapshot(0, true).SampledAt
	s := observed(3, 9)
	s.Collected = time.Time{}
	s.Complete = false
	l.Observe(s)
	if !l.Snapshot(0, true).SampledAt.Equal(before) {
		t.Fatal("failed timestamp regressed")
	}
	s = observed(4, 9)
	s.Rows = make([]identity.ActivityRow, MaxBaselines+1)
	l.Observe(s)
	if l.frozen || len(l.previous) != 0 || sum(l, 1000) != 5 {
		t.Fatal("oversized collection changed totals/permanently froze")
	}
}
func TestRuntimeForeignCoholderIsUnattributed(t *testing.T) {
	l := New()
	for seq := uint64(1); seq <= 2; seq++ {
		s := observed(seq, seq*10)
		p := s.Processes["10:100"]
		p.Application.Kind = "wine-unresolved"
		s.Processes[p.ID] = p
		foreign := p
		foreign.PID = 20
		foreign.ID = "20:200"
		foreign.Start = "200"
		foreign.Application.Kind = "native"
		s.Processes[foreign.ID] = foreign
		s.Rows[0].Owners = append(s.Rows[0].Owners, foreign.ID)
		s.Rows[0].OwnershipCategory = "shared"
		s.Rows[0].RuntimeApplication = &identity.RuntimeApplication{UID: 1000, Application: identity.Application{Kind: "wine", Key: "windows", Revision: "pe", Prefix: "prefix"}, Evidence: identity.TableEvidence{UID: 1000, Prefix: "prefix", Generation: "helper", BrokerPID: 10, BrokerStart: "100", SocketCookie: "cookie", Owners: []identity.WindowsOwner{{PID: 1, Created: 1}}}}
		l.Observe(s)
	}
	if len(l.entries) != 0 || unassigned(l, TCP) != "10" {
		t.Fatal("native co-holder donated Windows usage", l.Snapshot(0, true))
	}
}
func BenchmarkLedgerBoundedObservation(b *testing.B) {
	s := observed(1, 0)
	base := s.Rows[0]
	s.Rows = nil
	for i := 0; i < MaxBaselines; i++ {
		r := base
		r.Socket.Cookie = fmt.Sprint(i)
		s.Rows = append(s.Rows, r)
	}
	l := New()
	l.Observe(s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Sequence++
		s.Collected = s.Collected.Add(time.Second)
		for j := range s.Rows {
			s.Rows[j].Traffic.Uploaded++
		}
		l.Observe(s)
	}
}

func TestMaximumCounterAndForeignSaturationProjection(t *testing.T) {
	l := New()
	l.Observe(observed(1, 0))
	l.Observe(observed(2, math.MaxUint64))
	own := l.Snapshot(1000, false)
	if !own.Saturated || own.Entries[0].Uploaded != "18446744073709551615" {
		t.Fatal(own)
	}
	if l.Snapshot(1001, false).Saturated {
		t.Fatal("foreign saturation disclosed")
	}
}
func TestUDPSourceNamespaceAndScope(t *testing.T) {
	for _, kind := range []string{"namespace", "uid", "sample"} {
		t.Run(kind, func(t *testing.T) {
			l := New()
			for seq := uint64(1); seq <= 2; seq++ {
				s := udp(seq, seq*100, "one")
				switch kind {
				case "namespace":
					s.UDP.NetNS = "foreign"
				case "uid":
					s.UDP.Machine = false
					s.UDP.UID = 2000
				case "sample":
					s.UDP.SampleNS = 0
				}
				l.Observe(s)
			}
			if len(l.entries) != 0 {
				t.Fatal("mismatched source attributed", l.Snapshot(0, true))
			}
		})
	}
}
func TestWireBudgetForMaximumEntries(t *testing.T) {
	l := New()
	for i := 0; i < MaxEntries; i++ {
		id := fmt.Sprint(i)
		l.entries[id] = &retained{entry: Entry{ID: strings.Repeat("a", 64), Application: Application{strings.Repeat("k", 256), strings.Repeat("r", 256), strings.Repeat("t", 256), strings.Repeat("x", 256)}, Source: TCP, FirstObservedAt: time.Now(), LastObservedAt: time.Now(), Partial: true}, counts: counts{up: math.MaxUint64, down: math.MaxUint64}}
	}
	// This even overestimates production, which rejects metadata JSON >1024.
	b, err := json.Marshal(l.Snapshot(0, true))
	if err != nil || len(b) > 2<<20 {
		t.Fatal(len(b), err)
	}
}

func TestCapacityFreezeIsWholeObservation(t *testing.T) {
	l := New()
	for i := 0; i < MaxEntries-1; i++ {
		l.entries[fmt.Sprint(i)] = &retained{counts: counts{up: 7}}
	}
	s := observed(1, 0)
	r := s.Rows[0]
	r.Socket.Cookie = "second"
	r.Owners = []string{"other"}
	s.Rows = append(s.Rows, r)
	p := s.Processes["10:100"]
	p.ID = "other"
	p.Application.Key = "second"
	s.Processes[p.ID] = p
	l.Observe(s)
	s.Sequence++
	s.Collected = s.Collected.Add(time.Second)
	for i := range s.Rows {
		s.Rows[i].Traffic.Uploaded = 100
	}
	l.Observe(s)
	if !l.frozen || len(l.entries) != MaxEntries-1 {
		t.Fatal("partial row allocation")
	}
	for _, e := range l.entries {
		if e.counts.up != 7 {
			t.Fatal("partial delta")
		}
	}
	if unassigned(l, TCP) != "0" {
		t.Fatal("partial unattributed delta")
	}
}

func TestSimultaneousWineApplicationsAndPrefixes(t *testing.T) {
	l := New()
	for seq := uint64(1); seq <= 3; seq++ {
		s := observed(seq, 0)
		s.Rows = nil
		s.Processes = map[string]identity.ActivityProcess{}
		for i := 0; i < 2; i++ {
			label := fmt.Sprint(i)
			prefix := "prefix-" + label
			app := identity.Application{Key: "windows-" + label, Revision: "pe-" + label, Kind: "wine", Name: "Synthetic " + label, Prefix: prefix}
			broker := identity.ActivityProcess{ID: "broker-" + label, PID: 100 + i, Start: "broker-start", BootID: "boot", NetNS: "net", UID: 1000, ExecutableRevision: "broker", Application: identity.Application{Kind: "wine-unresolved", Prefix: prefix}}
			co := broker
			co.ID = "app-" + label
			co.PID = 200 + i
			co.Application = app
			co.ExecutableRevision = "loader"
			s.Processes[broker.ID] = broker
			s.Processes[co.ID] = co
			r := observed(seq, 0).Rows[0]
			r.Socket.Cookie = label
			r.Owners = []string{broker.ID, co.ID}
			r.OwnershipCategory = "shared"
			r.Traffic.Uploaded = uint64(i+1) * 10 * (seq - 1)
			r.RuntimeApplication = &identity.RuntimeApplication{Application: app, UID: 1000, Evidence: identity.TableEvidence{UID: 1000, Prefix: prefix, Generation: "helper-" + label, BrokerPID: broker.PID, BrokerStart: broker.Start, SocketCookie: label, Owners: []identity.WindowsOwner{{PID: uint32(300 + i), Created: 12, Image: label}}}}
			if seq == 3 && i == 0 {
				co.Application.Key = "different-app-same-prefix"
				s.Processes[co.ID] = co
			}
			s.Rows = append(s.Rows, r)
		}
		l.Observe(s)
	}
	got := l.Snapshot(1000, false)
	if len(got.Entries) != 2 || unassigned(l, TCP) != "10" {
		t.Fatal(got, unassigned(l, TCP))
	}
	for _, e := range got.Entries {
		want := "10"
		if e.Application.Key == "windows-1" {
			want = "40"
		}
		if e.Uploaded != want {
			t.Fatal("cross app/prefix credit", e)
		}
	}
}
func TestBackwardUDPClockOneCoverageBreak(t *testing.T) {
	l := New()
	l.Observe(udp(1, 0, "source"))
	l.Observe(udp(2, 5, "source"))
	s := udp(3, 10, "source")
	s.UDP.SampleNS = 1e9
	l.Observe(s)
	if l.Snapshot(0, true).Gaps != "1" || sum(l, 1000) != 5 {
		t.Fatal(l.Snapshot(0, true))
	}
}
