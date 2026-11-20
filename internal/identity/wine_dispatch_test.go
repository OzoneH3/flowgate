package identity

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dispatchFixture() (Flow, Attribution, Attribution) {
	f := Flow{Protocol: "udp", Direction: "outgoing", NetNS: NetNS(), Local: netip.MustParseAddrPort("192.0.2.1:4000"), Remote: netip.MustParseAddrPort("198.51.100.1:5000")}
	p := Process{PID: 10, Start: "one", UID: 1000, NetNS: f.NetNS, ExecutableRevision: "r", Application: Application{Kind: "wine-unresolved", Prefix: "/prefix-one"}}
	a := Attribution{VisibilityComplete: true, Owners: []Process{p}, Sockets: []Socket{{Protocol: "udp", Family: 2, Local: f.Local, Inode: 1, Cookie: "0100000000000000", NetNS: f.NetNS}}}
	r := a
	r.Application = &Application{Kind: "wine", Key: "alpha", Prefix: "/prefix-one"}
	r.Status = "corroborated-runtime-table"
	r.Table = &TableEvidence{}
	return f, a, r
}

func TestWineDispatchBoundAgeIsolationAndNoAuthority(t *testing.T) {
	f, a, r := dispatchFixture()
	m := WineObservers{}
	now := time.Now()
	m.rememberDispatch(f, a, r, now, now)
	h := m.dispatchHint(f, now.Add(time.Millisecond))
	if h == nil {
		t.Fatal("missing hint")
	}
	if h.initial.Application != nil || h.initial.Table != nil || h.initial.Association != nil {
		t.Fatal("hint retained permission evidence")
	}
	for _, change := range []string{"direction", "remote", "namespace", "local"} {
		other := f
		switch change {
		case "direction":
			other.Direction = "incoming"
		case "remote":
			other.Remote = netip.MustParseAddrPort("198.51.100.2:5000")
		case "namespace":
			other.NetNS = "foreign"
		case "local":
			other.Local = netip.MustParseAddrPort("192.0.2.1:4001")
		}
		if m.dispatchHint(other, now) != nil {
			t.Fatal("hint crossed", change)
		}
	}
	if m.dispatchHint(f, now.Add(wineDispatchTTL)) != nil {
		t.Fatal("hit renewed TTL")
	}
	for i := 0; i < wineDispatchMax+20; i++ {
		g := f
		g.Local = netip.MustParseAddrPort(fmt.Sprintf("192.0.2.1:%d", 1000+i))
		m.rememberDispatch(g, a, r, now, now)
	}
	if len(m.dispatch) != wineDispatchMax {
		t.Fatalf("unbounded hints: %d", len(m.dispatch))
	}
	m.Close()
	if len(m.dispatch) != 0 || m.dispatchHint(f, now) != nil {
		t.Fatal("closed observer donated hint")
	}
}

func TestWineDispatchNeverStoresIncompleteOrOtherRuntime(t *testing.T) {
	for _, scenario := range []string{"incomplete", "no-app", "native", "hosted", "no-table", "no-cookie", "link-local", "expired", "raw-native"} {
		t.Run(scenario, func(t *testing.T) {
			f, a, r := dispatchFixture()
			now := time.Now()
			observed := now
			switch scenario {
			case "incomplete":
				r.VisibilityComplete = false
			case "no-app":
				r.Application = nil
			case "native":
				r.Application.Kind = "native"
			case "hosted":
				r.Application.Kind = "hosted"
			case "no-table":
				r.Table = nil
			case "no-cookie":
				a.Sockets[0].Cookie = ""
			case "link-local":
				f.Local = netip.MustParseAddrPort("169.254.1.1:4000")
			case "expired":
				observed = now.Add(-wineDispatchTTL)
			case "raw-native":
				a.Owners[0].Application.Kind = "native"
			}
			m := WineObservers{}
			m.rememberDispatch(f, a, r, observed, now)
			if len(m.dispatch) != 0 {
				t.Fatal("invalid hint stored")
			}
		})
	}
}

func TestWineDispatchFreshCensusRejectsReuseAndBrokerChanges(t *testing.T) {
	for _, scenario := range []string{"new-socket", "other-app-same-prefix", "other-prefix", "broker-restart", "broker-exec", "incomplete"} {
		t.Run(scenario, func(t *testing.T) {
			f, initial, result := dispatchFixture()
			m := WineObservers{}
			now := time.Now()
			m.rememberDispatch(f, initial, result, now, now)
			h := m.dispatchHint(f, now)
			a := copyWineInitial(h.initial)
			again := copyWineInitial(initial)
			row := WindowsOwner{Family: 4, PID: 42, Created: 10, CreationTime: "10", Image: "C:\\alpha.exe", Address: "192.0.2.1", Port: 4000}
			snap := tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true, Rows: []WindowsOwner{row}}
			switch scenario {
			case "new-socket", "other-app-same-prefix", "other-prefix":
				again.Sockets[0].Inode++
				again.Sockets[0].Cookie = "0200000000000000"
			case "broker-restart":
				again.Owners[0].Start = "new"
			case "broker-exec":
				again.Owners[0].ExecutableRevision = "new"
			case "incomplete":
				again.VisibilityComplete = false
			}
			w := WineTable{prefix: "/prefix-one"}
			got := w.finishCensus(f, a, again, &a.Owners[0], snap, snap, []WindowsOwner{row}, func(*Process, string, string) bool { t.Fatal("changed evidence reached image proof"); return true })
			if positiveWineDispatch(got) || got.Application != nil {
				t.Fatal("stale dispatch granted permission")
			}
			m.forgetDispatch(f, h)
			if m.dispatchHint(f, now) != nil {
				t.Fatal("failed hint retained")
			}
		})
	}
}

// Synthetic orchestration test: runtime validation itself is covered by the
// finishCensus refusal cases and separately by the real receiver fixture.
func TestWineDispatchMismatchRetriesFreshOnce(t *testing.T) {
	f, a, r := dispatchFixture()
	bin := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(exe, filepath.Join(bin, "wineserver")); err != nil {
		t.Fatal(err)
	}
	start, _, err := processStat(fmt.Sprintf("/proc/%d", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	a.Owners[0].PID = os.Getpid()
	a.Owners[0].Start = start
	a.Owners[0].UID = uint32(os.Getuid())
	m := WineObservers{options: WineObserverOptions{UID: uint32(os.Getuid()), RuntimeBins: []string{bin}, Prefixes: []string{"/prefix-one"}}, sessions: map[string]*observedWine{}, census: make(chan struct{}, WineCensusLimit)}
	defer m.Close()
	attempts := 0
	m.setupSession = func(record *observedWine, _ *Process, _ string) {
		defer close(record.ready)
		record.resolve = func(_ Flow, initial Attribution, _ bool) (Attribution, bool) {
			attempts++
			if initial.Sockets[0].Cookie != "0200000000000000" {
				return Attribution{ReasonCode: ReasonRuntimeOwnershipChanged}, true
			}
			out := r
			out.Sockets = initial.Sockets
			return out, true
		}
	}
	now := time.Now()
	m.rememberDispatch(f, a, r, now, now)
	calls := 0
	before := renewalBootNow()
	var admissionEnd uint64
	got, fullStart := m.resolveObservedBefore(f, func(Flow) Attribution {
		calls++
		fresh := copyWineInitial(a)
		fresh.Sockets[0].Cookie = "0200000000000000"
		return fresh
	}, func() { admissionEnd = renewalBootNow() })
	if fullStart < admissionEnd || admissionEnd == 0 {
		t.Fatal("scan witness preceded admission")
	}
	done := fullStart >= before && fullStart <= renewalBootNow()
	if !done || !positiveWineDispatch(got) || calls != 1 || attempts != 2 {
		t.Fatalf("fresh retry failed: done=%v calls=%d attempts=%d result=%+v", done, calls, attempts, got)
	}
	h := m.dispatchHint(f, time.Now())
	if h == nil || h.initial.Sockets[0].Cookie != "0200000000000000" {
		t.Fatal("stale hint survived retry")
	}

	_, hintStart := m.resolveObservedBefore(f, func(Flow) Attribution { t.Fatal("valid hint should keep routing savings"); return Attribution{} }, func() { t.Fatal("hint hit delayed by admission") })
	if hintStart != 0 {
		t.Fatal("hint result reported a fresh initial observation")
	}
	observed := h.observed
	_, done = m.resolveDispatch(f, true, func(Flow) Attribution { t.Fatal("valid hit rediscovered"); return Attribution{} })
	if !done || m.dispatchHint(f, time.Now()).observed != observed {
		t.Fatal("hit renewed hint age")
	}
	var record *observedWine
	for _, v := range m.sessions {
		record = v
	}
	record.resolve = func(Flow, Attribution, bool) (Attribution, bool) { return Attribution{}, false }
	_, done = m.resolveDispatch(f, false, func(Flow) Attribution { t.Fatal("busy hit rediscovered"); return Attribution{} })
	if done || m.dispatchHint(f, time.Now()) != h {
		t.Fatal("busy hit donated evidence or lost hint")
	}
	attempts = 0
	calls = 0
	record.resolve = func(Flow, Attribution, bool) (Attribution, bool) {
		attempts++
		return Attribution{ReasonCode: ReasonRuntimeEvidenceIncomplete}, true
	}
	got, done = m.resolveDispatch(f, true, func(Flow) Attribution { calls++; return a })
	if !done || got.Application != nil || calls != 1 || attempts != 2 || len(m.dispatch) != 0 {
		t.Fatal("incomplete refresh retained authority or retried repeatedly")
	}
}

func TestWineDispatchSameCookieCannotTransferApplicationOrPrefix(t *testing.T) {
	for _, otherPrefix := range []bool{false, true} {
		t.Run(fmt.Sprint("other-prefix=", otherPrefix), func(t *testing.T) {
			f, a, r := dispatchFixture()
			root := t.TempDir()
			prefix := filepath.Join(root, "one")
			drive := filepath.Join(prefix, "dosdevices", "c:")
			if err := os.MkdirAll(drive, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"alpha.exe", "beta.exe"} {
				if err := os.WriteFile(filepath.Join(drive, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			app := func(name, pfx string) Application {
				path := filepath.Join(drive, name)
				v := Application{Kind: "wine", Executable: path, Revision: stamp(path), Prefix: pfx}
				v.Key = digest(fmt.Sprintf("1000|wine|%s|%s", pfx, path))
				return v
			}
			alpha := app("alpha.exe", prefix)
			beta := app("beta.exe", prefix)
			if otherPrefix {
				beta.Prefix = filepath.Join(root, "two")
				beta.Key = "other-prefix-beta"
			}
			a.Owners[0].Application.Prefix = prefix
			client := a.Owners[0]
			client.PID = 20
			client.Application = alpha
			a.Owners = append(a.Owners, client)
			m := WineObservers{}
			now := time.Now()
			m.rememberDispatch(f, a, r, now, now)
			h := m.dispatchHint(f, now)
			initial := copyWineInitial(h.initial)
			again := copyWineInitial(a)
			again.Owners[1].PID = 30
			again.Owners[1].Start = "beta"
			again.Owners[1].Application = beta
			image := "C:\\beta.exe"
			if otherPrefix {
				image = "C:\\alpha.exe"
			}
			row := WindowsOwner{Family: 4, PID: 43, Created: 11, CreationTime: "11", Image: image, Address: "192.0.2.1", Port: 4000}
			snap := tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true, Rows: []WindowsOwner{row}}
			w := WineTable{prefix: prefix}
			got := w.finishCensus(f, initial, again, &initial.Owners[0], snap, snap, []WindowsOwner{row}, func(*Process, string, string) bool { return true })
			if got.Application != nil || got.ReasonCode != ReasonRuntimeHolderConflict {
				t.Fatalf("same-cookie handoff accepted: %+v", got)
			}
		})
	}
}

func TestWineFinalTCPHolderRequiresUnchangedVerifiedBrokerPrefix(t *testing.T) {
	root := t.TempDir()
	prefixes := []string{filepath.Join(root, "one"), filepath.Join(root, "two")}
	for i, name := range []string{"alpha.exe", "beta.exe"} {
		prefix := prefixes[i]
		drive := filepath.Join(prefix, "dosdevices", "c:")
		if err := os.MkdirAll(drive, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(drive, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		f, initial, _ := dispatchFixture()
		f.Protocol, initial.Sockets[0].Protocol, initial.Sockets[0].Remote = "tcp", "tcp", f.Remote
		initial.Owners[0].Application.Prefix = prefix
		row := WindowsOwner{Family: 4, PID: 42, Created: 10, CreationTime: "10", Image: "C:\\" + name,
			Address: f.Local.Addr().String(), Port: f.Local.Port(),
			RemoteAddress: f.Remote.Addr().String(), RemotePort: f.Remote.Port(), State: 5}
		snap := tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true, Rows: []WindowsOwner{row}}
		for _, tc := range []struct{ name, final string }{
			{"matching", prefix}, {"changed", prefixes[1-i]}, {"unverified", ""},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				again := copyWineInitial(initial)
				again.Owners[0].Application.Prefix = tc.final
				w := WineTable{prefix: prefix}
				got := w.finishCensus(f, initial, again, &initial.Owners[0], snap, snap, []WindowsOwner{row}, func(*Process, string, string) bool { return true })
				if tc.final == prefix {
					if !got.FreshConnectionProof() || got.Application == nil || got.Application.Prefix != prefix || got.Application.Name != name {
						t.Fatalf("matching prefix lost verified ownership: %+v", got)
					}
				} else if got.FreshConnectionProof() || got.Application != nil || got.ReasonCode != ReasonRuntimeOwnershipChanged {
					t.Fatalf("changed or unverified prefix retained ownership: %+v", got)
				}
			})
		}
	}
}
