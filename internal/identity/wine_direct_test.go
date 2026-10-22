package identity

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectWineRuntimeImageIsolation(t *testing.T) {
	for _, prefixName := range []string{"prefix-one", "prefix-two"} {
		t.Run(prefixName, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), prefixName)
			dir := filepath.Join(prefix, "dosdevices", "c:")
			if e := os.MkdirAll(dir, 0700); e != nil {
				t.Fatal(e)
			}
			for _, name := range []string{"alpha.exe", "beta.exe"} {
				if e := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); e != nil {
					t.Fatal(e)
				}
			}
			w := WineTable{prefix: prefix, generation: "helper-generation", session: &RuntimeSession{Build: directWine11Build}}
			broker := Process{PID: 10, Start: "100", UID: 1000, PIDNS: link("/proc/self/ns/pid"), NetNS: "net", MountNS: "mount", Application: Application{Kind: "wine-unresolved", Prefix: prefix}}
			for i, name := range []string{"alpha.exe", "beta.exe"} {
				t.Run(name, func(t *testing.T) {
					owner := broker
					owner.PID = 20 + i
					owner.Start = fmt.Sprint(200 + i)
					socket := Socket{NetNS: "net", Protocol: "udp", Local: netip.MustParseAddrPort("127.0.0.1:45000"), Remote: netip.MustParseAddrPort("127.0.0.53:53"), Inode: 1, Cookie: "one"}
					a := Attribution{VisibilityComplete: true, Owners: []Process{owner}, Sockets: []Socket{socket}, Status: "unidentified"}
					row := WindowsOwner{UnixPID: owner.PID, PID: uint32(40 + i), Created: uint64(400 + i), Image: "C:\\" + name}
					snap := tableSnapshot{Schema: 3, Kind: "process-images", Version: "11.0", Complete: true, Rows: []WindowsOwner{row}}
					path := filepath.Join(dir, name)
					proof := func(p Process, file, revision string) bool {
						return p.PID == owner.PID && p.Start == owner.Start && file == path && revision == stamp(path)
					}
					got := w.finishDirectCensus(a, a, broker, snap, snap, proof)
					if got.Application == nil || got.Application.Key != digest(fmt.Sprintf("1000|wine|%s|%s", prefix, path)) || got.Table.DirectPID != owner.PID || got.Principal().UID != 1000 {
						t.Fatal("direct owner not corroborated", got)
					}
					for _, scenario := range []string{"different-image", "cross-prefix", "foreign-user", "owner-change", "socket-change", "ambiguous", "new-ambiguous", "windows-generation", "incomplete", "old-capability", "missing-map", "revision-change", "foreign-unix-pid", "foreign-pidns", "unknown-version", "unknown-build", "own-unprovable-foreign-mapped"} {
						t.Run(scenario, func(t *testing.T) {
							initial, fresh := a, a
							fresh.Owners = append([]Process(nil), a.Owners...)
							fresh.Sockets = append([]Socket(nil), a.Sockets...)
							before, after := snap, snap
							after.Rows = append([]WindowsOwner(nil), snap.Rows...)
							b := broker
							verify := proof
							switch scenario {
							case "different-image":
								before.Rows = []WindowsOwner{{UnixPID: owner.PID, PID: 99, Created: 999, Image: "C:\\other.exe"}}
							case "cross-prefix":
								b.Application.Prefix = filepath.Join(prefix, "other")
							case "foreign-user":
								b.UID = 1001
							case "owner-change":
								fresh.Owners[0].Start = "replacement"
							case "socket-change":
								fresh.Sockets[0].Cookie = "replacement"
							case "ambiguous":
								extra := row
								extra.PID = 999
								before.Rows = append(append([]WindowsOwner(nil), snap.Rows...), extra)
								after.Rows = before.Rows
							case "new-ambiguous":
								extra := row
								extra.PID = 999
								after.Rows = append(after.Rows, extra)
							case "windows-generation":
								after.Rows[0].Created++
							case "incomplete":
								after.Complete = false
							case "old-capability":
								before.Schema = 2
							case "missing-map":
								verify = func(Process, string, string) bool { return false }
							case "foreign-unix-pid":
								before.Rows = append([]WindowsOwner(nil), before.Rows...)
								before.Rows[0].UnixPID = owner.PID + 10
								after.Rows = before.Rows
							case "foreign-pidns":
								initial.Owners = append([]Process(nil), initial.Owners...)
								initial.Owners[0].PIDNS = "foreign"
								fresh.Owners[0].PIDNS = "foreign"
								b.PIDNS = "foreign"
							case "unknown-build":
								old := w.session
								w.session = &RuntimeSession{Build: "unvalidated"}
								defer func() { w.session = old }()
							case "unknown-version":
								before.Version = "11.19"
								after.Version = "11.19"
							case "own-unprovable-foreign-mapped":
								own := row
								own.Image = "C:\\unprovable.exe"
								foreign := row
								foreign.UnixPID = owner.PID + 1
								foreign.PID++
								before.Rows = []WindowsOwner{own, foreign}
								after.Rows = before.Rows
							case "revision-change":
								calls := 0
								verify = func(Process, string, string) bool {
									calls++
									if calls == 2 {
										if e := os.WriteFile(path, []byte("updated image"), 0600); e != nil {
											t.Fatal(e)
										}
									}
									return true
								}
								defer os.WriteFile(path, []byte(name), 0600)
							}
							if bad := w.finishDirectCensus(initial, fresh, b, before, after, verify); bad.Application != nil {
								t.Fatal("transferred permission identity", scenario)
							}
						})
					}
					// A table naming the other verified application must not borrow this
					// process's mapping proof, even in the same prefix.
					other := snap
					other.Rows = []WindowsOwner{{UnixPID: owner.PID, PID: 99, Created: 999, Image: "C:\\beta.exe"}}
					if name == "beta.exe" {
						other.Rows[0].Image = "C:\\alpha.exe"
					}
					if got := w.finishDirectCensus(a, a, broker, other, other, proof); got.Application != nil {
						t.Fatal("other app inherited identity")
					}
				})
			}
		})
	}
}

type rejectedPrivateQuery struct{ calls int }

func (w *rejectedPrivateQuery) Write(p []byte) (int, error) { w.calls++; return len(p), nil }
func (w *rejectedPrivateQuery) Close() error                { return nil }
func TestUnknownRuntimeBuildNeverSendsPrivateRequest(t *testing.T) {
	writer := &rejectedPrivateQuery{}
	ns := link("/proc/self/ns/pid")
	w := WineTable{requiredSchema: 3, version: "11.0", input: writer, session: &RuntimeSession{Build: "unknown-fork", Broker: Process{PIDNS: ns}}}
	a := Attribution{Owners: []Process{{PIDNS: ns}}}
	got := w.resolveDirect(Flow{}, a)
	if writer.calls != 0 || got.Application != nil || got.Reason != "runtime process-image census capability unavailable" {
		t.Fatal("unknown build reached private server call", writer.calls, got)
	}
}

// A broker is itself wine-unresolved in the Linux census. That does not make
// its sockets direct-client sockets, even on builds without the private API.
func TestUnresolvedBrokerUsesOwnerTableBeforeDirectCapability(t *testing.T) {
	actual, err := Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"/synthetic/prefix-one", "/synthetic/prefix-two"} {
		for _, app := range []string{"alpha.exe", "beta.exe"} {
			t.Run(prefix+"/"+app, func(t *testing.T) {
				owner := actual
				owner.Application = Application{Kind: "wine-unresolved", Prefix: prefix, Name: app}
				a := Attribution{VisibilityComplete: true, Owners: []Process{owner}, Sockets: []Socket{{Family: 2}}}
				if !directUnresolved(a) {
					t.Fatal("fixture must reproduce ambiguous broker kind")
				}
				writer := &rejectedPrivateQuery{}
				w := WineTable{broker: "/proc/self/exe", prefix: prefix, dead: true, input: writer,
					session: &RuntimeSession{Broker: actual, Build: "unsupported-private-api"}}
				got := w.resolveAttributionLocked(Flow{Protocol: "tcp", Direction: "outgoing"}, a)
				if got.Reason != "observer stopped; explicit restart required" || got.Application != nil || writer.calls != 0 {
					t.Fatal("broker bypassed ordinary owner-table path", got, writer.calls)
				}
				// A different pinned binary cannot lend its broker identity to this
				// owner, and an unsupported direct capability must grant nothing.
				w.broker = "/bin/sh"
				got = w.resolveAttributionLocked(Flow{Protocol: "tcp", Direction: "outgoing"}, a)
				if got.Application != nil || writer.calls != 0 || got.Reason != "runtime process-image census capability unavailable" {
					t.Fatal("foreign executable inherited broker evidence", got, writer.calls)
				}
			})
		}
	}
}
