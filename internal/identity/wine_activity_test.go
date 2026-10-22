package identity

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestWineActivityBatchAllStreamsAndIsolation(t *testing.T) {
	for _, prefixName := range []string{"prefix-one", "prefix-two"} {
		t.Run(prefixName, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), prefixName)
			if e := os.MkdirAll(filepath.Join(prefix, "dosdevices", "c:"), 0700); e != nil {
				t.Fatal(e)
			}
			apps := make([]Application, 2)
			for i, name := range []string{"alpha.exe", "beta.exe"} {
				path := filepath.Join(prefix, "dosdevices", "c:", name)
				if e := os.WriteFile(path, []byte(name), 0600); e != nil {
					t.Fatal(e)
				}
				apps[i] = Application{Kind: "wine", Name: name, Executable: path, Revision: stamp(path), Prefix: prefix}
				apps[i].Key = digest(fmt.Sprintf("%d|wine|%s|%s", 1000, prefix, path))
			}
			broker := Process{PID: 10, Start: "100", UID: 1000, NetNS: "test-netns", MountNS: "test-mount", ExecutableRevision: "broker-rev", Application: Application{Kind: "wine-unresolved", Prefix: prefix}}
			process := func(id string, p Process) ActivityProcess {
				return ActivityProcess{ID: id, PID: p.PID, Start: p.Start, UID: p.UID, NetNS: p.NetNS, MountNS: p.MountNS, ExecutableRevision: p.ExecutableRevision, Application: p.Application}
			}
			s := ActivitySnapshot{Complete: true, Processes: map[string]ActivityProcess{"10:100": process("10:100", broker)}}
			for i, app := range apps {
				p := broker
				p.PID = 20 + i
				p.Start = fmt.Sprint(200 + i)
				p.Application = app
				s.Processes[fmt.Sprintf("%d:%s", p.PID, p.Start)] = process("", p)
			}
			table := tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true}
			var sockets []Socket
			var indices []int
			for i := 0; i < 24; i++ {
				app := i % 2
				socket := Socket{Protocol: "tcp", Family: 2, Local: netip.MustParseAddrPort(fmt.Sprintf("192.0.2.1:%d", 40000+i)), Remote: netip.MustParseAddrPort("198.51.100.1:443"), Cookie: fmt.Sprint(i + 1), Inode: uint32(i + 1), NetNS: broker.NetNS, State: 1}
				s.Rows = append(s.Rows, ActivityRow{ID: fmt.Sprint(i), Socket: socket, Owners: []string{"10:100", fmt.Sprintf("%d:%d", 20+app, 200+app)}})
				sockets = append(sockets, socket)
				indices = append(indices, i)
				table.Rows = append(table.Rows, WindowsOwner{PID: uint32(40 + app), Created: uint64(400 + app), Image: "C:\\" + apps[app].Name, Address: "192.0.2.1", Port: uint16(40000 + i), RemoteAddress: "198.51.100.1", RemotePort: 443, State: 5})
			}
			w := WineTable{prefix: prefix, generation: prefixName}
			first := map[int]tableSnapshot{4: table}
			visible := func(_ *Process, path, rev string) bool {
				return (path == apps[0].Executable && rev == apps[0].Revision) || (path == apps[1].Executable && rev == apps[1].Revision)
			}
			got := w.annotateCensus(&s, &s, sockets, indices, &broker, first, first, visible)
			if len(got) != 24 {
				t.Fatalf("only %d/24 streams attributed", len(got))
			}
			for i := range s.Rows {
				if got[i].Application.Key != apps[i%2].Key || got[i].Evidence.Prefix != prefix || got[i].Evidence.SocketCookie != sockets[i].Cookie {
					t.Fatalf("wrong app/prefix/socket at %d", i)
				}
			}
			for _, scenario := range []string{"cookie", "holder", "runtime-change", "cross-prefix", "hidden", "missing-image", "extra-socket", "foreign-socket", "unproven-dual-stack"} {
				t.Run(scenario, func(t *testing.T) {
					initial := s
					initial.Rows = append([]ActivityRow(nil), s.Rows...)
					fresh := s
					fresh.Rows = append([]ActivityRow(nil), s.Rows...)
					fresh.Processes = map[string]ActivityProcess{}
					for k, v := range s.Processes {
						fresh.Processes[k] = v
					}
					end := append([]Socket(nil), sockets...)
					after := table
					after.Rows = append([]WindowsOwner(nil), table.Rows...)
					verify := visible
					switch scenario {
					case "cookie":
						end[0].Cookie = "replacement"
					case "holder":
						fresh.Rows[0].Owners = []string{"10:100", "21:201"}
					case "runtime-change":
						after.Rows[0].Image = "C:\\beta.exe"
					case "cross-prefix":
						p := fresh.Processes["20:200"]
						p.Application.Prefix = "/different-prefix"
						fresh.Processes["20:200"] = p
					case "hidden":
						fresh.Complete = false
					case "missing-image":
						verify = func(*Process, string, string) bool { return false }
					case "foreign-socket":
						initial.Rows[0].Socket.NetNS = "other-netns"
						fresh.Rows[0].Socket.NetNS = "other-netns"
						end[0].NetNS = "other-netns"
					case "unproven-dual-stack":
						initial.Rows[0].Socket.Family = 10
						fresh.Rows[0].Socket.Family = 10
						end[0].Family = 10
					case "extra-socket":
						extra := end[0]
						extra.Cookie = "second"
						extra.Inode = 999
						end = append(end, extra)
					}
					result := w.annotateCensus(&initial, &fresh, end, indices, &broker, map[int]tableSnapshot{4: table, 6: table}, map[int]tableSnapshot{4: after, 6: after}, verify)
					if result[0] != nil {
						t.Fatalf("%s transferred association", scenario)
					}
				})
			}
		})
	}
}
