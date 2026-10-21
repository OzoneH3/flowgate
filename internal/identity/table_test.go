package identity

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTableRows(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:1234", "127.0.0.1:50000")
	a := WindowsOwner{PID: 12, Created: 1, Image: "Z:\\alpha.exe", Address: "127.0.0.1", Port: 1234, State: 2}
	b := a
	b.PID = 16
	b.Image = "Z:\\beta.exe"
	rows, err := selectTableRows(tableSnapshot{Rows: []WindowsOwner{a, a, b}}, f)
	if err != nil || len(rows) != 2 {
		t.Fatalf("shared holders lost: %+v %v", rows, err)
	}
	a.Created = 0
	if _, err = selectTableRows(tableSnapshot{Rows: []WindowsOwner{a}}, f); err == nil {
		t.Fatal("accepted missing generation")
	}
}
func TestTableObserverLoss(t *testing.T) {
	w := &WineTable{dead: true}
	start := time.Now()
	if _, err := w.snapshot("tcp"); err == nil {
		t.Fatal("stopped observer accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("stopped observer blocked")
	}
	if _, err := NewWineTable("", "", "", "", "unknown"); err == nil {
		t.Fatal("unrecognized runtime accepted")
	}
}

func TestTableRejectsBrokenResponses(t *testing.T) {
	for _, response := range []string{`not-json`, `{"version":"11.19","complete":false}`, `{"version":"unexpected","complete":true}`, `{"version":"11.19","complete":true,"error":2}`, `{"schema":99,"family":4,"version":"11.19","complete":true}`, `{"schema":1,"family":6,"version":"11.19","complete":true}`} {
		t.Run(response, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "helper.sh")
			if err := os.WriteFile(helper, []byte("while read line; do printf '%s\\n' '"+response+"'; done\n"), 0600); err != nil {
				t.Fatal(err)
			}
			w, err := NewWineTable("/bin/sh", helper, "/bin/sh", dir, "11.19")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err = w.snapshot("tcp"); err == nil {
				t.Fatal("bad snapshot accepted")
			}
			if _, err = w.snapshot("tcp"); err == nil {
				t.Fatal("failed observer revived")
			}
		})
	}
}

func TestIPv6TableScopeAndFamilies(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "[::1]:1234", "[::1]:50000")
	r := WindowsOwner{PID: 1, Created: 1, Image: "Z:\\alpha.exe", Address: "0000:0000:0000:0000:0000:0000:0000:0001", Port: 1234, State: 2, Family: 6, Scope: 1}
	if rows, err := selectTableRows(tableSnapshot{Rows: []WindowsOwner{r}}, f); err != nil || len(rows) != 1 {
		t.Fatalf("loopback scope is not link-local: %v", err)
	}
	f.Local = netip.MustParseAddrPort("[fe80::1]:1234")
	r.Address = "fe80::1"
	if _, err := selectTableRows(tableSnapshot{Rows: []WindowsOwner{r}}, f); err == nil {
		t.Fatal("unmapped link-local scope accepted")
	}
	f.Local = netip.MustParseAddrPort("127.0.0.1:1234")
	r.Address = "::ffff:127.0.0.1"
	r.Scope = 0
	if rows, err := selectTableRows(tableSnapshot{Rows: []WindowsOwner{r}}, f); err != nil || len(rows) != 1 {
		t.Fatal("mapped address not matched")
	}
}
func TestKernelFamilyCandidates(t *testing.T) {
	f, _ := ParseFlow("tcp", "incoming", "127.0.0.1:1234", "127.0.0.1:50000")
	yes, no := true, false
	s := Socket{Family: 10, V6Only: &yes, Local: netip.MustParseAddrPort("[::]:1234"), Protocol: "tcp", State: 10}
	if matches(s, f) {
		t.Fatal("v6-only socket claimed v4")
	}
	s.V6Only = &no
	if !matches(s, f) {
		t.Fatal("dual-stack candidate omitted")
	}
	s.V6Only = nil
	if !matches(s, f) {
		t.Fatal("unknown must remain ambiguous candidate")
	}
}

func TestOutgoingTableRequiresExactPeerBeforeCompletion(t *testing.T) {
	f, _ := ParseFlow("tcp", "outgoing", "127.0.0.1:40000", "127.0.0.1:50000")
	r := WindowsOwner{PID: 7, Created: 123, Image: `Z:\game.exe`, Address: "127.0.0.1", Port: 40000, RemoteAddress: "127.0.0.1", RemotePort: 50000, State: 3}
	for _, state := range []uint32{3, 5} {
		r.State = state
		rows, err := selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{r}}, f)
		if err != nil || len(rows) != 1 {
			t.Fatal(rows, err)
		}
	}
	if _, err := selectTableRows(tableSnapshot{Schema: 1, Rows: []WindowsOwner{r}}, f); err == nil {
		t.Fatal("legacy table acquired outgoing authority")
	}
	other := r
	other.RemotePort++
	rows, err := selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{other}}, f)
	if err != nil || len(rows) != 0 {
		t.Fatal("coincident local endpoint borrowed another remote", rows, err)
	}
	other = r
	other.PID++
	other.Created++
	other.Image = `Z:\other.exe`
	rows, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{r, other}}, f)
	if err != nil || len(rows) != 2 {
		t.Fatal("shared handle hidden", rows, err)
	}
	r.Created = 0
	if _, err = selectTableRows(tableSnapshot{Schema: 2, Rows: []WindowsOwner{r}}, f); err == nil {
		t.Fatal("missing Windows generation accepted")
	}
}
func TestVisibleBrokerDuplicateIsNotASecondApplication(t *testing.T) {
	app := Application{Key: "game", Revision: "pe-revision"}
	broker := Process{PID: 5, Start: "1", UID: 1000, NetNS: "net", MountNS: "mnt", ExecutableRevision: "broker"}
	client := Process{PID: 6, Start: "2", UID: 1000, NetNS: "net", MountNS: "mnt", Application: app}
	if !consistentWineHolders([]Process{broker}, broker, app) || !consistentWineHolders([]Process{broker, client}, broker, app) {
		t.Fatal("broker duplicate invalidated established Windows owner")
	}
	client.Application.Key = "other"
	if consistentWineHolders([]Process{broker, client}, broker, app) {
		t.Fatal("different client FD holder accepted")
	}
	changed := broker
	changed.Start = "reused"
	if sameBrokerGeneration(broker, []Process{changed}) {
		t.Fatal("broker PID reused")
	}
}

func TestMissingWindowsOwnerRetriesOnlyWithinBound(t *testing.T) {
	f, _ := ParseFlow("tcp", "outgoing", "127.0.0.1:40000", "127.0.0.1:50000")
	for _, publish := range []bool{false, true} {
		reader, writer := io.Pipe()
		w := &WineTable{input: writer, output: make(chan []byte, 1), version: "11.0"}
		done := make(chan int, 1)
		go func() {
			sc := bufio.NewScanner(reader)
			n := 0
			for sc.Scan() {
				n++
				rows := []WindowsOwner{}
				if publish && n == 3 {
					rows = append(rows, WindowsOwner{PID: 7, Created: 1, Image: `Z:\a.exe`, Address: "127.0.0.1", Port: 40000, RemoteAddress: "127.0.0.1", RemotePort: 50000, State: 3})
				}
				b, _ := json.Marshal(tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true, Rows: rows})
				w.output <- b
			}
			done <- n
		}()
		start := time.Now()
		_, rows, err := w.snapshotRows(f, 4)
		writer.Close()
		if n := <-done; n != 3 {
			t.Fatal("unexpected query count", n)
		}
		reader.Close()
		if err != nil || len(rows) != map[bool]int{false: 0, true: 1}[publish] || time.Since(start) > 500*time.Millisecond {
			t.Fatal("missing-owner retry manufactured authority or exceeded bound", rows, err)
		}
	}
}

func TestNegotiatedCensusContract(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		schema        int
		accepted      bool
	}{
		{"wine11", "11.0", 2, true},
		{"wineDevelopment", "11.19", 2, true},
		{"newBuild", "11.21", 2, true},
		{"unknownFamily", "12.0", 2, false},
		{"unknown", "unknown", 2, false},
		{"legacySchema", "11.0", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "helper.sh")
			first, _ := json.Marshal(tableSnapshot{Version: tc.version, Schema: tc.schema, Family: 4, Complete: true})
			second, _ := json.Marshal(tableSnapshot{Version: "11.99", Schema: 2, Family: 4, Complete: true})
			script := "read line; printf '%s\\n' '" + string(first) + "'; while read line; do printf '%s\\n' '" + string(second) + "'; done\n"
			if err := os.WriteFile(helper, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			w, err := NewWineTable("/bin/sh", helper, "/bin/sh", dir, "")
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			_, err = w.snapshot("tcp")
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v: %v", tc.accepted, err)
			}
			if tc.accepted && w.version != tc.version {
				t.Fatal("negotiated version not pinned")
			}
			if _, err = w.snapshot("tcp"); err == nil {
				t.Fatal("changed contract or failed observer accepted")
			}
		})
	}
}
