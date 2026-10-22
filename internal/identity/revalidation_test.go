package identity

import (
	"testing"
	"time"
)

func TestPendingBindingComparisonSeparatesSocketAndProcess(t *testing.T) {
	app := Application{Key: "a", Revision: "r"}
	original := Attribution{Application: &app, VisibilityComplete: true, Fingerprint: "old", Owners: []Process{{PID: 10, Start: "20", UID: 1000, Application: app, ExecutableRevision: "er"}}, Sockets: []Socket{{Inode: 123, Cookie: "oldcookie", NetNS: "n"}}}
	for _, field := range []string{"socket_inode_cookie", "process[10].start_ticks", "process[10].executable_revision", "process[10].uid"} {
		t.Run(field, func(t *testing.T) {
			next := original
			next.Owners = append([]Process{}, original.Owners...)
			next.Sockets = append([]Socket{}, original.Sockets...)
			next.Fingerprint = "new"
			switch field {
			case "socket_inode_cookie":
				next.Sockets[0].Cookie = "replacement"
			case "process[10].start_ticks":
				next.Owners[0].Start = "21"
			case "process[10].executable_revision":
				next.Owners[0].ExecutableRevision = "changed"
			case "process[10].uid":
				next.Owners[0].UID = 1001
			}
			r := ComparePendingBinding(original, next, time.Now())
			found := false
			for _, c := range r.Changes {
				if c.Field == field {
					found = true
				}
			}
			if !found {
				t.Fatal(r)
			}
			if field == "socket_inode_cookie" && r.Code != "connection_ended" {
				t.Fatal(r)
			}
			if field != "socket_inode_cookie" && r.Code != "identity_changed" {
				t.Fatal(r)
			}
		})
	}
	gone := Attribution{Status: "unidentified", Reason: "no visible matching socket"}
	r := ComparePendingBinding(original, gone, time.Now())
	if r.Code != "connection_ended" {
		t.Fatal(r)
	}
	for _, c := range r.Changes {
		if c.Field == "process[10].executable_revision" {
			t.Fatal("missing owner is not an executable revision change")
		}
	}
	unavailable := Attribution{Status: "unidentified", Reason: "socket diagnostics unavailable: test"}
	if ComparePendingBinding(original, unavailable, time.Now()).Code == "connection_ended" {
		t.Fatal("diagnostic failure claimed socket closure")
	}
}

// A Wine fingerprint also covers runtime-table holders and the census helper
// instance. A fingerprint-only mismatch names which of them changed; identical
// table evidence and native attributions report neither.
func TestPendingBindingNamesRuntimeTableChanges(t *testing.T) {
	app := Application{Key: "a", Revision: "r"}
	holder := WindowsOwner{PID: 20, Created: 2, Image: `Z:\alpha.exe`, Address: "::1", Port: 40000, State: 3, RemoteAddress: "::1", RemotePort: 40000}
	original := Attribution{Application: &app, VisibilityComplete: true, Fingerprint: "old", Owners: []Process{{PID: 10, Start: "20", UID: 1000, Application: app}}, Sockets: []Socket{{Inode: 123, Cookie: "c", NetNS: "n"}},
		Table: &TableEvidence{Owners: []WindowsOwner{holder}, Generation: "g1"}}
	fields := func(next Attribution) map[string]bool {
		out := map[string]bool{}
		for _, c := range ComparePendingBinding(original, next, time.Now()).Changes {
			out[c.Field] = true
		}
		return out
	}
	changed := func(mutate func(*TableEvidence)) Attribution {
		next := original
		table := *original.Table
		table.Owners = append([]WindowsOwner{}, original.Table.Owners...)
		mutate(&table)
		next.Table, next.Fingerprint = &table, "new"
		return next
	}
	if f := fields(changed(func(t *TableEvidence) { t.Owners[0].State = 5 })); !f["runtime_table_holders"] || f["runtime_table_generation"] {
		t.Fatalf("holder state change not named: %v", f)
	}
	if f := fields(changed(func(t *TableEvidence) { t.Generation = "g2" })); !f["runtime_table_generation"] || f["runtime_table_holders"] {
		t.Fatalf("helper generation change not named: %v", f)
	}
	if f := fields(changed(func(*TableEvidence) {})); f["runtime_table_holders"] || f["runtime_table_generation"] {
		t.Fatalf("identical table evidence reported a change: %v", f)
	}
	lost := original
	lost.Table = nil
	if f := fields(lost); !f["runtime_table_holders"] || !f["runtime_table_generation"] {
		t.Fatalf("lost table evidence not named: %v", f)
	}
	native := original
	native.Table = nil
	r := ComparePendingBinding(native, native, time.Now())
	for _, c := range r.Changes {
		if c.Field == "runtime_table_holders" || c.Field == "runtime_table_generation" {
			t.Fatalf("native attribution reported table fields: %v", r.Changes)
		}
	}
}
