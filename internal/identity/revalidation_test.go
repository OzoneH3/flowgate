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
