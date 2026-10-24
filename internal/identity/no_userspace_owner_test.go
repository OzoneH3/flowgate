package identity

import (
	"testing"
	"time"
)

func TestNoUserspaceOwnerIsNotMultipleOrKernelAuthority(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		a := Attribution{Status: "unidentified", Sockets: []Socket{{Inode: 123, Cookie: "test"}}, Fingerprint: "fixed"}
		if !unresolvedOwnership(&a, incomplete) || a.Status != "unidentified" || a.Application != nil || a.Principal() != nil || a.Fingerprint != "fixed" || len(a.Sockets) != 1 {
			t.Fatal(a)
		}
		want := ReasonNoUserspaceOwnerObserved
		if incomplete {
			want = ReasonProcessVisibilityIncomplete
		}
		if a.ReasonCode != want {
			t.Fatal(a)
		}
		if ComparePendingBinding(a, a, time.Now()).Code == "connection_ended" {
			t.Fatal("observed socket became ended")
		}
	}
	a := Attribution{Sockets: []Socket{{Inode: 1}}, Owners: []Process{{PID: 1}, {PID: 2}}}
	if !unresolvedOwnership(&a, false) || a.ReasonCode != ReasonMultipleCandidates {
		t.Fatal(a)
	}
	a = Attribution{Sockets: []Socket{{Inode: 1}}, Owners: []Process{{PID: 1}}}
	if unresolvedOwnership(&a, false) {
		t.Fatal("single owner rejected")
	}
}
