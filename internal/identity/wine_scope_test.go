package identity

import (
	"errors"
	"testing"
)

func TestWineScopeExclusionsAgreeWithFullPredicate(t *testing.T) {
	b := Process{UID: 1000, NetNS: "net", MountNS: "mnt"}
	for _, helper := range []bool{false, true} {
		for _, dimension := range []string{"matching", "uid", "netns", "mountns"} {
			t.Run(dimension+map[bool]string{true: "-helper", false: "-image"}[helper], func(t *testing.T) {
				s := wineScope{Start: "1", Exe: "runtime", UID: b.UID, NetNS: b.NetNS, MountNS: b.MountNS}
				switch dimension {
				case "uid":
					s.UID++
				case "netns":
					s.NetNS = "other"
				case "mountns":
					s.MountNS = "other"
				}
				full := s.UID == b.UID && s.NetNS == b.NetNS && (!helper || s.MountNS == b.MountNS)
				got := wineScopeCandidate(b, helper, func() (wineScope, error) { return s, nil })
				if got != full {
					t.Fatalf("prefilter=%v full predicate=%v", got, full)
				}
			})
		}
	}
}

func TestWineScopeUnknownAndChangesReachInspection(t *testing.T) {
	for _, change := range []string{"error-first", "error-second", "start", "exe", "uid", "netns", "mountns"} {
		t.Run(change, func(t *testing.T) {
			n := 0
			got := wineScopeCandidate(Process{UID: 1000, NetNS: "net", MountNS: "mnt"}, true, func() (wineScope, error) {
				n++
				s := wineScope{Start: "1", Exe: "exe", UID: 0, NetNS: "other", MountNS: "other"}
				if change == "error-first" || change == "error-second" && n == 2 {
					return s, errors.New("unreadable or vanished")
				}
				if n == 2 {
					switch change {
					case "start":
						s.Start = "2"
					case "exe":
						s.Exe = "new"
					case "uid":
						s.UID = 1000
					case "netns":
						s.NetNS = "net"
					case "mountns":
						s.MountNS = "mnt"
					}
				}
				return s, nil
			})
			if !got {
				t.Fatal("unknown/change skipped full inspection")
			}
		})
	}
}

func TestWineScopeDeletedImageInAnotherMountNamespaceIsNotSkipped(t *testing.T) {
	b := Process{UID: 1000, NetNS: "net", MountNS: "broker-mnt"}
	candidate := wineScopeCandidate(b, false, func() (wineScope, error) {
		return wineScope{Start: "1", Exe: "runtime", UID: 1000, NetNS: "net", MountNS: "other-mnt"}, nil
	})
	// The existing deleted-image negative must remain reachable even though its
	// process is in a different mount namespace from the broker.
	if !candidate {
		t.Fatal("same-UID/netns deleted-image process would be skipped")
	}
}
