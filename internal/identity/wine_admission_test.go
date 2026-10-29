package identity

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestHelperPeerPrefilterPreservesFullCandidateCount(t *testing.T) {
	bf := map[uint32]bool{10: true, 20: true, 30: true}
	peers := map[uint32]uint32{10: 11, 11: 10, 20: 21, 21: 20, 30: 31, 31: 30, 40: 41}
	for count := 0; count <= 2; count++ {
		for _, unreadable := range []bool{false, true} {
			unfiltered, filtered := 0, 0
			for i, fd := range []uint32{11, 21, 31, 40, 50} {
				fds := map[uint32]bool{fd: true}
				// Independent full validation includes the original reciprocal relation,
				// exact image and prefix. The third related process is a different prefix.
				valid := i < count && bf[peers[fd]] && peers[peers[fd]] == fd
				if valid {
					unfiltered++
				}
				var err error
				initial := fds
				if unreadable {
					err = errors.New("fd census unavailable")
					initial = nil
				}
				if mayBeHelperPeer(bf, peers, initial, err) && valid {
					filtered++
				}
			}
			if filtered != unfiltered || filtered != count {
				t.Fatalf("count=%d unreadable=%v: %d != %d", count, unreadable, filtered, unfiltered)
			}
		}
	}
	if !mayBeHelperPeer(bf, peers, nil, errors.New("vanished")) {
		t.Fatal("unknown was excluded")
	}
}

func TestWineAdmissionInitialCookieCannotSurviveReplacement(t *testing.T) {
	f := Flow{Protocol: "udp", Direction: "outgoing", Local: netip.MustParseAddrPort("192.0.2.1:4000"), Remote: netip.MustParseAddrPort("198.51.100.1:5000")}
	b := Process{PID: 10, Start: "one", ExecutableRevision: "r", Application: Application{Prefix: "/prefix"}}
	a := Attribution{VisibilityComplete: true, Owners: []Process{b}, Sockets: []Socket{{Protocol: "udp", Family: 2, Local: f.Local, Inode: 1, Cookie: "old", NetNS: "n"}}}
	again := a
	again.Sockets = append([]Socket(nil), a.Sockets...)
	again.Sockets[0].Cookie = "replacement"
	row := WindowsOwner{Family: 4, PID: 42, Created: 10, CreationTime: "10", Image: "C:\\alpha.exe", Address: "192.0.2.1", Port: 4000}
	snap := tableSnapshot{Schema: 2, Family: 4, Version: "11.0", Complete: true, Rows: []WindowsOwner{row}}
	w := WineTable{prefix: "/prefix"}
	result := w.finishCensus(f, a, again, &b, snap, snap, []WindowsOwner{row}, func(*Process, string, string) bool { t.Fatal("changed cookie reached image validation"); return true })
	if result.Application != nil || result.ReasonCode != ReasonRuntimeOwnershipChanged {
		t.Fatalf("replacement accepted: %+v", result)
	}
}

func TestWineCandidateUnknownFallsThrough(t *testing.T) {
	if !mayBeWineProcess(-1) {
		t.Fatal("unreadable process skipped")
	}
}

func TestWineProcessPrefilterUsesFullInspectionRuntimePredicate(t *testing.T) {
	for _, scenario := range []string{"native", "memfd-wine", "deleted-image", "changed-start", "changed-exe", "unreadable", "over-bound"} {
		t.Run(scenario, func(t *testing.T) {
			maps := "100-200 r-xp 0 00:00 1 /native\n"
			switch scenario {
			case "memfd-wine":
				maps = "100-200 r-xp 0 00:00 1 /runtime/ntdll.dll\n200-300 r-xp 0 00:00 2 /memfd:image (deleted)\n"
			case "deleted-image":
				maps = "100-200 r-xp 0 00:00 1 /runtime/ntdll.dll\n200-300 r-xp 0 00:00 2 /image.exe (deleted)\n"
			case "over-bound":
				maps = strings.Repeat("x", processMapsLimit+1)
			}
			calls, links := 0, 0
			stat := func(string) (string, int, error) {
				calls++
				if scenario == "changed-start" && calls > 1 {
					return "new", 0, nil
				}
				return "old", 0, nil
			}
			link := func(string) string {
				links++
				if scenario == "changed-exe" && links > 1 {
					return "/replacement"
				}
				return "/runtime-loader"
			}
			scan := func(_, exe string) (string, bool, error) {
				if scenario == "unreadable" {
					return "", false, errors.New("EACCES")
				}
				return scanProcessMaps(strings.NewReader(maps), exe)
			}
			candidate := wineProcessCandidate(42, stat, link, scan)
			if candidate != (scenario != "native") {
				t.Fatalf("%s candidate=%v", scenario, candidate)
			}
			// The full predicate admits a Wine prefix only when its scan reports Wine.
			_, wine, err := scan("", "/runtime-loader")
			if !candidate && (wine || err != nil) {
				t.Fatal("excluded a potential full Wine inspection")
			}
			if scenario == "deleted-image" {
				p := Process{Application: Application{Kind: "wine", Executable: "/image.exe", Revision: "r", Key: "a", Prefix: "/prefix"}}
				full := wineTableImageVisible(p, "/image.exe", "r", maps)
				filtered := candidate && wineTableImageVisible(p, "/image.exe", "r", maps)
				if full || filtered {
					t.Fatal("deleted same-prefix image became visible")
				}
			}
		})
	}
}
