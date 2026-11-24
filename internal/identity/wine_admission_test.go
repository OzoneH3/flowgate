package identity

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWineFirstSYNDoesNotBorrowSiblingOwner(t *testing.T) {
	prefix := t.TempDir()
	drive := filepath.Join(prefix, "dosdevices", "c:")
	if err := os.MkdirAll(drive, 0700); err != nil {
		t.Fatal(err)
	}
	broker := Process{PID: 10, Start: "one", UID: 1000, ExecutableRevision: "broker", Application: Application{Prefix: prefix}}
	first := tableSnapshot{Schema: 2, Family: 4, Version: "11.20", Complete: true, Rows: []WindowsOwner{
		{Family: 4, PID: 42, Created: 10, CreationTime: "10", Image: `C:\alpha.exe`, Address: "127.0.0.1", Port: 47101, RemoteAddress: "127.0.0.1", RemotePort: 46000, State: 3},
		{Family: 4, PID: 43, Created: 11, CreationTime: "11", Image: `C:\beta.exe`, Address: "127.0.0.1", Port: 47102, RemoteAddress: "127.0.0.1", RemotePort: 46000, State: 3},
	}}
	for _, name := range []string{"alpha.exe", "beta.exe"} {
		if err := os.WriteFile(filepath.Join(drive, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range first.Rows {
		name := []string{"alpha.exe", "beta.exe"}[i]
		t.Run(name, func(t *testing.T) {
			f := Flow{Protocol: "tcp", Direction: "outgoing", NetNS: "net",
				Local: netip.AddrPortFrom(netip.MustParseAddr(row.Address), row.Port), Remote: netip.MustParseAddrPort("127.0.0.1:46000")}
			sock := Socket{Protocol: "tcp", Family: 2, Local: f.Local, Remote: f.Remote,
				State: 2, Inode: uint32(i + 1), Cookie: []string{"0100000000000000", "0200000000000000"}[i], NetNS: f.NetNS}
			a := Attribution{VisibilityComplete: true, Owners: []Process{broker}, Sockets: []Socket{sock}}
			rows, err := selectTableRows(first, f)
			if err != nil || len(rows) != 1 || rows[0].PID != row.PID {
				t.Fatalf("selected sibling or lost the exact SYN row: %v %v", rows, err)
			}
			w := WineTable{prefix: prefix}
			path := filepath.Join(drive, name)
			imageVisible := func(_ *Process, image, revision string) bool {
				return image == path && revision == stamp(path)
			}
			got := w.finishCensus(f, a, a, &broker, first, first, rows, imageVisible)
			if got.Application == nil || got.Application.Executable != path || got.Application.Prefix != prefix ||
				got.Table == nil || got.Table.SocketCookie != sock.Cookie || got.ReasonCode != ReasonRuntimeOwnerObserved {
				t.Fatalf("exact SYN lost its owner: %+v", got)
			}
			sibling := first.Rows[1-i]
			siblingOnly := first
			siblingOnly.Rows = []WindowsOwner{sibling}
			got = w.finishCensus(f, a, a, &broker, first, siblingOnly, rows, imageVisible)
			if got.Application != nil || got.ReasonCode != ReasonRuntimeOwnershipChanged {
				t.Fatalf("sibling row survived loss of the exact SYN row: %+v", got)
			}
		})
	}
}

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
