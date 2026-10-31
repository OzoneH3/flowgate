package daemon

import (
	"flowgate/internal/identity"
	"net/netip"
	"testing"
	"time"
)

// A dual-stack wildcard socket can carry an IPv4 flow with an exact live grant.
// Same exact live socket evidence, with the dual-stack wildcard shape also
// accepted by KeyFor for an IPv4 queued flow. No traffic or enforcement runs.
func TestFastPathSharedWineDualStackWildcardPresentation(t *testing.T) {
	for _, app := range []string{"synthetic-A", "synthetic-B"} {
		for _, prefix := range []string{"/fixture/prefix-A", "/fixture/prefix-B"} {
			for _, local := range []string{"0.0.0.0:1234", "[::]:1234"} {
				e := New(time.Second)
				runtime := &identity.RuntimeApplication{UID: 1000, Application: identity.Application{Key: app, Revision: "revision", Prefix: prefix, Kind: "wine"}, DisplaySource: "established-grant"}
				row := identity.ActivityRow{ID: "socket", Owners: []string{"101:10", "102:20"}, Socket: identity.Socket{Protocol: "udp", NetNS: "ns", UID: 1000, Inode: 7, Cookie: "0100000000000000", Local: netip.MustParseAddrPort(local), Remote: netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 0)}}
				if !row.Socket.Local.Addr().Is4() {
					row.Socket.Remote = netip.MustParseAddrPort("[::]:0")
				}
				grant := socketGrantHint{netns: "ns", cookie: row.Socket.Cookie, inode: 7, uid: 1000, application: app, revision: "revision", prefix: prefix, runtime: runtime, active: true, statsKnown: true}
				e.listReads.published.Store(&publishedList{at: time.Now(), socketHints: socketFastPathHints{available: true, grants: []socketGrantHint{grant}}})
				snapshot := identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{row}, Processes: map[string]identity.ActivityProcess{"101:10": {UID: 1000, Executable: "/fixture/wineserver"}, "102:20": {UID: 1000, Executable: "/fixture/wine"}}}
				out := e.annotateSocketFastPath(activityFor(snapshot, 1000, false)).Rows[0]
				retained := out.RuntimeApplication != nil
				t.Logf("app=%s prefix=%s local=%s shared_holders=%d retained=%v state=%s code=%s", app, prefix, local, len(row.Owners), retained, out.FastPath.State, out.FastPath.Code)
				if !retained || out.FastPath.State != "in_use" {
					t.Fatal("exact granted wildcard socket lost presentation")
				}
				for _, field := range []string{"cookie", "inode", "uid", "netns", "holder"} {
					bad := row
					processes := snapshot.Processes
					switch field {
					case "cookie":
						bad.Socket.Cookie = "0200000000000000"
					case "inode":
						bad.Socket.Inode++
					case "uid":
						bad.Socket.UID++
					case "netns":
						bad.Socket.NetNS = "other"
					case "holder":
						processes = map[string]identity.ActivityProcess{"101:10": {UID: 1001}, "102:20": {UID: 1000}}
					}
					other := e.annotateSocketFastPath(identity.ActivitySnapshot{Complete: true, Rows: []identity.ActivityRow{bad}, Processes: processes}).Rows[0]
					if other.RuntimeApplication != nil || other.FastPath.State == "in_use" {
						t.Fatal("foreign socket/holder borrowed presentation", field)
					}
				}

			}
		}
	}
}
