package daemon

import (
	"flowgate/internal/identity"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectionAnalysisOnAuthenticatedReadOnlyAPI(t *testing.T) {
	now := time.Now()
	original := identity.ActivityRow{OwnershipCategory: "unknown", Evidence: "No visible descriptor",
		Socket: identity.Socket{Protocol: "tcp", Family: 2, NetNS: "net:[22]", Inode: 40,
			Cookie: "8e23000000000000", Local: netip.MustParseAddrPort("127.0.0.1:40000"),
			Remote: netip.MustParseAddrPort("127.0.0.1:40001")}}
	visible := original
	visible.Owners = []string{"app"}
	visible.OwnershipCategory = "visible-holder"
	visible.Evidence = "Visible descriptor holder"
	executable := identity.Application{Kind: "native", Key: "verified-app", Revision: "stamp"}
	e := New(time.Second)
	e.Mode = "host-monitor"
	e.Activity = func() identity.ActivitySnapshot {
		return identity.ActivitySnapshot{Collected: now, Rows: []identity.ActivityRow{original}}
	}
	e.ConnectionSample = func(port uint16) identity.ConnectionSample {
		if port != 40000 {
			t.Errorf("wrong sample port %d", port)
		}
		return identity.ConnectionSample{
			Activity: identity.ActivitySnapshot{Collected: now.Add(time.Second), DurationMS: 12,
				Rows: []identity.ActivityRow{visible}, Processes: map[string]identity.ActivityProcess{
					"app": {PID: 3, Start: "455", Executable: "/example/app", Application: executable},
				}},
			Confirmed: map[string]bool{identity.ConnectionKey(visible.Socket): true},
		}
	}
	e.Resolve = func(identity.Flow) identity.Attribution {
		t.Error("analysis called firewall attribution")
		return identity.Attribution{}
	}
	// Keep the UNIX path short even when the repository sets TMPDIR.
	dir, err := os.MkdirTemp("", "fga-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	listener, err := Serve(path, e, true)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	query := &ConnectionAnalysisQuery{LocalPort: 40000}
	response, err := Call(path, Request{Version: 1, Operation: "connection-analyze", ConnectionAnalysis: query})
	if err != nil || !response.ReadOnly || response.Permissions == nil {
		t.Fatal(response.Error, err)
	}
	analysis := response.ConnectionAnalysis
	if analysis == nil || analysis.Scope != response.Permissions.ObservationScope ||
		analysis.BaselineUnidentified != 1 || analysis.Recovered != 1 || analysis.CollectionMS != 12 {
		t.Fatalf("bad result %+v", analysis)
	}
	row := analysis.Connections[0]
	observation := row.Observations[1]
	if row.OriginalReason != original.Evidence || !row.OriginalAt.Equal(now) ||
		!observation.At.Equal(now.Add(time.Second)) ||
		observation.Application == nil || observation.Application.Key != executable.Key ||
		len(observation.Holders) != 1 || observation.Holders[0].Start != "455" {
		t.Fatalf("bad timestamp or evidence %+v", row)
	}
}

func TestConnectionAnalysisDoesNotCarryHoldersAcrossGenerationsOrVisibility(t *testing.T) {
	e := New(time.Second)
	uid := uint32(1000)
	e.APIUID = &uid
	first := identity.ActivityRow{OwnershipCategory: "unknown", Socket: identity.Socket{
		Protocol: "udp", Family: 2, Inode: 10, Cookie: "a900000000000000", NetNS: "net:[50]", UID: uid}}
	replacement, foreign, newNS := first, first, first
	replacement.Socket.Cookie = "aa00000000000000"
	replacement.Owners = []string{"self"}
	replacement.OwnershipCategory = "visible-holder"
	foreign.Owners = []string{"self", "other"}
	foreign.OwnershipCategory = "shared"
	newNS.Socket.NetNS = "net:[51]"
	newNS.Owners = []string{"self"}
	newNS.OwnershipCategory = "visible-holder"
	e.Activity = func() identity.ActivitySnapshot {
		return identity.ActivitySnapshot{Collected: time.Now(), Rows: []identity.ActivityRow{first}}
	}
	e.ConnectionSample = func(uint16) identity.ConnectionSample {
		return identity.ConnectionSample{
			Activity: identity.ActivitySnapshot{Collected: time.Now(),
				Rows: []identity.ActivityRow{foreign, replacement, newNS},
				Processes: map[string]identity.ActivityProcess{
					"self":  {UID: uid, PID: 3, Application: identity.Application{Kind: "native", Key: "self", Revision: "one"}},
					"other": {UID: 1001, PID: 7, Executable: "/foreign/secret"},
				}},
			Confirmed: map[string]bool{identity.ConnectionKey(replacement.Socket): true},
		}
	}
	result, code, detail := e.analyzeConnections(&ConnectionAnalysisQuery{WatchMS: 1}, uid, false, "self")
	if code != "" || len(result.Connections) != 3 || result.Recovered != 0 || result.LatestVerified != 1 {
		t.Fatalf("unexpected analysis %+v %s %s", result, code, detail)
	}
	old := result.Connections[0].Observations[1]
	next := result.Connections[1].Observations[0]
	otherNS := result.Connections[2].Observations[0]
	if old.Category != "not-observed" || len(old.Holders) != 0 ||
		next.Application == nil || next.Application.Key != "self" || len(next.Holders) != 1 ||
		otherNS.Category != "unconfirmed-socket" || otherNS.Application != nil || len(otherNS.Holders) != 0 {
		t.Fatalf("crossed observation boundary: %+v %+v %+v", old, next, otherNS)
	}
}

func TestConnectionAnalysisAcceptsOnlyFreshMatchingRuntimeEvidence(t *testing.T) {
	for _, example := range []struct{ name, prefix, cookie string }{
		{"window-a.exe", "/fixtures/prefix-a", "ab00000000000000"},
		{"window-b.exe", "/fixtures/prefix-b", "bc00000000000000"},
	} {
		t.Run(example.name, func(t *testing.T) {
			application := identity.Application{Kind: "wine", Key: example.prefix + example.name,
				Revision: "stamp", Prefix: example.prefix, Name: example.name}
			row := identity.ActivityRow{
				Socket: identity.Socket{Cookie: example.cookie},
				Owners: []string{"broker"},
				RuntimeApplication: &identity.RuntimeApplication{Application: application, UID: 1000,
					Evidence: identity.TableEvidence{SocketCookie: example.cookie, BrokerPID: 48, BrokerStart: "21", UID: 1000}},
			}
			s := identity.ActivitySnapshot{Processes: map[string]identity.ActivityProcess{"broker": {PID: 48, Start: "21", UID: 1000}}}
			if app := analysisApplication(s, row); app == nil || app.Key != application.Key || app.Prefix != example.prefix {
				t.Fatalf("missing fresh runtime result %+v", app)
			}
			row.RuntimeApplication.DisplaySource = "last-verified-snapshot"
			if app := analysisApplication(s, row); app != nil {
				t.Fatalf("cached label presented as fresh: %+v", app)
			}
			row.RuntimeApplication.DisplaySource = ""
			row.Socket.Cookie = "cc00000000000000"
			if app := analysisApplication(s, row); app != nil {
				t.Fatalf("runtime label transferred to a different socket: %+v", app)
			}
		})
	}
}
