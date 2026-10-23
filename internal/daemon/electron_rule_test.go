package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Possible Electron runtimes retain Once only; bundle and process scopes refuse.
func TestUnverifiedElectronRuntimeRefusesRememberedRules(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	a.Application.Kind = "native"
	a.Application.Executable = "/usr/lib/electron43/electron"
	a.Application.Hosted = &identity.Hosted{State: "unverified", Runtime: "/usr/lib/electron43/electron", Reason: "the parent of utility process 42 is gone"}
	v := e.Observe(f, "udp")
	if v.ScopePreviews["once"] == "" || len(v.ScopePreviews) != 1 {
		t.Fatalf("unavailable runtime scopes advertised: %v", v.ScopePreviews)
	}
	_, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", "any", e.Zones.Revision, 1000, false)
	if err == nil || !strings.Contains(err.Error(), "possible shared runtime") {
		t.Fatalf("Remember preview must be refused: %v", err)
	}
	if _, err := e.Decide(v.ID, "allow", "persistent", 1000, false); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("legacy Remember must be refused: %v", err)
	}
	if _, err := e.Decide(v.ID, "allow", ForAWhileScope, 1000, false); code(err) != "process_scope_unavailable" {
		t.Fatalf("unverified runtime must not acquire a process lease: %v", err)
	}
	if len(e.processLeases) != 0 {
		t.Fatal("refused runtime lease was stored")
	}
	if len(e.rules) != 0 {
		t.Fatal("no rule may exist", e.rules)
	}
	if r, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil || r.State != "allowed" {
		t.Fatalf("Once stays available: %v %v", r, err)
	}
	// Legacy verified labels also cannot restore bundle authority.
	v2f := f
	v2f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
	a.Application.Kind, a.Application.Executable, a.Application.Hosted = "electron", "/usr/lib/heroic-games-launcher/app.asar", &identity.Hosted{State: "verified"}
	v2 := e.Observe(v2f, "udp")
	if v2.ScopePreviews["once"] == "" || len(v2.ScopePreviews) != 1 {
		t.Fatalf("legacy runtime scopes advertised: %v", v2.ScopePreviews)
	}
	if _, err := e.PreviewDecision(e.Generation, v2.ID, "allow", "application", "any", e.Zones.Revision, 1000, false); err == nil {
		t.Fatal("legacy verified label restored application authority")
	}
}

func TestLeaseOwnerRefusesWorkerAndLegacyHostedAuthority(t *testing.T) {
	_, _, a, _ := fixture()
	a.VisibilityComplete = true
	p := a.Owners[0]
	p.PID, p.Start, p.BootID = 101, "11", "boot"
	p.ThreadGroup = 100
	a.Owners = []identity.Process{p}
	if _, err := leaseOwner(*a); code(err) != "process_scope_unavailable" {
		t.Fatalf("worker lease: %v", err)
	}
	p.ThreadGroup = p.PID
	a.Owners[0] = p
	if _, err := leaseOwner(*a); err != nil {
		t.Fatalf("ordinary native control: %v", err)
	}
	p.HolderWitness = "merged-tables"
	a.Owners[0] = p
	if _, err := leaseOwner(*a); code(err) != "process_scope_unavailable" {
		t.Fatalf("merged leader lease: %v", err)
	}
	p.HolderWitness = ""
	a.Owners[0] = p

	for _, kind := range []string{"native", "electron"} {
		for _, state := range []string{"unverified", "verified"} {
			a.Application.Kind = kind
			a.Application.Hosted = &identity.Hosted{State: state, Runtime: "/runtime/electron"}
			if _, err := leaseOwner(*a); code(err) != "process_scope_unavailable" {
				t.Fatalf("hosted %s/%s lease: %v", kind, state, err)
			}
			l := processLease{PID: p.PID, Start: p.Start, UID: p.UID, BootID: p.BootID, Application: *a.Application, Direction: "outgoing", Until: time.Now().Add(time.Hour)}
			f, _ := identity.ParseFlow("tcp", "outgoing", "192.0.2.1:4000", "198.51.100.1:443")
			if l.matches(f, *a, time.Now()) {
				t.Fatal("stored lease revived hosted authority")
			}
		}
	}
}

func TestStoredLeaseCannotAuthorizeMergedLeaderEvidence(t *testing.T) {
	_, f, a, _ := fixture()
	a.VisibilityComplete = true
	p := a.Owners[0]
	p.PID, p.ThreadGroup, p.Start, p.BootID = 101, 101, "11", "boot"
	a.Owners = []identity.Process{p}
	now := time.Now()
	l := processLease{PID: p.PID, Start: p.Start, UID: p.UID, BootID: p.BootID, Application: *a.Application, Direction: f.Direction, Until: now.Add(time.Hour)}
	if !l.matches(f, *a, now) {
		t.Fatal("ordinary leader lease control failed")
	}
	a.Owners[0].HolderWitness = "merged-tables"
	if l.matches(f, *a, now) {
		t.Fatal("existing lease authorized merged holder set")
	}
}
