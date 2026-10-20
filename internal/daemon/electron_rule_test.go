package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Allow Heroic must not mean Allow every program run by /usr/bin/electron: an
// Electron runtime whose hosted app is unverified gets Once/For a while only.
func TestUnverifiedElectronRuntimeRefusesRememberedRules(t *testing.T) {
	e, f, a, _ := fixture()
	e.Timeout = time.Minute
	e.SaveRules = func([]policy.Rule) error { return nil }
	a.Application.Kind = "native"
	a.Application.Executable = "/usr/lib/electron43/electron"
	a.Application.Hosted = &identity.Hosted{State: "unverified", Runtime: "/usr/lib/electron43/electron", Reason: "the parent of utility process 42 is gone"}
	v := e.Observe(f, "udp")
	_, err := e.PreviewDecision(e.Generation, v.ID, "allow", "application", "any", e.Zones.Revision, 1000, false)
	if err == nil || !strings.Contains(err.Error(), "runs many Electron applications") {
		t.Fatalf("Remember preview must be refused: %v", err)
	}
	if _, err := e.Decide(v.ID, "allow", "persistent", 1000, false); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("legacy Remember must be refused: %v", err)
	}
	if len(e.rules) != 0 {
		t.Fatal("no rule may exist", e.rules)
	}
	if r, err := e.Decide(v.ID, "allow", "once", 1000, false); err != nil || r.State != "allowed" {
		t.Fatalf("Once stays available: %v %v", r, err)
	}
	// Verified: the bundle is the identity and Remember works.
	v2f := f
	v2f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
	a.Application.Kind, a.Application.Executable, a.Application.Hosted = "electron", "/usr/lib/heroic-games-launcher/app.asar", &identity.Hosted{State: "verified"}
	v2 := e.Observe(v2f, "udp")
	if _, err := e.PreviewDecision(e.Generation, v2.ID, "allow", "application", "any", e.Zones.Revision, 1000, false); err != nil {
		t.Fatalf("verified Electron app may be remembered: %v", err)
	}
}
