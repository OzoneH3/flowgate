package daemon

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestUnverifiedRuntimeProcessRememberAndLease(t *testing.T) {
	for _, mode := range []string{"remember", "lease"} {
		t.Run(mode, func(t *testing.T) {
			e, f, a, _ := fixture()
			e.Timeout = time.Minute
			e.SaveRules = func([]policy.Rule) error { return nil }
			defer e.CloseProcessTargets()
			p, err := identity.Inspect(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			p.Application.Hosted = &identity.Hosted{State: "unverified", Runtime: p.Executable, Bundle: "/synthetic/claimed-bundle"}
			*a = identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}, Sockets: []identity.Socket{{}}, VisibilityComplete: true, Fingerprint: "verified-socket-owner"}
			if !identity.NativeProcessAuthority(*a) {
				t.Fatalf("native authority: %+v", p)
			}
			v := e.Observe(f, "udp")
			if v.ScopePreviews["process-remember"] == "" || v.ScopePreviews["application"] != "" {
				t.Fatal(v.ScopePreviews)
			}
			opts := RememberOptions{Fields: &RememberFields{Process: true}}
			if mode == "remember" {
				preview, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.UID, false, opts)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := e.DecideReviewed(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, preview.Token, p.UID, false, opts); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := e.Decide(v.ID, "allow", ForAWhileScope, p.UID, false); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 12; i++ {
				f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
				if got := e.Observe(f, "udp"); got.State != "allowed" {
					t.Fatalf("repeat %d: %+v", i, got)
				}
			}
			original := *a
			for _, change := range []string{"pid", "start", "uid", "direction", "worker", "revision", "legacy"} {
				*a = original
				a.Owners = append([]identity.Process(nil), original.Owners...)
				app := *original.Application
				a.Application = &app
				f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
				testFlow := f
				switch change {
				case "pid":
					a.Owners[0].PID++
					a.Owners[0].ThreadGroup = a.Owners[0].PID
				case "start":
					a.Owners[0].Start += "0"
				case "uid":
					a.Owners[0].UID++
				case "direction":
					if testFlow.Direction == "incoming" {
						testFlow.Direction = "outgoing"
					} else {
						testFlow.Direction = "incoming"
					}
				case "worker":
					a.Owners[0].HolderWitness = "merged"
				case "revision":
					app.Revision += "new"
				case "legacy":
					app.Kind = "electron"
				}
				if got := e.Observe(testFlow, "udp"); got.State == "allowed" {
					t.Fatalf("permission widened to %s", change)
				}
			}
			*a = original
			f.Remote = netip.AddrPortFrom(f.Remote.Addr(), f.Remote.Port()+1)
			v = e.Observe(f, "udp")
			if _, err := e.PreviewDecision(e.Generation, v.ID, "allow", "persistent", "any", e.Zones.Revision, p.UID, false, RememberOptions{Fields: &RememberFields{}}); err == nil {
				t.Fatal("application-wide Remember accepted")
			}

		})
	}
}
