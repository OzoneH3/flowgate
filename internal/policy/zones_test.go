package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestZoneTierAndUnknown(t *testing.T) {
	app := identity.Application{Key: "a", Revision: "r", Kind: "native"}
	p := identity.Process{PID: 100, ThreadGroup: 100, Start: "1", UID: 1000, BootID: "boot", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Executable: "/native", ExecutableRevision: "r", Application: app}
	b, e := identity.BindInstance("session", p)
	if e != nil {
		t.Fatal(e)
	}
	b.ID = "0123456789abcdef0123456789abcdef"
	a := identity.Attribution{Application: &app, Owners: []identity.Process{p}, VisibilityComplete: true, Sockets: []identity.Socket{{}}}
	f, _ := identity.ParseFlow("udp", "incoming", "192.0.2.1:80", "192.0.2.2:3000")
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "local"}
	zr := Rule{Schema: 4, ID: "zone", Priority: 1000, Action: "block", Filter: Filter{AllPrograms: true, AllUIDs: true, NetworkZone: "local", Direction: "incoming", Protocol: "*"}}
	ar := Rule{Schema: 4, ID: "app", Priority: 0, Action: "allow", Filter: Filter{Application: "a", Revision: "r", UID: 1000, NetworkZone: "local", Direction: "incoming", Protocol: "*"}}
	pr := ar
	pr.ID = "process"
	pr.Priority = -1000
	pr.Action = "block"
	pr.Filter.Process = b
	for _, r := range []Rule{zr, ar, pr} {
		if e := r.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct {
		rules      []Rule
		action, id string
	}{{[]Rule{zr}, "block", "zone"}, {[]Rule{zr, ar}, "allow", "app"}, {[]Rule{zr, ar, pr}, "block", "process"}} {
		act, id, _ := EvaluateSession(tc.rules, f, a, time.Now(), "session")
		if act != tc.action || id != tc.id {
			t.Fatal(act, id)
		}
	}
	f.NetworkScope = identity.NetworkScope{State: "unavailable"}
	act, id, _ := EvaluateSession([]Rule{zr, ar, pr}, f, a, time.Now(), "session")
	if act != "ask" || id != "default-ask" {
		t.Fatal("unknown matched", act, id)
	}
	// Existing Any-zone application rule still behaves identically.
	ar.Schema = 2
	ar.Filter.NetworkZone = ""
	act, id, _ = EvaluateSession([]Rule{zr, ar, pr}, f, a, time.Now(), "session")
	if act != "allow" || id != "app" {
		t.Fatal(act, id)
	}
	act, id, _ = EvaluateSession([]Rule{zr}, f, identity.Attribution{}, time.Now(), "session")
	if act != "block" || id != "unsafe-attribution" {
		t.Fatal("global bypassed attribution")
	}
	zr.Filter.AllUIDs = false
	zr.Filter.UID = 2000
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "local"}
	act, _, _ = EvaluateSession([]Rule{zr}, f, a, time.Now(), "session")
	if act != "ask" {
		t.Fatal("cross UID")
	}
	zr.Filter.AllUIDs = true
	zr.Filter.UID = 0
	zr.Filter.Application = "forged"
	if zr.Validate() == nil {
		t.Fatal("invented application accepted")
	}
}

func TestGlobalAllowRequiresCompleteApplicationIdentity(t *testing.T) {
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.2:3000")
	f.NetworkScope = identity.NetworkScope{State: "known", Zone: "local"}
	r := Rule{Schema: 4, ID: "global", Action: "allow", Filter: Filter{AllPrograms: true, AllUIDs: true, NetworkZone: "local", Direction: "incoming", Protocol: "*"}}
	for _, app := range []identity.Application{{}, {Key: "key"}, {Revision: "revision"}} {
		a := identity.Attribution{Application: &app, Owners: []identity.Process{{UID: 1000}}}
		act, id, _ := Evaluate([]Rule{r}, f, a, time.Now())
		if act != "block" || id != "unsafe-attribution" {
			t.Fatalf("incomplete identity got %s/%s", act, id)
		}
	}
}
