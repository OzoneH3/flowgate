package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestProcessTierIdentityAndFallback(t *testing.T) {
	app := identity.Application{Key: "same", Revision: "rev", Kind: "native"}
	p := identity.Process{PID: 100, ThreadGroup: 100, Start: "123", UID: 1000, BootID: "boot", NetNS: "net", MountNS: "mnt", PIDNS: "pid", Executable: "/native", ExecutableRevision: "rev", Application: app}
	b, err := identity.BindInstance("session", p)
	if err != nil {
		t.Fatal(err)
	}
	b.ID = "0123456789abcdef0123456789abcdef"
	f, _ := identity.ParseFlow("udp", "incoming", "127.0.0.1:80", "127.0.0.2:2000")
	a := identity.Attribution{Application: &app, Owners: []identity.Process{p}, VisibilityComplete: true, Sockets: []identity.Socket{{}}}
	base := Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Direction: "incoming", Protocol: "udp"}
	ar := Rule{ID: "app", Priority: 100, Action: "block", Filter: base}
	pr := Rule{Schema: 3, ID: "process", Priority: -100, Action: "allow", Filter: base}
	pr.Filter.Process = b
	rules := []Rule{ar, pr}
	check := func(want string) {
		t.Helper()
		act, _, _ := EvaluateSession(rules, f, a, time.Now(), "session")
		if act != want {
			t.Fatalf("want %s got %s", want, act)
		}
	}
	check("allow")
	act, _, _ := Evaluate(rules, f, a, time.Now())
	if act != "block" {
		t.Fatal("legacy evaluator granted process authority")
	}
	for _, what := range []string{"sibling", "start", "uid", "namespace", "revision", "shared", "incomplete", "session", "holder-witness"} {
		t.Run(what, func(t *testing.T) {
			x := a
			x.Owners = append([]identity.Process{}, a.Owners...)
			s := "session"
			switch what {
			case "sibling":
				x.Owners[0].PID++
			case "start":
				x.Owners[0].Start = "124"
			case "uid":
				x.Owners[0].UID++
			case "namespace":
				x.Owners[0].NetNS = "foreign"
			case "revision":
				x.Owners[0].ExecutableRevision = "changed"
			case "shared":
				x.Owners = append(x.Owners, p)
			case "incomplete":
				x.VisibilityComplete = false
			case "session":
				s = "new"
			case "holder-witness":
				x.Owners[0].HolderWitness = "merged"
			}
			act, id, _ := EvaluateSession(rules, f, x, time.Now(), s)
			if id == pr.ID || act == "allow" {
				t.Fatal("unsafe process grant", act, id)
			}
		})
	}
	pr.Action = "block"
	ar.Action = "allow"
	rules = []Rule{ar, pr}
	check("block")
	pr.Disabled = true
	rules = []Rule{ar, pr}
	check("allow")
	pr.Disabled = false
	pr.Expires = time.Now().Add(-time.Second)
	rules = []Rule{ar, pr}
	check("allow")
	pr.Expires = time.Time{}
	p2 := pr
	p2.ID = "aaa"
	p2.Action = "allow"
	rules = []Rule{pr, p2, ar}
	// NetLimiter: on equal weight Deny is applied before Allow (not ID order).
	check("block")
}
