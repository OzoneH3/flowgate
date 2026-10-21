package policy

import (
	"flowgate/internal/identity"
	"testing"
	"time"
)

func TestPairedRootApplicationScope(t *testing.T) {
	now := time.Now()
	app := identity.Application{Kind: "native", Executable: "/usr/bin/tool", Revision: "v1"}
	app.Key = identity.ApplicationKey(1000, app)
	r := Rule{ID: "user", Schema: 2, Executable: app.Executable, Action: "allow", Created: now, Filter: Filter{Application: app.Key, Revision: app.Revision, UID: 1000, Direction: "outgoing", Protocol: "tcp"}, RootApplication: identity.ApplicationKey(0, app)}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	flow, _ := identity.ParseFlow("tcp", "outgoing", "127.0.0.1:1234", "1.2.3.4:443")
	eval := func(rules []Rule, uid uint32, a identity.Application) string {
		a.Key = identity.ApplicationKey(uid, a)
		action, _, _ := Evaluate(rules, flow, identity.Attribution{Application: &a, Owners: []identity.Process{{UID: uid}}}, now)
		return action
	}
	for _, uid := range []uint32{1000, 0} {
		if eval([]Rule{r}, uid, app) != "allow" {
			t.Fatal("paired account not allowed", uid)
		}
	}
	if eval([]Rule{r}, 970, app) != "ask" {
		t.Fatal("service account inherited permission")
	}
	other := app
	other.Executable = "/other/tool"
	if eval([]Rule{r}, 0, other) != "ask" {
		t.Fatal("different path allowed")
	}
	other = app
	other.Revision = "v2"
	if eval([]Rule{r}, 0, other) != "ask" {
		t.Fatal("different revision allowed")
	}
	for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
		other = app
		other.Kind = "wine"
		other.Prefix = prefix
		if eval([]Rule{r}, 0, other) != "ask" {
			t.Fatal("Wine identity inherited native permission")
		}
	}
	flow.Direction = "incoming"
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("direction transferred")
	}
	flow.Direction = "outgoing"
	block := r
	block.ID = "root-block"
	block.RootApplication = ""
	block.Filter.UID = 0
	block.Filter.Application = identity.ApplicationKey(0, app)
	block.Action = "block"
	if eval([]Rule{r, block}, 0, app) != "block" {
		t.Fatal("root block lost precedence")
	}
	r.Disabled = true
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("disabled shared rule allowed")
	}
	r.Disabled = false
	r.Expires = now
	if eval([]Rule{r}, 0, app) != "ask" {
		t.Fatal("expired shared rule allowed")
	}
	r.Expires = time.Time{}
	r.RootApplication = "forged"
	if r.Validate() == nil {
		t.Fatal("invalid counterpart accepted")
	}
}
