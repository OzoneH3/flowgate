package identity

import (
	"encoding/json"
	"testing"
)

func TestPermissionPresentationNeverRestoresAuthority(t *testing.T) {
	app := Application{Kind: "electron", Key: "candidate", Revision: "revision", Executable: "/app.asar", Runtime: "/electron", Hosted: &Hosted{State: "best-effort", Runtime: "/electron", Bundle: "/app.asar"}, bestEffortElectron: true}
	original := Attribution{Application: &app, Owners: []Process{{UID: 1000, PID: 20, Start: "1", Application: app}}, VisibilityComplete: true}
	target := DescribePermissionTarget(original)
	if target.Kind != "application" {
		t.Fatal(target)
	}
	b, _ := json.Marshal(original)
	var copy Attribution
	if err := json.Unmarshal(b, &copy); err != nil {
		t.Fatal(err)
	}
	copy = copy.WithPermissionPresentation(*target)
	check := func(a Attribution, want string) {
		t.Helper()
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Target PermissionTarget `json:"permission_target"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if out.Target.Kind != want {
			t.Fatalf("target=%+v want %s", out.Target, want)
		}
	}
	check(copy, "application")
	if BestEffortElectron(*copy.Application) || RuntimeRuleBlocked(copy.Application) == "" {
		t.Fatal("presentation restored authority")
	}
	copy.Owners[0].UID++
	check(copy, "runtime-unverified")
	copy.Owners = nil
	check(copy, "unavailable")
	copy.Application = nil
	check(copy, "")
}
