package daemon

import (
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"strings"
	"testing"
)

func TestUpdateMetadataIsDerivedAndNotStoredAuthority(t *testing.T) {
	app := identity.Application{Kind: "native", Executable: "/opt/program/native", Revision: "new"}
	app.Key = identity.ApplicationKey(1000, app)
	rule := policy.Rule{ID: "app", Executable: app.Executable, Filter: policy.Filter{Application: app.Key, Revision: "old", UID: 1000}}
	data, err := json.Marshal(Response{Rules: []policy.Rule{rule}, SavedRule: &rule})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"follows_updates":true`) != 2 {
		t.Fatal(string(data))
	}
	stored, err := json.Marshal(rule)
	if err != nil || strings.Contains(string(stored), "follows_updates") {
		t.Fatal("presentation flag persisted", string(stored), err)
	}
	var client policy.Rule
	if err = json.Unmarshal([]byte(`{"id":"other","executable":"/unrelated","filter":{"application":"fake","revision":"old"},"follows_updates":true}`), &client); err != nil {
		t.Fatal(err)
	}
	if client.MatchesApplication("fake", "new", 0, app) {
		t.Fatal("client metadata granted update scope")
	}
}

func TestRuntimeUpdateProjectionIsIndependentOfActivity(t *testing.T) {
	app := identity.Application{Kind: "wine", Prefix: "/prefix-a", Executable: "/games/alpha.exe", Revision: "new"}
	app.Key = identity.ApplicationKey(1000, app)
	rule := policy.Rule{ID: "alpha", Executable: app.Executable, Filter: policy.Filter{Application: app.Key, Revision: "old", UID: 1000}}
	for _, prefix := range []string{"/prefix-a", "/prefix-b"} {
		current := app
		current.Prefix = prefix
		current.Key = identity.ApplicationKey(1000, current)
		r := Response{Rules: []policy.Rule{rule}, Activity: &identity.ActivitySnapshot{Processes: map[string]identity.ActivityProcess{"p": {Application: current, UID: 1000}}}}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Rules []struct {
				FollowsUpdates bool `json:"follows_updates"`
			}
		}
		if err = json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Rules) != 1 || !decoded.Rules[0].FollowsUpdates {
			t.Fatal("projection crossed prefix", prefix, string(data))
		}
	}
}

func TestSavedNativeShapingIdentityProjection(t *testing.T) {
	const executable = "/games/alpha.exe"
	const uid = 1000
	native := identity.Application{Kind: "native", Executable: executable}
	stored := policy.Rule{Executable: executable, Filter: policy.Filter{
		Application: identity.ApplicationKey(uid, native), Revision: "saved", UID: uid,
	}}
	for _, tc := range []struct {
		name string
		edit func(*policy.Rule)
		want bool
	}{
		{"native", func(*policy.Rule) {}, true},
		{"another account", func(r *policy.Rule) { r.Filter.UID++ }, false},
		{"different path", func(r *policy.Rule) { r.Executable = "/games/beta.exe" }, false},
		{"wine alpha", func(r *policy.Rule) {
			r.Filter.Application = identity.ApplicationKey(uid, identity.Application{Kind: "wine", Executable: executable, Prefix: "/prefix-a"})
		}, false},
		{"wine beta", func(r *policy.Rule) {
			r.Executable = "/games/beta.exe"
			r.Filter.Application = identity.ApplicationKey(uid, identity.Application{Kind: "wine", Executable: r.Executable, Prefix: "/prefix-b"})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := stored
			tc.edit(&r)
			raw, err := json.Marshal(Response{Rules: []policy.Rule{r}})
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Rules []projectedRule
			}
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Rules) != 1 || response.Rules[0].NativeShapingIdentity != tc.want {
				t.Fatalf("expected native shaping identity %t: %s", tc.want, raw)
			}
		})
	}
}
