package essential

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestMigratedPresetRepairsOnlyIdenticalCurrentScope(t *testing.T) {
	oldProcess := identity.Process{UID: 974, Executable: "/synthetic/resolver", ExecutableRevision: "52:7:100:5:6", Application: identity.Application{Kind: "native", Key: "resolver-key", Executable: "/synthetic/resolver", Revision: "52:7:100:5:6"}}
	before := snapshot(t, oldProcess, lanA)
	current := oldProcess
	current.ExecutableRevision = "7:100:5:6"
	current.Application.Revision = "7:100:5:6"
	after := snapshot(t, current, lanA)
	for _, r := range rules(t, before) {
		if !policy.MigrateRevisions(&r) {
			t.Fatal("fixture must migrate")
		}
		if after.EntryActive(r) {
			t.Fatal("fixture did not reproduce stale metadata")
		}
		fixed, ok := after.RepairMigratedRule(r, time.Now())
		if !ok || !after.EntryActive(fixed) || !policy.UneditedPreset(fixed) || fixed.ID != r.ID || fixed.Filter != r.Filter || fixed.Version != r.Version+1 {
			t.Fatalf("repair failed: %+v", fixed)
		}
		if _, ok := after.RepairMigratedRule(fixed, time.Now()); ok {
			t.Fatal("repair not one-time")
		}
		for _, mutate := range []func(*policy.Rule){
			func(x *policy.Rule) { x.Filter.RemoteAddress = "203.0.113.53" },
			func(x *policy.Rule) { x.Filter.UID++ },
			func(x *policy.Rule) { x.Filter.Application = "other" },
			func(x *policy.Rule) {
				x.Filter.Direction = "incoming"
				if r.Filter.Direction == "incoming" {
					x.Filter.Direction = "outgoing"
				}
			},
			func(x *policy.Rule) { x.Filter.LocalPort++ },
			func(x *policy.Rule) { x.Filter.PeerService.Revision = "different" },
			func(x *policy.Rule) { x.Disabled = true },
		} {
			edited := r
			p := *r.Preset
			edited.Preset = &p
			mutate(&edited)
			if _, ok := after.RepairMigratedRule(edited, time.Now()); ok {
				t.Fatal("edited rule repaired")
			}
			edited.Preset.Digest = policy.PresetDigest(edited)
			if _, ok := after.RepairMigratedRule(edited, time.Now()); ok {
				t.Fatal("different current scope repaired")
			}
		}
		changed := current
		changed.Application.Revision = "8:100:5:6"
		changed.ExecutableRevision = "8:100:5:6"
		if _, ok := snapshot(t, changed, lanA).RepairMigratedRule(r, time.Now()); ok {
			t.Fatal("new executable revision auto-approved")
		}
		if _, ok := after.RepairMigratedRule(r, after.ValidUntil); ok {
			t.Fatal("expired discovery accepted")
		}
		incomplete := after
		incomplete.Failures = []string{"resolver probe failed"}
		if _, ok := incomplete.RepairMigratedRule(r, time.Now()); ok {
			t.Fatal("incomplete discovery accepted")
		}
	}
}
