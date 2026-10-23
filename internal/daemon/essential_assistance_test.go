package daemon

import (
	"context"
	"flowgate/internal/essential"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestEssentialAssistanceSkipsOnlyDurableCoveringAllows(t *testing.T) {
	env, _ := essentialEnvironment(t)
	e := New(time.Second)
	defer e.CloseProcessTargets()
	e.Essential = essential.NewManager(env)
	e.Essential.Refresh(context.Background())
	e.SaveRules = func([]policy.Rule) error { return nil }
	base, err := e.PreviewEssential(e.Generation, "apply", essential.Options{}, 0)
	if err != nil || len(base.Rules) != 0 {
		t.Fatalf("DNS should be opt-in: %+v %v", base, err)
	}
	opts := essential.Options{ServiceAssistance: true}
	p, err := e.PreviewEssential(e.Generation, "apply", opts, 0)
	if err != nil || len(p.Rules) != 2 {
		t.Fatalf("DNS fixture: %+v %v", p, err)
	}
	existing := p.Rules[0]
	existing.Preset = nil
	existing.Schema = 2
	existing.ID = "ordinary-allow"
	existing.Priority = 100
	existing.Filter.Protocol = "*"
	existing.Filter.RemoteAddress = "*"
	existing.Filter.RemotePort = 0
	existing.Filter.InterfaceIndex = 0
	existing.Filter.InterfaceName = ""
	if err = e.SetRules([]policy.Rule{existing}); err != nil {
		t.Fatal(err)
	}
	clean, err := e.PreviewEssential(e.Generation, "apply", opts, 0)
	if err != nil || len(clean.Rules) != 0 || len(clean.Preserved) != 1 {
		t.Fatalf("duplicate assistance: %+v %v", clean, err)
	}
	// Each negative would leave part of the service scope without durable coverage.
	for name, mutate := range map[string]func(*policy.Rule){
		"deny":              func(r *policy.Rule) { r.Action = "block" },
		"ask":               func(r *policy.Rule) { r.Action = "ask" },
		"disabled":          func(r *policy.Rule) { r.Disabled = true },
		"temporary":         func(r *policy.Rule) { r.Expires = time.Now().Add(time.Hour) },
		"other application": func(r *policy.Rule) { r.Filter.Application = "other" },
		"other revision":    func(r *policy.Rule) { r.Filter.Revision = "other" },
		"other uid":         func(r *policy.Rule) { r.Filter.UID++ },
		"incoming":          func(r *policy.Rule) { r.Filter.Direction = "incoming" },
		"other address":     func(r *policy.Rule) { r.Filter.RemoteAddress = "192.0.2.254" },
		"other port":        func(r *policy.Rule) { r.Filter.RemotePort = 853 },
		"zone":              func(r *policy.Rule) { r.Schema = 4; r.Filter.NetworkZone = "local" },
	} {
		t.Run(name, func(t *testing.T) {
			r := existing
			mutate(&r)
			if serviceAssistanceCovered(r, p.Rules[0]) {
				t.Fatal("restricted rule treated as complete coverage")
			}
		})
	}
	// Changing this choice after review must not silently enable more permissions.
	if _, _, err = e.ApplyEssential(e.Generation, base.Token, "apply", opts, 0); err == nil {
		t.Fatal("changed option accepted")
	}
}
