package daemon

import (
	"context"
	"errors"
	"flowgate/internal/essential"
	"flowgate/internal/policy"
	"testing"
	"time"
)

func TestEssentialMigrationRepairPersistsBeforeActivation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		env, _ := essentialEnvironment(t)
		e := New(time.Second)
		e.Now = time.Now
		e.Essential = essential.NewManager(env)
		current := e.Essential.Refresh(context.Background())
		old := current
		old.Components = append([]essential.Component(nil), current.Components...)
		for i := range old.Components {
			if p := old.Components[i].Service; p != nil {
				copy := *p
				copy.ExecutableRevision = "52:" + copy.ExecutableRevision
				copy.Application.Revision = "52:" + copy.Application.Revision
				old.Components[i].Service = &copy
			}
		}
		old.Seal()
		rules, _, err := old.Rules(essential.Options{}, time.Now())
		if err != nil || len(rules) == 0 {
			t.Fatal(err)
		}
		for i := range rules {
			if !policy.MigrateRevisions(&rules[i]) {
				t.Fatal("fixture not migrated")
			}
		}
		e.rules = rules
		calls := 0
		e.SaveRules = func(next []policy.Rule) error {
			calls++
			for _, r := range e.rules {
				if current.EntryActive(r) {
					t.Fatal("published before persistence")
				}
			}
			if fail {
				return errors.New("storage unavailable")
			}
			for _, r := range next {
				if !current.EntryActive(r) {
					t.Fatal("saved inactive migrated preset")
				}
			}
			return nil
		}
		err = e.RepairMigratedEssential()
		if (err != nil) != fail || calls != 1 {
			t.Fatalf("fail=%v err=%v calls=%d", fail, err, calls)
		}
		for _, r := range e.rules {
			if current.EntryActive(r) == fail {
				t.Fatal("wrong policy after persistence result")
			}
		}
		if !fail {
			if err = e.RepairMigratedEssential(); err != nil || calls != 1 {
				t.Fatal("repair persisted twice")
			}
			preview, err := e.PreviewEssential(e.Generation, "apply", essential.Options{}, 0)
			if err != nil || len(preview.Rules) != 0 {
				t.Fatalf("reapply duplicates repaired scope: %+v %v", preview, err)
			}
		}
	}
}
