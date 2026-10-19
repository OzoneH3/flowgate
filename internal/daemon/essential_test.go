package daemon

import (
	"context"
	"errors"
	"flowgate/internal/essential"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func essentialEnvironment(t *testing.T) (essential.Environment, *string) {
	t.Helper()
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	server := "192.0.2.53"
	env := essential.Environment{Read: os.ReadFile, Sockets: func() ([]identity.Socket, error) { return nil, nil }, Inspect: func(_ int) (identity.Process, error) {
		q := p
		q.Cgroup = "0::/system.slice/systemd-resolved.service"
		return q, nil
	}, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			if args[1] == "systemd-resolved.service" {
				return []byte("ActiveState=active\nMainPID=" + strconv.Itoa(p.PID)), nil
			}
			return []byte("ActiveState=inactive\nMainPID=0"), nil
		}
		if name == "resolvectl" {
			return []byte(`[{"servers":[{"addressString":"` + server + `","port":53}]}]`), nil
		}
		return []byte(""), nil
	}}
	return env, &server
}
func TestEssentialAPIAtomicReplayStaleRemove(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("run compiled fixture in private user namespace for real root-peer API authorization")
	}
	env, server := essentialEnvironment(t)
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.Now = time.Now
		e.Essential = essential.NewManager(env)
		e.Essential.Refresh(context.Background())
	})
	options := essential.Options{}
	call := func(op, token string) Response {
		return callResponse(a.path, Request{Version: 1, Operation: op, Generation: a.e.Generation, PreviewToken: token, EssentialOptions: &options})
	}
	p := call("essential-preview", "")
	if p.Error != "" || p.EssentialPreview == nil || len(p.EssentialPreview.Rules) != 2 {
		t.Fatalf("preview %+v", p)
	}
	saved := call("essential-apply", p.EssentialPreview.Token)
	if saved.Error != "" || len(saved.EssentialReceipt.Rules) != 2 {
		t.Fatalf("save %+v", saved)
	}
	replay := call("essential-apply", p.EssentialPreview.Token)
	if replay.Error != "" || !replay.Replayed {
		t.Fatal("replay", replay)
	}
	receipt := call("essential-status", p.EssentialPreview.Token)
	if receipt.Error != "" || receipt.EssentialReceipt == nil {
		t.Fatal(receipt)
	}
	fresh := call("essential-preview", "")
	if len(fresh.EssentialPreview.Rules) != 0 || len(fresh.EssentialPreview.Preserved) != 2 {
		t.Fatal("duplicate", fresh)
	}
	*server = "192.0.2.54"
	stale := call("essential-apply", fresh.EssentialPreview.Token)
	if stale.ErrorCode != "preset_stale" {
		t.Fatal("stale", stale)
	}
	// A disabled/user-modified record is preserved even by preset removal.
	a.e.mu.Lock()
	edited := a.e.rules[0]
	edited.Disabled = true
	edited.Version++
	next := append([]policy.Rule{}, a.e.rules...)
	next[0] = edited
	if err := a.e.publishRulesLocked(next); err != nil {
		t.Fatal(err)
	}
	a.e.mu.Unlock()
	rem := call("essential-remove-preview", "")
	if rem.Error != "" || len(rem.EssentialPreview.Rules) != 1 || len(rem.EssentialPreview.Preserved) != 1 {
		t.Fatal(rem)
	}
	done := call("essential-remove", rem.EssentialPreview.Token)
	if done.Error != "" || len(done.EssentialReceipt.Removed) != 1 {
		t.Fatal(done)
	}
	rules, err := a.s.Load()
	if err != nil || len(rules) != 1 || !rules[0].Disabled {
		t.Fatal("edited rule removed", rules, err)
	}
	// Persisted metadata remains readable after restart, and old generation cannot replay.
	if err := a.e.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	bad := callResponse(a.path, Request{Version: 1, Operation: "essential-apply", Generation: "old", PreviewToken: rem.EssentialPreview.Token, EssentialOptions: &options})
	if bad.ErrorCode != "generation_conflict" {
		t.Fatal(bad)
	}
}
func TestEssentialScopeGuardsAndPersistenceFailure(t *testing.T) {
	env, _ := essentialEnvironment(t)
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.Now = time.Now
		e.Essential = essential.NewManager(env)
		e.Essential.Refresh(context.Background())
	})
	o := essential.Options{}
	p, err := a.e.PreviewEssential(a.e.Generation, "apply", o, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.e.SaveRules = func([]policy.Rule) error { return errors.New("disk failed") }
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", o, 0); err == nil || !strings.Contains(err.Error(), "disk failed") {
		t.Fatal(err)
	}
	if len(a.e.Rules(0, true)) != 0 {
		t.Fatal("partial commit")
	}
	a.e.Enforcement = func() EnforcementStatus { return EnforcementStatus{State: "active"} }
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", o, 0); err == nil {
		t.Fatal("mutation while active")
	}
}

func TestEssentialOrdinaryClientCannotManageMachinePreset(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ordinary-peer check is run outside the private root fixture")
	}
	env, _ := essentialEnvironment(t)
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.Essential = essential.NewManager(env)
		e.Essential.Refresh(context.Background())
	})
	o := essential.Options{}
	r := callResponse(a.path, Request{Version: 1, Operation: "essential-preview", Generation: a.e.Generation, EssentialOptions: &o})
	if r.ErrorCode != "forbidden" || r.EssentialPreview != nil {
		t.Fatal(r)
	}
}
