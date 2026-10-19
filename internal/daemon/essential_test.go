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
	manager := a.e.Essential
	a.e.Essential = nil
	inventory := call("list", "")
	if !strings.Contains(strings.Join(inventory.Capabilities, ","), EssentialCapability) {
		t.Fatal("schema5 inventory omitted capability")
	}
	a.e.Essential = manager
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

func TestEssentialStaleExpiryInventoryAndLegacyEditor(t *testing.T) {
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
	changed := o
	changed.Tailscale = true
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", changed, 0); err == nil || !strings.Contains(err.Error(), "Options") {
		t.Fatal("options mismatch", err)
	}
	before := a.e.Now
	a.e.Now = func() time.Time { return p.ExpiresAt.Add(time.Second) }
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", o, 0); err == nil {
		t.Fatal("expired preview saved")
	}
	a.e.Now = before
	p, err = a.e.PreviewEssential(a.e.Generation, "apply", o, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.e.mu.Lock()
	a.e.rules = append(a.e.rules, policy.Rule{Schema: 2, ID: "user", Version: 1, Action: "block", Filter: policy.Filter{Application: "a", Revision: "r", Protocol: "tcp", Direction: "outgoing"}})
	a.e.mu.Unlock()
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", o, 0); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatal("inventory change accepted", err)
	}
}

// Applied records are validated per endpoint: losing VPN DNS (Tailscale down)
// deactivates only those records; unchanged LAN DNS stays active without re-apply.
func TestEssentialVPNDNSRemovalKeepsAppliedLANActive(t *testing.T) {
	env, _ := essentialEnvironment(t)
	links := `[{"ifname":"lo","ifindex":1,"servers":[{"addressString":"192.0.2.53","port":53}]},{"ifname":"tailscale0","ifindex":9,"servers":[{"addressString":"100.100.100.100","port":53}]}]`
	run := env.Run
	env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "resolvectl" {
			return []byte(links), nil
		}
		return run(ctx, name, args...)
	}
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.Now = time.Now
		e.Essential = essential.NewManager(env)
		e.Essential.Refresh(context.Background())
	})
	p, err := a.e.PreviewEssential(a.e.Generation, "apply", essential.Options{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", essential.Options{}, 0); err != nil {
		t.Fatal(err)
	}
	links = `[{"ifname":"lo","ifindex":1,"servers":[{"addressString":"192.0.2.53","port":53}]}]`
	if s := a.e.Essential.Refresh(context.Background()); s.Revision == "" {
		t.Fatal("refresh failed")
	}
	vpn, lan := 0, 0
	for _, r := range a.e.rules {
		if r.Preset == nil {
			continue
		}
		active := a.e.presetActive(r)
		if r.Filter.InterfaceName == "tailscale0" {
			vpn++
			if active {
				t.Fatal("removed VPN DNS endpoint still active")
			}
		} else if !active {
			t.Fatalf("unchanged entry deactivated: %+v", r.Filter)
		} else {
			lan++
		}
	}
	if vpn != 2 || lan < 2 {
		t.Fatalf("unexpected applied set vpn=%d other=%d", vpn, lan)
	}
}

// Exclusions are bound to the preview token and echoed in the receipt; the
// excluded work-VPN entries are never stored, and its later removal leaves the
// applied LAN entries active.
func TestEssentialInterfaceExclusionBoundToToken(t *testing.T) {
	env, _ := essentialEnvironment(t)
	links := `[{"ifname":"lo","ifindex":1,"servers":[{"addressString":"192.0.2.53","port":53}]},{"ifname":"ppp0","ifindex":11,"servers":[{"addressString":"192.168.23.221","port":53}]}]`
	run := env.Run
	env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "resolvectl" {
			return []byte(links), nil
		}
		return run(ctx, name, args...)
	}
	a, _, _, _ := observedAPI(t, func(e *Engine, _ *store.Store) {
		e.Now = time.Now
		e.Essential = essential.NewManager(env)
		e.Essential.Refresh(context.Background())
	})
	o := essential.Options{ExcludedInterfaces: []string{"ppp0"}}
	p, err := a.e.PreviewEssential(a.e.Generation, "apply", o, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Rules {
		if r.Filter.InterfaceName == "ppp0" {
			t.Fatal("excluded interface proposed")
		}
	}
	if _, _, err = a.e.ApplyEssential(a.e.Generation, p.Token, "apply", essential.Options{}, 0); err == nil || !strings.Contains(err.Error(), "Options") {
		t.Fatal("apply without the reviewed exclusion accepted", err)
	}
	receipt, _, err := a.e.ApplyEssential(a.e.Generation, p.Token, "apply", essential.Options{ExcludedInterfaces: []string{"ppp0", "ppp0"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Options.Equal(o) || len(receipt.RuleIDs) != len(p.Rules) {
		t.Fatalf("receipt does not bind the reviewed exclusion: %+v", receipt.Options)
	}
	links = `[{"ifname":"lo","ifindex":1,"servers":[{"addressString":"192.0.2.53","port":53}]}]`
	a.e.Essential.Refresh(context.Background())
	stored := 0
	for _, r := range a.e.rules {
		if r.Preset == nil {
			continue
		}
		stored++
		if r.Filter.InterfaceName == "ppp0" || !a.e.presetActive(r) {
			t.Fatalf("unexpected stored/inactive entry after VPN DNS removal: %+v", r.Filter)
		}
	}
	if stored != len(p.Rules) {
		t.Fatalf("stored %d, reviewed %d", stored, len(p.Rules))
	}
}
