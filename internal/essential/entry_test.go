package essential

import (
	"context"
	"errors"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"strconv"
	"testing"
	"time"
)

var (
	lanA = DNS{"172.30.42.128", 53, 2, "enp7s0", false}
	lanB = DNS{"172.30.42.250", 53, 2, "enp7s0", false}
	vpn4 = DNS{"100.100.100.100", 53, 7, "tailscale0", false}
	vpn6 = DNS{"fd7a:115c:a1e0::53", 53, 7, "tailscale0", false}
)

func snapshot(t *testing.T, p identity.Process, dns ...DNS) Snapshot {
	t.Helper()
	s := Snapshot{Collected: time.Now(), DNS: append([]DNS{}, dns...), Stubs: []Stub{{"127.0.0.53", "udp", 1}, {"127.0.0.53", "tcp", 1}, {"127.0.0.54", "udp", 1}}, Components: []Component{{ID: "dns", State: "ready", Service: &p}, {ID: "dns-stub-client", State: "ready", Service: &p}}}
	if len(dns) == 0 {
		s.Components[0].State = "unavailable" // explicit "no active upstream" observation
	}
	s.Seal()
	return s
}
func rules(t *testing.T, s Snapshot) []policy.Rule {
	t.Helper()
	r, _, err := s.Rules(Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func isVPN(r policy.Rule) bool { return r.Filter.InterfaceName == "tailscale0" }

func TestVPNDNSRemovalKeepsUnchangedLANAndStubRules(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	stored := rules(t, snapshot(t, p, lanA, lanB, vpn4, vpn6))
	if len(stored) != 8+3+3 {
		t.Fatalf("want 8 upstream + 3 incoming stub + 3 stub-client, got %d", len(stored))
	}
	after := snapshot(t, p, lanA, lanB) // Tailscale down: resolved drops tailscale0 servers
	for _, r := range stored {
		if got, want := after.EntryActive(r), !isVPN(r); got != want {
			t.Fatalf("%s %s %s active=%v, want %v", r.Preset.Component, r.Filter.InterfaceName, r.Filter.RemoteAddress, got, want)
		}
	}
	// Returning to the identical set reactivates the same stored records unchanged.
	back := snapshot(t, p, lanA, lanB, vpn4, vpn6)
	for _, r := range stored {
		if !back.EntryActive(r) {
			t.Fatalf("identical configuration did not reactivate %s", r.ID)
		}
	}
}

func TestVPNDNSAdditionNeedsApprovalAndLeavesExistingActive(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	stored := rules(t, snapshot(t, p, lanA, lanB))
	after := snapshot(t, p, lanA, lanB, vpn4) // new destination appears (like ppp0 on the host)
	have := map[string]bool{}
	for _, r := range stored {
		have[r.ID] = true
		if !after.EntryActive(r) {
			t.Fatalf("existing entry invalidated by an unrelated addition: %s", r.Filter.RemoteAddress)
		}
	}
	added := 0
	for _, r := range rules(t, after) {
		if !have[r.ID] {
			added++
			if r.Filter.RemoteAddress != vpn4.Address {
				t.Fatalf("unexpected new proposal %+v", r.Filter)
			}
		}
	}
	if added != 2 { // udp+tcp to the new server only; nothing stored grants it
		t.Fatalf("want 2 new reviewable rules, got %d", added)
	}
}

func TestStubPermissionsIndependentOfUpstreamSet(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	stored := rules(t, snapshot(t, p, lanA))
	none := snapshot(t, p) // no upstream at all; resolver identity and stubs unchanged
	stubs := 0
	for _, r := range stored {
		upstream := r.Preset.Component == "dns" && r.Filter.Direction == "outgoing"
		if none.EntryActive(r) == upstream {
			t.Fatalf("%s %s: upstream=%v but active=%v", r.Preset.Component, r.Filter.RemoteAddress, upstream, none.EntryActive(r))
		}
		if !upstream {
			stubs++
		}
	}
	if stubs != 6 {
		t.Fatalf("want 6 stub rules active, got %d", stubs)
	}
}

func TestInterfaceRenumberingKeepsEntriesActive(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	stored := rules(t, snapshot(t, p, lanA, vpn4))
	a, v := lanA, vpn4
	a.Interface, v.Interface = 3, 41
	after := snapshot(t, p, v, a)
	for _, r := range stored {
		if !after.EntryActive(r) {
			t.Fatalf("renumbered interface invalidated %s", r.Filter.RemoteAddress)
		}
	}
}

func TestResolverIdentityChangeInvalidatesItsEntries(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	stored := rules(t, snapshot(t, p, lanA))
	q := p
	q.Application.Revision += "-upgraded"
	q.ExecutableRevision = q.Application.Revision
	after := snapshot(t, q, lanA)
	for _, r := range stored {
		if after.EntryActive(r) {
			t.Fatalf("old executable revision still active: %s", r.ID)
		}
	}
}

// Fake host: resolved (+ optional tailscale0 DNS) and an injectable probe failure.
func fakeEnv(p identity.Process, vpn *bool, broken *bool, inactive *bool) Environment {
	return Environment{Inspect: func(pid int) (identity.Process, error) {
		q := p
		q.Cgroup = "0::/system.slice/systemd-resolved.service"
		return q, nil
	}, Read: os.ReadFile, Sockets: func() ([]identity.Socket, error) { return []identity.Socket{}, nil }, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if *broken && name == "resolvectl" {
			return nil, errors.New("transient bus error")
		}
		if name == "systemctl" {
			if args[1] == "systemd-resolved.service" && !*inactive {
				return []byte("MainPID=" + strconv.Itoa(p.PID) + "\nActiveState=active"), nil
			}
			return []byte("MainPID=0\nActiveState=inactive"), nil
		}
		if name == "resolvectl" {
			out := `[{"ifname":"enp7s0","ifindex":2,"servers":[{"addressString":"172.30.42.128","port":53}]}`
			if *vpn {
				out += `,{"ifname":"tailscale0","ifindex":7,"servers":[{"addressString":"100.100.100.100","port":53}]}`
			}
			return []byte(out + "]"), nil
		}
		return []byte(""), nil
	}}
}

func TestUnsuccessfulRefreshRetainsSnapshotWithoutExtension(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	vpn, broken, inactive := true, false, false
	m := NewManager(fakeEnv(p, &vpn, &broken, &inactive))
	good := m.Refresh(context.Background())
	if good.Revision == "" || len(good.Failures) != 0 {
		t.Fatalf("baseline discovery failed: %v", good.Failures)
	}
	stored, _, _ := good.Rules(Options{}, time.Now())
	broken = true
	if s := m.Refresh(context.Background()); s.Revision != "" {
		t.Fatal("unsuccessful refresh reported as fresh")
	}
	kept := m.Snapshot()
	if kept.Revision != good.Revision || !kept.ValidUntil.Equal(good.ValidUntil) {
		t.Fatal("still-valid snapshot discarded or its expiry extended by a failed refresh")
	}
	for _, r := range stored {
		if !kept.EntryActive(r) {
			t.Fatal("transient failure removed a still-valid permission")
		}
	}
	// Once the retained snapshot expires, a failed refresh fails closed.
	m.mu.Lock()
	m.s.ValidUntil = time.Now().Add(-time.Second)
	m.mu.Unlock()
	m.Refresh(context.Background())
	if c := m.Snapshot().Component("dns"); c == nil || c.State != "unavailable" || m.Snapshot().ValidUntil.Equal(good.ValidUntil) {
		t.Fatal("expired snapshot was retained past its bound")
	}
	// Recovery: identical successful discovery restores the same entries, no re-review.
	broken = false
	m.Refresh(context.Background())
	for _, r := range stored {
		if !m.Snapshot().EntryActive(r) {
			t.Fatal("identical recovery did not restore the stored permission")
		}
	}
	// Explicit removal is applied immediately, unlike an unsuccessful probe.
	vpn = false
	m.Refresh(context.Background())
	for _, r := range stored {
		if m.Snapshot().EntryActive(r) == isVPN(r) {
			t.Fatalf("explicit removal mishandled for %s", r.Filter.RemoteAddress)
		}
	}
	inactive = true
	m.Refresh(context.Background())
	for _, r := range stored {
		if m.Snapshot().EntryActive(r) {
			t.Fatal("inactive resolver service kept permissions")
		}
	}
}
