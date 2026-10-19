package essential

import (
	"context"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestRulesScopesAndRevisions(t *testing.T) {
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Collected: time.Now(), Components: []Component{}, DNS: []DNS{{"192.0.2.53", 53, 2, "test0", false}}, Stubs: []Stub{{"127.0.0.53", "udp", 1}, {"127.0.0.53", "tcp", 1}}, NTP: []string{"192.0.2.123"}, DHCP: []DHCP{{"test0", 2, true, true}}, VPNPort: 41641}
	for _, id := range []string{"dns", "dns-stub-client", "dhcp", "time", "tailscale"} {
		s.Components = append(s.Components, Component{ID: id, State: "ready", Service: &p, Details: []string{}})
	}
	s.Seal()
	rules, _, err := s.Rules(Options{}, time.Now())
	if err != nil || len(rules) != 9 {
		t.Fatal(len(rules), err)
	}
	for _, r := range rules {
		if !r.Expires.IsZero() || r.Preset == nil {
			t.Fatal("invalid provenance", r)
		}
		if r.Preset.Component == "time" && (r.Filter.Direction != "outgoing" || r.Filter.LocalPort != 0 || r.Filter.RemotePort != 123) {
			t.Fatal("inbound time permission")
		}
	}
	more, _, err := s.Rules(Options{Tailscale: true, TailscaleIncoming: true, TailscaleHTTP: true}, time.Now())
	if err != nil || len(more) != len(rules)+5 {
		t.Fatal(err, len(more))
	}
	orig := s.Component("dns").Revision
	s.Components[0].Service = &p
	before := p.PID
	p.PID = before + 1
	p.Start = "restarted"
	s.Seal()
	if s.Component("dns").Revision != orig {
		t.Fatal("application permission should survive process restart")
	}
	s.DNS[0].Address = "192.0.2.54"
	s.Seal()
	if s.Component("dns").Revision == orig {
		t.Fatal("configuration change not invalidating")
	}
}
func TestStructuredDiscoveryNotWrappedOrGuessed(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	env := Environment{Inspect: func(pid int) (identity.Process, error) {
		q := p
		q.Cgroup = "0::/system.slice/systemd-resolved.service"
		return q, nil
	}, Read: os.ReadFile, Sockets: func() ([]identity.Socket, error) { return []identity.Socket{}, nil }, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			unit := args[1]
			if unit == "systemd-resolved.service" {
				return []byte("MainPID=" + strconv.Itoa(p.PID) + "\nActiveState=active"), nil
			}
			return []byte("MainPID=0\nActiveState=inactive"), nil
		}
		if name == "resolvectl" {
			return []byte(`[{"servers":[{"addressString":"192.0.2.53","port":53}],"fallbackServers":[{"addressString":"8.8.8.8"}]}]`), nil
		}
		return []byte(""), nil
	}}
	s := Discover(context.Background(), env)
	if len(s.DNS) != 1 || s.DNS[0].Address != "192.0.2.53" || s.Component("dns").State != "ready" {
		t.Fatal(s)
	}
	if _, err := netip.ParseAddr(s.DNS[0].Address); err != nil {
		t.Fatal(err)
	}
}

func TestTimeAndVPNDoNotExemptOtherPrograms(t *testing.T) {
	p, err := identity.Inspect(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := Snapshot{Collected: time.Now(), NTP: []string{"192.0.2.123"}, VPNPort: 41641}
	for _, id := range []string{"time", "tailscale"} {
		s.Components = append(s.Components, Component{ID: id, State: "ready", Service: &p})
	}
	s.Seal()
	rules, _, err := s.Rules(Options{Tailscale: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attr := identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}}
	for _, tc := range []struct {
		proto, dir, local, remote string
		other                     bool
		want                      string
	}{
		{"udp", "outgoing", "192.0.2.1:40000", "192.0.2.123:123", false, "allow"},
		{"udp", "incoming", "192.0.2.1:123", "192.0.2.123:40000", false, "ask"},
		{"udp", "outgoing", "192.0.2.1:40000", "192.0.2.124:123", false, "ask"},
		{"tcp", "outgoing", "192.0.2.1:40000", "198.51.100.10:443", false, "allow"},
		{"udp", "outgoing", "192.0.2.1:41641", "198.51.100.10:50000", false, "allow"},
		{"udp", "outgoing", "192.0.2.1:40000", "198.51.100.10:50000", false, "ask"},
		{"tcp", "outgoing", "192.0.2.1:40000", "198.51.100.10:443", true, "ask"},
		{"udp", "outgoing", "192.0.2.1:41641", "198.51.100.10:50000", true, "ask"},
	} {
		f, _ := identity.ParseFlow(tc.proto, tc.dir, tc.local, tc.remote)
		a := attr
		if tc.other {
			app := p.Application
			app.Key = "independent-inner-application"
			a.Application = &app
		}
		action, _, _ := policy.Evaluate(rules, f, a, time.Now())
		if action != tc.want {
			t.Fatalf("%+v: %s", tc, action)
		}
	}
}

func TestDiscoveryTimeoutInvalidatesInsteadOfPublishingPartialSuccess(t *testing.T) {
	env := Default()
	env.Run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	m := NewManager(env)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if s := m.Refresh(ctx); s.Revision != "" {
		t.Fatal("partial discovery claimed fresh")
	}
	if m.Snapshot().ValidUntil.After(time.Now()) {
		t.Fatal("timeout coverage remained active")
	}
}

func TestStableOrderingAndRevisionRejection(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	s := Snapshot{Collected: time.Now(), DNS: []DNS{{"192.0.2.2", 53, 2, "test0", false}, {"192.0.2.1", 53, 2, "test0", false}}, Components: []Component{{ID: "dns", State: "ready", Service: &p}}}
	s.Seal()
	first := s.Revision
	s.DNS[0], s.DNS[1] = s.DNS[1], s.DNS[0]
	s.Seal()
	if first != s.Revision {
		t.Fatal("order-only change invalidated preview")
	}
	old := s.Component("dns").Revision
	p.Application.Revision = "replacement"
	p.ExecutableRevision = "replacement"
	s.Seal()
	if old == s.Component("dns").Revision {
		t.Fatal("new native executable revision inherited permission")
	}
}

func TestEncryptedDNSDoesNotGrantPlaintextWhenRequired(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	env := Default()
	env.Inspect = func(_ int) (identity.Process, error) {
		q := p
		q.Cgroup = "0::/system.slice/systemd-resolved.service"
		return q, nil
	}
	env.Sockets = func() ([]identity.Socket, error) { return nil, nil }
	env.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			if args[1] == "systemd-resolved.service" {
				return []byte("MainPID=" + strconv.Itoa(p.PID) + "\nActiveState=active"), nil
			}
			return []byte("MainPID=0\nActiveState=inactive"), nil
		}
		if name == "resolvectl" {
			return []byte(`[{"dnsOverTLS":"yes","servers":[{"addressString":"192.0.2.53","port":53}]}]`), nil
		}
		return nil, nil
	}
	s := Discover(context.Background(), env)
	rules, _, err := s.Rules(Options{}, time.Now())
	if err != nil || len(rules) != 1 || rules[0].Filter.Protocol != "tcp" || rules[0].Filter.RemotePort != 853 {
		t.Fatal("TLS-only scope broadened", rules, err)
	}
}

func TestExplicitUserPolicyOverridesPreset(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	s := Snapshot{Collected: time.Now(), NTP: []string{"192.0.2.123"}, Components: []Component{{ID: "time", State: "ready", Service: &p}}}
	s.Seal()
	rules, _, err := s.Rules(Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user := rules[0]
	user.Preset = nil
	user.Schema = 2
	user.ID = "user:explicit"
	user.Action = "block"
	f, _ := identity.ParseFlow("udp", "outgoing", "192.0.2.1:40000", "192.0.2.123:123")
	a := identity.Attribution{Application: &p.Application, Owners: []identity.Process{p}}
	for _, priority := range []int{100, 0, -1000} {
		user.Priority = priority
		action, id, _ := policy.Evaluate(append(rules, user), f, a, time.Now())
		if action != "block" || id != user.ID {
			t.Fatalf("user override lost at priority%d: %s %s", priority, action, id)
		}
	}
}

func TestInterfaceIndexReuseDoesNotDuplicateNamedPolicy(t *testing.T) {
	p, _ := identity.Inspect(os.Getpid())
	s := Snapshot{Collected: time.Now(), DNS: []DNS{{"192.0.2.53", 53, 2, "test0", false}}, Components: []Component{{ID: "dns", State: "ready", Service: &p}}}
	s.Seal()
	first, _, err := s.Rules(Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rev := s.Component("dns").Revision
	s.DNS[0].Interface = 9
	s.Seal()
	second, _, err := s.Rules(Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rev != s.Component("dns").Revision || len(first) != len(second) {
		t.Fatal("numeric index changed named policy")
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatal("duplicate ID after ifindex change")
		}
	}
}
