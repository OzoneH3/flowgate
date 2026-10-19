package essential

import (
	"context"
	"flowgate/internal/identity"
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
