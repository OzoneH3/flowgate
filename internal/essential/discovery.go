package essential

import (
	"context"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/readiness"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Environment struct {
	Run     func(context.Context, string, ...string) ([]byte, error)
	Inspect func(int) (identity.Process, error)
	Read    func(string) ([]byte, error)
	Sockets func() ([]identity.Socket, error)
	Resolve func(identity.Flow) identity.Attribution
}

func Default() Environment {
	return Environment{Run: readiness.Run, Inspect: identity.Inspect, Read: os.ReadFile, Sockets: identity.Sockets, Resolve: identity.Resolve}
}
func properties(b []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}
func service(ctx context.Context, env Environment, unit, id, title string, essential bool) Component {
	c := Component{ID: id, Title: title, State: "unavailable", Essential: essential, Details: []string{}}
	b, err := env.Run(ctx, "systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState")
	if err != nil {
		c.Details = append(c.Details, "Service inspection unavailable: "+err.Error())
		return c
	}
	props := properties(b)
	pid, _ := strconv.Atoi(props["MainPID"])
	if props["ActiveState"] != "active" || pid <= 0 {
		c.Details = append(c.Details, "Service not active; no identity or permissions guessed")
		return c
	}
	p, err := env.Inspect(pid)
	if err != nil || p.PID != pid || p.Application.Kind != "native" || p.Application.Key == "" || p.Application.Revision == "" || p.ExecutableRevision != p.Application.Revision || p.NetNS != identity.NetNS() {
		c.Details = append(c.Details, "Live native executable identity unavailable/unsupported; root observer required")
		return c
	}
	unitBound := false
	for _, part := range strings.Split(strings.TrimSpace(p.Cgroup), "/") {
		if part == unit {
			unitBound = true
		}
	}
	if !unitBound {
		c.Details = append(c.Details, "Unit/process cgroup binding not verified")
		return c
	}
	c.State = "ready"
	c.Service = &p
	c.Details = append(c.Details, fmt.Sprintf("%s UID%d; exact running executable revision; application scope", p.Executable, p.UID))
	return c
}
func Discover(ctx context.Context, env Environment) Snapshot {
	s := Snapshot{Collected: time.Now(), Components: []Component{}, Issues: []string{}, DNS: []DNS{}, Stubs: []Stub{}, DHCP: []DHCP{}, NTP: []string{}}
	dns := service(ctx, env, "systemd-resolved.service", "dns", "DNS resolver and local stub", true)
	var status []struct {
		Ifname  string `json:"ifname"`
		Ifindex uint32 `json:"ifindex"`
		TLS     string `json:"dnsOverTLS"`
		Servers []struct {
			Address string `json:"addressString"`
			Port    uint16 `json:"port"`
		} `json:"servers"`
		Fallback []struct {
			Address string `json:"addressString"`
			Port    uint16 `json:"port"`
		} `json:"fallbackServers"`
		Domains []any `json:"searchDomains"`
	}
	b, err := env.Run(ctx, "resolvectl", "--json=short", "status")
	if err != nil || json.Unmarshal(b, &status) != nil {
		dns.State = "unavailable"
		dns.Details = append(dns.Details, "Structured resolved configuration unavailable; other resolvers/direct DNS require a separate adapter")
	}
	fallback := false
	for _, link := range status {
		for _, d := range link.Servers {
			if ip, e := netip.ParseAddr(d.Address); e == nil && ip.IsValid() && !ip.IsUnspecified() {
				tls := link.TLS == "yes" || link.TLS == "opportunistic"
				port := d.Port
				if port == 0 {
					port = 53
				}
				if link.TLS == "yes" {
					if port == 53 {
						port = 853
					}
					s.DNS = append(s.DNS, DNS{ip.Unmap().String(), port, link.Ifindex, link.Ifname, true})
					continue
				}
				s.DNS = append(s.DNS, DNS{ip.Unmap().String(), port, link.Ifindex, link.Ifname, false})
				if tls {
					s.DNS = append(s.DNS, DNS{ip.Unmap().String(), 853, link.Ifindex, link.Ifname, true})
				}
			}
		}
		if len(link.Fallback) > 0 {
			fallback = true
		}
		if len(link.Domains) > 0 {
			dns.Details = append(dns.Details, "Split/search routing domains retained from authoritative per-link configuration")
		}
	}
	if len(s.DNS) == 0 {
		dns.State = "unavailable"
		dns.Details = append(dns.Details, "No active upstream configured; fallback-only selection requires explicit review, no compiled public DNS guessed")
	} else if fallback {
		dns.Details = append(dns.Details, "Configured fallback list is not granted while active per-link/global servers exist")
	}
	if dns.Service != nil && dns.State == "ready" {
		sockets, e := env.Sockets()
		if e != nil {
			dns.State = "unavailable"
			dns.Details = append(dns.Details, "Stub listener inventory unavailable")
		}
		for _, sock := range sockets {
			ip := sock.Local.Addr()
			if sock.Local.Port() != 53 || !ip.IsLoopback() || ip.String() != "127.0.0.53" && ip.String() != "127.0.0.54" {
				continue
			}
			if sock.UID != dns.Service.UID {
				continue
			}
			if sock.Protocol == "tcp" && sock.State != 10 {
				continue
			}
			resolve := env.Resolve
			if resolve == nil {
				resolve = identity.Resolve
			}
			a := resolve(identity.Flow{NetNS: identity.NetNS(), Direction: "incoming", Protocol: sock.Protocol, Local: sock.Local, Remote: netip.MustParseAddrPort("127.0.0.1:0")})
			if !a.VisibilityComplete || a.Application == nil || a.Application.Key != dns.Service.Application.Key || a.Application.Revision != dns.Service.Application.Revision || a.Principal() == nil || a.Principal().UID != dns.Service.UID {
				dns.Details = append(dns.Details, "Stub owner could not be verified; no client permission proposed")
				continue
			}
			iface, _ := net.InterfaceByName("lo")
			idx := uint32(0)
			if iface != nil {
				idx = uint32(iface.Index)
			}
			s.Stubs = append(s.Stubs, Stub{ip.String(), sock.Protocol, idx})
		}
	}
	s.Components = append(s.Components, dns)
	stub := dns
	stub.ID = "dns-stub-client"
	stub.Title = "Local applications to verified DNS stub"
	if len(s.Stubs) == 0 {
		stub.State = "unavailable"
		stub.Details = append(stub.Details, "No verified active loopback DNS stub listener; no client rule generated")
	}
	stub.Details = append(append([]string{}, dns.Details...), "All identified programs, only exact observed loopback stubs TCP/UDP53; peer executable verified at decision time; not general loopback access")
	s.Components = append(s.Components, stub)
	nm := Component{ID: "dhcp", Title: "Interface-scoped DHCP bootstrap", Essential: true, State: "unavailable", Details: []string{}}
	b, err = env.Run(ctx, "nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			uuid, name, ok := strings.Cut(line, ":")
			if !ok || name == "" || name == "lo" {
				continue
			}
			iface, e := net.InterfaceByName(name)
			if e != nil {
				continue
			}
			methods, e := env.Run(ctx, "nmcli", "-g", "ipv4.method,ipv6.method", "connection", "show", uuid)
			if e != nil {
				continue
			}
			m := strings.Fields(string(methods))
			if len(m) != 2 {
				continue
			}
			d := DHCP{name, uint32(iface.Index), m[0] == "auto", m[1] == "auto"}
			if d.IPv4 || d.IPv6 {
				s.DHCP = append(s.DHCP, d)
			}
		}
	}
	if len(s.DHCP) > 0 {
		nm.State = "ready"
		nm.Details = append(nm.Details, "Protocol-only client bootstrap on active auto-addressed NM interfaces; UDP68/67 and link-local/multicast DHCPv6 546/547. Raw packet paths are not assigned fictitious process owners.")
	}
	s.Components = append(s.Components, nm)
	ntp := service(ctx, env, "systemd-timesyncd.service", "time", "Time synchronization", true)
	if ntp.State == "ready" {
		b, e := env.Run(ctx, "timedatectl", "show-timesync", "--all")
		if e == nil {
			p := properties(b)
			if addr, e := netip.ParseAddr(p["ServerAddress"]); e == nil {
				s.NTP = append(s.NTP, addr.String())
				ntp.Details = append(ntp.Details, "Current selected source "+p["ServerName"]+" "+addr.String()+": UDP123, any local source port; pool/address changes invalidate rather than broaden")
			}
		}
		if len(s.NTP) == 0 {
			ntp.State = "unavailable"
			ntp.Details = append(ntp.Details, "Configured source unresolved; no startup DNS lookup while guard blocks. Refresh in monitoring first")
		}
	}
	if ntp.State != "ready" {
		ntp.Details = append(ntp.Details, "chronyd/other time clients are detected as unsupported by this first adapter; no inbound time service opened")
	}
	s.Components = append(s.Components, ntp)
	vpn := service(ctx, env, "tailscaled.service", "tailscale", "Optional Tailscale outer transport", false)
	if vpn.Service != nil {
		b, e := env.Read(fmt.Sprintf("/proc/%d/cmdline", vpn.Service.PID))
		if e == nil {
			args := strings.Split(string(b), "\x00")
			port := uint64(41641)
			for i, v := range args {
				if strings.HasPrefix(v, "--port=") {
					port, _ = strconv.ParseUint(strings.TrimPrefix(v, "--port="), 10, 16)
				}
				if v == "--port" && i+1 < len(args) {
					port, _ = strconv.ParseUint(args[i+1], 10, 16)
				}
			}
			s.VPNPort = uint16(port)
		}
		if s.VPNPort == 0 {
			vpn.State = "unavailable"
			vpn.Details = append(vpn.Details, "Dynamic/unknown WireGuard port cannot be silently generalized")
		}
	}
	vpn.Details = append(vpn.Details, "Explicit optional permission: Any destination TCP443 coordination/DERP, UDP3478 STUN, UDP from configured WireGuard port to variable peer ports. Inner applications remain independently controlled; no routing/ACL change. Incoming configured port and TCP80 are separate choices.")
	s.Components = append(s.Components, vpn, Component{ID: "discovery", Title: "Optional local discovery", State: "unavailable", Details: []string{"No trusted-interface policy configured; mDNS/LLMNR remain ungranted, regardless of RFC1918 addresses"}}, Component{ID: "connectivity", Title: "Optional connectivity checks and sharing", State: "optional", Details: []string{"NetworkManager URI checks, SSH, remote desktop, KDE Connect, printing/sharing require separate review; no permissions in this preset"}})
	for _, c := range s.Components {
		if c.Essential && c.State != "ready" {
			s.Issues = append(s.Issues, c.Title+": unavailable; no permission guessed")
		}
	}
	s.Seal()
	return s
}

type Manager struct {
	mu          sync.RWMutex
	refreshGate chan struct{}
	s           Snapshot
	Env         Environment
}

func NewManager(env Environment) *Manager {
	return &Manager{Env: env, refreshGate: make(chan struct{}, 1)}
}
func (m *Manager) Refresh(ctx context.Context) Snapshot {
	select {
	case m.refreshGate <- struct{}{}:
	case <-ctx.Done():
		return Snapshot{}
	}
	defer func() { <-m.refreshGate }()
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s := Discover(probe, m.Env)
	if probe.Err() != nil {
		m.mu.Lock()
		m.s = Snapshot{Components: []Component{}, Issues: []string{"Discovery timed out; preset coverage unavailable"}}
		m.mu.Unlock()
		return Snapshot{}
	}
	m.mu.Lock()
	m.s = s
	m.mu.Unlock()
	return s
}
func (m *Manager) Snapshot() Snapshot { m.mu.RLock(); defer m.mu.RUnlock(); return m.s }
func (m *Manager) Run(ctx context.Context) {
	for {
		m.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
