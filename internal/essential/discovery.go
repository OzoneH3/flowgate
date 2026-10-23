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

// fail records an unsuccessful probe (command/inspection error or timeout). It is
// distinct from an explicit observation such as an inactive service or a server
// absent from a successful resolver report: failed refreshes are never published
// over a still-valid snapshot.
func service(ctx context.Context, env Environment, unit, id, title string, essential bool, fail func(string)) Component {
	c := Component{ID: id, Title: title, State: "unavailable", Essential: essential, Details: []string{}}
	b, err := env.Run(ctx, "systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState")
	if err != nil {
		c.Details = append(c.Details, "Service inspection unavailable: "+err.Error())
		fail(unit + " inspection failed")
		return c
	}
	props := properties(b)
	pid, _ := strconv.Atoi(props["MainPID"])
	if props["ActiveState"] != "active" || pid <= 0 {
		c.Details = append(c.Details, "Service not active; no identity or permissions guessed")
		return c
	}
	p, err := env.Inspect(pid)
	if err != nil {
		c.Details = append(c.Details, "Live native executable identity unavailable/unsupported; root observer required")
		fail(unit + " identity inspection failed")
		return c
	}
	if p.PID != pid || p.Application.Kind != "native" || p.Application.Key == "" || p.Application.Revision == "" || p.ExecutableRevision != p.Application.Revision || p.NetNS != identity.NetNS() {
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
	s := Snapshot{Collected: time.Now(), Components: []Component{}, Issues: []string{}, DNS: []DNS{}, Stubs: []Stub{}, DHCP: []DHCP{}, NTP: []string{}, Failures: []string{}}
	fail := func(m string) { s.Failures = append(s.Failures, m) }
	dns := service(ctx, env, "systemd-resolved.service", "dns", "Optional DNS resolver assistance", false, fail)
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
		fail("resolvectl status failed")
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
			fail("socket inventory failed")
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
	stub.Title = "Local DNS stub (default localhost trust)"
	stub.Essential = false
	if len(s.Stubs) == 0 {
		stub.State = "unavailable"
		stub.Details = append(stub.Details, "No verified active loopback DNS stub listener; no client rule generated")
	}
	stub.Details = append(append([]string{}, dns.Details...), "No new localhost permissions proposed; discovery retained only to validate existing saved stub permissions")
	s.Components = append(s.Components, stub)
	nm := Component{ID: "dhcp", Title: "Interface-scoped DHCP bootstrap", Essential: true, State: "unavailable", Details: []string{}}
	s.DHCP, err = discoverDHCP(ctx, env, net.InterfaceByName)
	if err != nil {
		fail(err.Error())
	}
	if len(s.DHCP) > 0 {
		nm.State = "ready"
		nm.Details = append(nm.Details, "Protocol-only client bootstrap on active auto-addressed NM interfaces; UDP68/67 and link-local/multicast DHCPv6 546/547. Raw packet paths are not assigned fictitious process owners.")
	}
	s.Components = append(s.Components, nm)
	ntp := service(ctx, env, "systemd-timesyncd.service", "time", "Optional time synchronization assistance", false, fail)
	if ntp.State == "ready" {
		b, e := env.Run(ctx, "timedatectl", "show-timesync", "--all")
		if e != nil {
			fail("timedatectl show-timesync failed")
		} else {
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
	s.Components = append(s.Components, Component{ID: "discovery", Title: "Optional local discovery", State: "unavailable", Details: []string{"No trusted-interface policy configured; mDNS/LLMNR remain ungranted, regardless of RFC1918 addresses"}}, Component{ID: "connectivity", Title: "Optional connectivity checks and sharing", State: "optional", Details: []string{"NetworkManager URI checks, SSH, remote desktop, KDE Connect, printing/sharing require separate review; no permissions in this preset"}})
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
	failure     string
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if probe.Err() != nil || len(s.Failures) > 0 {
		// Unsuccessful refresh: keep a still-valid successful snapshot with its
		// ORIGINAL expiry (never extended), so a transient probe error is not an
		// explicit removal. Without one, fail closed: a timeout publishes nothing.
		m.failure = "Latest discovery refresh unsuccessful; retained snapshot is not extended"
		if probe.Err() != nil {
			m.failure = "Discovery timed out; retained snapshot is not extended"
		}
		if m.s.Revision == "" || !time.Now().Before(m.s.ValidUntil) {
			if probe.Err() != nil {
				m.s = Snapshot{Components: []Component{}, Issues: []string{"Discovery timed out; preset coverage unavailable"}}
			} else {
				m.s = s
			}
		}
		return Snapshot{}
	}
	m.failure = ""
	m.s = s
	return s
}
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.s
	if m.failure != "" {
		s.Issues = append(append([]string{}, s.Issues...), m.failure)
	}
	return s
}
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
