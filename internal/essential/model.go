// Package essential discovers and proposes host-specific permissions. It never
// mutates policy, networking, services or collectors.
package essential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"fmt"
	"sort"
	"time"
)

const Name = "essential-system-networking"

type Options struct {
	Tailscale         bool `json:"tailscale"`
	TailscaleIncoming bool `json:"tailscale_incoming"`
	TailscaleHTTP     bool `json:"tailscale_http"`
	Discovery         bool `json:"discovery"`
}
type Component struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	State     string            `json:"state"`
	Essential bool              `json:"essential"`
	Details   []string          `json:"details"`
	Service   *identity.Process `json:"service,omitempty"`
	Revision  string            `json:"revision"`
}
type DNS struct {
	Address       string `json:"address"`
	Port          uint16 `json:"port"`
	Interface     uint32 `json:"interface_index"`
	InterfaceName string `json:"interface_name"`
	TLS           bool   `json:"tls"`
}
type Stub struct {
	Address   string `json:"address"`
	Protocol  string `json:"protocol"`
	Interface uint32 `json:"interface_index"`
}
type DHCP struct {
	Name       string
	Index      uint32
	IPv4, IPv6 bool
}
type Snapshot struct {
	Revision   string      `json:"revision"`
	Components []Component `json:"components"`
	Issues     []string    `json:"issues"`
	Collected  time.Time   `json:"collected"`
	ValidUntil time.Time   `json:"valid_until"`
	DNS        []DNS       `json:"dns"`
	Stubs      []Stub      `json:"stubs"`
	DHCP       []DHCP      `json:"dhcp"`
	NTP        []string    `json:"ntp"`
	VPNPort    uint16      `json:"vpn_port"`
	// Failures lists unsuccessful probes (errors/timeouts), not observations.
	Failures []string `json:"failures,omitempty"`
	// entries maps every currently derivable preset entry ID to its revision.
	entries map[string]string
}

func Hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func (s Snapshot) Component(id string) *Component {
	for i := range s.Components {
		if s.Components[i].ID == id {
			return &s.Components[i]
		}
	}
	return nil
}
func (s *Snapshot) Seal() {
	sort.Slice(s.DNS, func(i, j int) bool { return Hash(s.DNS[i]) < Hash(s.DNS[j]) })
	sort.Slice(s.Stubs, func(i, j int) bool { return Hash(s.Stubs[i]) < Hash(s.Stubs[j]) })
	sort.Slice(s.DHCP, func(i, j int) bool { return s.DHCP[i].Name < s.DHCP[j].Name })
	sort.Strings(s.NTP)
	s.DNS = unique(s.DNS)
	s.Stubs = unique(s.Stubs)
	s.DHCP = unique(s.DHCP)
	s.NTP = unique(s.NTP)
	for i := range s.Components {
		c := &s.Components[i]
		var service any
		if c.Service != nil {
			service = []any{c.Service.UID, c.Service.Application, c.Service.ExecutableRevision}
		}
		var config any
		switch c.ID {
		case "dns":
			dns := append([]DNS{}, s.DNS...)
			for i := range dns {
				dns[i].Interface = 0
			}
			stubs := append([]Stub{}, s.Stubs...)
			for i := range stubs {
				stubs[i].Interface = 0
			}
			// Re-sort after removing kernel indexes: a recreated interface (for
			// example tailscale0) must not reorder identical named configuration.
			sort.Slice(dns, func(i, j int) bool { return Hash(dns[i]) < Hash(dns[j]) })
			sort.Slice(stubs, func(i, j int) bool { return Hash(stubs[i]) < Hash(stubs[j]) })
			config = []any{dns, stubs}
		case "dns-stub-client":
			stubs := append([]Stub{}, s.Stubs...)
			for i := range stubs {
				stubs[i].Interface = 0
			}
			sort.Slice(stubs, func(i, j int) bool { return Hash(stubs[i]) < Hash(stubs[j]) })
			config = stubs
		case "dhcp":
			dhcp := append([]DHCP{}, s.DHCP...)
			for i := range dhcp {
				dhcp[i].Index = 0
			}
			config = dhcp
		case "time":
			config = s.NTP
		case "tailscale":
			config = s.VPNPort
		}
		c.Revision = Hash([]any{c.ID, c.State, service, config})
	}
	s.Revision = Hash([]any{s.Components, s.DNS, s.Stubs, s.DHCP, s.NTP, s.VPNPort, s.Issues})
	s.ValidUntil = s.Collected.Add(30 * time.Second)
	// Index every entry derivable from this snapshot (all options), so stored
	// preset rules are validated one endpoint/interface at a time.
	s.entries = map[string]string{}
	if all, _, err := s.Rules(Options{Tailscale: true, TailscaleIncoming: true, TailscaleHTTP: true}, s.Collected); err == nil {
		for _, r := range all {
			s.entries[r.Preset.EntryID] = r.Preset.Revision
		}
	}
}

// EntryActive reports whether this exact stored preset entry (same component,
// verified service identity and endpoint/interface target) is still derived
// from the snapshot. Unrelated endpoints changing never affect it; a removed or
// changed endpoint, or a new service revision/UID, does.
func (s Snapshot) EntryActive(r policy.Rule) bool {
	return r.Preset != nil && r.Preset.Revision != "" && s.entries[r.Preset.EntryID] == r.Preset.Revision
}
func (s Snapshot) Rules(o Options, now time.Time) ([]policy.Rule, []string, error) {
	if (o.TailscaleIncoming || o.TailscaleHTTP) && !o.Tailscale {
		return nil, nil, fmt.Errorf("select optional Tailscale before its incoming/HTTP options")
	}
	rules := []policy.Rule{}
	issues := append([]string{}, s.Issues...)
	add := func(component string, f policy.Filter) {
		c := s.Component(component)
		// Resolver/stub permissions need the verified resolver identity, not a
		// non-empty upstream set: local stub access survives upstream changes.
		if c == nil || !(c.State == "ready" || (component == "dns" || component == "dns-stub-client") && c.Service != nil) {
			return
		}
		r := policy.Rule{Schema: 5, Version: 1, Created: now.UTC(), Priority: -1000, Action: "allow", Filter: f, Preset: &policy.Preset{Name: Name, Component: component}}
		if !f.AllPrograms {
			r.Executable = c.Service.Executable
		}
		target := f
		if target.InterfaceName != "" {
			target.InterfaceIndex = 0
		}
		r.Preset.EntryID = Hash([]any{component, target})
		var service any
		if c.Service != nil {
			service = []any{c.Service.UID, c.Service.Application, c.Service.ExecutableRevision}
		}
		// Per-entry revision: this endpoint/interface plus the verified identity.
		r.Preset.Revision = Hash([]any{"entry-v2", component, service, r.Preset.EntryID})
		r.ID = "preset:" + r.Preset.EntryID[:40]
		r.Preset.Digest = policy.PresetDigest(r)
		rules = append(rules, r)
	}
	app := func(id, dir, proto, remote string, local, port uint16) policy.Filter {
		c := s.Component(id)
		f := policy.Filter{Direction: dir, Protocol: proto, RemoteAddress: remote, LocalPort: local, RemotePort: port}
		if c != nil && c.Service != nil {
			f.UID = c.Service.UID
			f.Application = c.Service.Application.Key
			f.Revision = c.Service.Application.Revision
		}
		return f
	}
	if c := s.Component("dns"); c != nil && c.Service != nil {
		for _, d := range s.DNS {
			protocols := []string{"udp", "tcp"}
			if d.TLS {
				protocols = []string{"tcp"}
			}
			for _, p := range protocols {
				f := app("dns", "outgoing", p, d.Address, 0, d.Port)
				f.InterfaceIndex = d.Interface
				f.InterfaceName = d.InterfaceName
				add("dns", f)
			}
		}
		for _, stub := range s.Stubs {
			f := app("dns", "incoming", stub.Protocol, "127.0.0.0/8", 53, 0)
			f.LocalAddress = stub.Address
			f.InterfaceName = "lo"
			f.InterfaceIndex = stub.Interface
			add("dns", f)
			f = policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: stub.Protocol, RemoteAddress: stub.Address, RemotePort: 53, InterfaceName: "lo", InterfaceIndex: stub.Interface, PeerService: policy.PeerService{Application: c.Service.Application.Key, Revision: c.Service.Application.Revision, UID: c.Service.UID}}
			add("dns-stub-client", f)
		}
	}
	for _, d := range s.DHCP {
		for _, v6 := range []bool{false, true} {
			if !v6 && !d.IPv4 || v6 && !d.IPv6 {
				continue
			}
			local, remote := uint16(68), uint16(67)
			if v6 {
				local, remote = 546, 547
			}
			add("dhcp", policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "udp", RemoteAddress: "*", LocalPort: local, RemotePort: remote, InterfaceName: d.Name, InterfaceIndex: d.Index})
		}
	}
	for _, address := range s.NTP {
		add("time", app("time", "outgoing", "udp", address, 0, 123))
	}
	if o.Tailscale {
		for _, p := range []struct {
			proto         string
			local, remote uint16
		}{{"tcp", 0, 443}, {"udp", 0, 3478}, {"udp", s.VPNPort, 0}} {
			if p.proto == "udp" && p.local == 0 && p.remote == 0 {
				continue
			}
			add("tailscale", app("tailscale", "outgoing", p.proto, "*", p.local, p.remote))
		}
		if o.TailscaleIncoming && s.VPNPort != 0 {
			add("tailscale", app("tailscale", "incoming", "udp", "*", s.VPNPort, 0))
		}
		if o.TailscaleHTTP {
			add("tailscale", app("tailscale", "outgoing", "tcp", "*", 0, 80))
		}
	}
	if o.Discovery {
		issues = append(issues, "Local discovery unavailable: no explicitly approved trusted-interface configuration; no multicast/LLMNR permission inferred")
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, nil, err
		}
	}
	return rules, issues, nil
}

func unique[T comparable](in []T) []T {
	out := make([]T, 0, len(in))
	seen := map[T]bool{}
	for _, v := range in {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}
