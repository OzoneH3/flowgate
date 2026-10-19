package policy

import (
	"flowgate/internal/identity"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type Filter struct {
	InterfaceIndex uint32            `json:"interface_index,omitempty"`
	InterfaceName  string            `json:"interface_name,omitempty"`
	LocalAddress   string            `json:"local_address,omitempty"`
	PeerService    PeerService       `json:"peer_service,omitzero"`
	NetworkZone    string            `json:"network_zone,omitempty"`
	AllPrograms    bool              `json:"all_programs,omitempty"`
	AllUIDs        bool              `json:"all_uids,omitempty"`
	Process        identity.Instance `json:"process,omitzero"`
	Application    string            `json:"application"`
	Revision       string            `json:"revision"`
	Direction      string            `json:"direction"`
	Protocol       string            `json:"protocol"`
	// Remote retains v1 exact endpoint semantics; new fields are additive (schema 2).
	RemoteAddress string `json:"remote_address,omitempty"`
	LocalPort     uint16 `json:"local_port,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
	Remote        string `json:"remote,omitempty"`
	UID           uint32 `json:"uid"`
}
type Rule struct {
	Preset     *Preset   `json:"preset,omitempty"`
	Version    uint64    `json:"version,omitempty"`
	Executable string    `json:"executable,omitempty"`
	Created    time.Time `json:"created"`
	Disabled   bool      `json:"disabled"`
	Schema     int       `json:"schema,omitempty"`
	ID         string    `json:"id"`
	Priority   int       `json:"priority"`
	Filter     Filter    `json:"filter"`
	Action     string    `json:"action"`
	Expires    time.Time `json:"expires"`
}

func (r Rule) Validate() error {
	if len(r.Executable) > 4096 {
		return fmt.Errorf("executable display path too long")
	}
	if r.Schema != 0 && r.Schema != 1 && r.Schema != 2 && r.Schema != 3 && r.Schema != 4 && r.Schema != 5 {
		return fmt.Errorf("unsupported rule schema")
	}
	if r.Schema != 2 && r.Schema != 3 && r.Schema != 4 && r.Schema != 5 && (r.Filter.RemoteAddress != "" || r.Filter.LocalPort != 0 || r.Filter.RemotePort != 0) {
		return fmt.Errorf("address/port fields require rule schema 2")
	}
	if r.Filter.Remote != "" {
		if _, err := netip.ParseAddrPort(r.Filter.Remote); err != nil {
			return err
		}
		if r.Filter.RemoteAddress != "" || r.Filter.RemotePort != 0 {
			return fmt.Errorf("legacy remote cannot be mixed with address/port fields")
		}
	}
	if r.Filter.RemoteAddress != "" && r.Filter.RemoteAddress != "*" {
		if _, err := netip.ParsePrefix(r.Filter.RemoteAddress); err != nil {
			if _, err = netip.ParseAddr(r.Filter.RemoteAddress); err != nil {
				return err
			}
		}
	}
	if !r.Filter.Process.IsZero() {
		b := r.Filter.Process
		if (r.Schema != 3 && r.Schema != 4) || b.ID == "" || b.Session == "" || b.BootID == "" || b.PID <= 0 || b.Start == "" || b.NetNS == "" || b.MountNS == "" || b.PIDNS == "" || b.Executable == "" || b.Revision != r.Filter.Revision || b.UID != r.Filter.UID {
			return fmt.Errorf("schema3 complete process identity required")
		}
	} else if r.Schema == 3 {
		return fmt.Errorf("schema3 requires a process binding")
	}
	if r.Filter.NetworkZone != "" && r.Filter.NetworkZone != "local" && r.Filter.NetworkZone != "internet" {
		return fmt.Errorf("invalid network zone")
	}
	if (r.Filter.NetworkZone != "" || r.Filter.AllPrograms || r.Filter.AllUIDs) && r.Schema != 4 && r.Schema != 5 {
		return fmt.Errorf("zone target fields require schema4")
	}
	if r.Filter.AllUIDs && (!r.Filter.AllPrograms || r.Filter.UID != 0) {
		return fmt.Errorf("machine target requires allprograms and canonical UID0")
	}
	if r.Filter.AllPrograms && r.Schema != 5 {
		if r.Schema != 4 || r.Filter.NetworkZone == "" || r.Filter.Application != "" || r.Filter.Revision != "" || !r.Filter.Process.IsZero() || r.Executable != "" {
			return fmt.Errorf("zone-wide rule has no application/process identity")
		}
	}
	if r.Schema == 5 {
		if err := r.validatePreset(); err != nil {
			return err
		}
	} else if r.Preset != nil || r.Filter.PeerService != (PeerService{}) || r.Filter.InterfaceIndex != 0 || r.Filter.InterfaceName != "" || r.Filter.LocalAddress != "" {
		return fmt.Errorf("preset/interface fields require schema5")
	}
	if r.ID == "" || (!r.Filter.AllPrograms && (r.Filter.Application == "" || r.Filter.Revision == "")) {
		return fmt.Errorf("rule needs ID, application and revision")
	}
	if r.Action != "allow" && r.Action != "block" && r.Action != "ask" {
		return fmt.Errorf("invalid action")
	}
	if r.Filter.Direction != "incoming" && r.Filter.Direction != "outgoing" {
		return fmt.Errorf("invalid direction")
	}
	if r.Filter.Protocol != "tcp" && r.Filter.Protocol != "udp" && !(r.Filter.Protocol == "*" && (r.Schema == 2 || r.Schema == 3 || r.Schema == 4 || r.Schema == 5)) {
		return fmt.Errorf("invalid protocol")
	}
	return nil
}
func Evaluate(rules []Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	return EvaluateSession(rules, f, a, now, "")
}
func EvaluateSession(rules []Rule, f identity.Flow, a identity.Attribution, now time.Time, session string) (string, string, []string) {
	if a.Application == nil || a.Application.Key == "" || a.Application.Revision == "" || a.Principal() == nil {
		return "block", "unsafe-attribution", nil
	}
	var matches []Rule
	for _, r := range rules {
		x := r.Filter
		if !x.Process.IsZero() && (session == "" || x.Process.Session != session || !a.VisibilityComplete || len(a.Owners) != 1 || len(a.Sockets) != 1 || !x.Process.Matches(a.Owners[0])) {
			continue
		}
		if r.Disabled {
			continue
		}
		if !r.Expires.IsZero() && !now.Before(r.Expires) {
			continue
		}
		if (!x.AllPrograms && (x.Application != a.Application.Key || x.Revision != a.Application.Revision)) || (!x.AllUIDs && x.UID != a.Principal().UID) || x.Direction != f.Direction || !ProtocolMatches(x.Protocol, f.Protocol) {
			continue
		}
		if x.NetworkZone != "" && (f.NetworkScope.State != "known" || f.NetworkScope.Zone != x.NetworkZone) {
			continue
		}
		if x.Remote != "" && x.Remote != f.Remote.String() {
			continue
		}
		if x.LocalPort != 0 && x.LocalPort != f.Local.Port() {
			continue
		}
		if x.RemotePort != 0 && x.RemotePort != f.Remote.Port() {
			continue
		}
		if x.RemoteAddress != "" && x.RemoteAddress != "*" {
			prefix, err := netip.ParsePrefix(x.RemoteAddress)
			if err == nil {
				if !prefix.Contains(f.Remote.Addr()) {
					continue
				}
			} else {
				addr, err := netip.ParseAddr(x.RemoteAddress)
				if err != nil || addr != f.Remote.Addr() {
					continue
				}
			}
		}
		matches = append(matches, r)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Filter.Process.IsZero() != matches[j].Filter.Process.IsZero() {
			return !matches[i].Filter.Process.IsZero()
		}
		if matches[i].Filter.AllPrograms != matches[j].Filter.AllPrograms {
			return !matches[i].Filter.AllPrograms
		}
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		// At equal tier/priority, an explicit user policy overrides a preset.
		if (matches[i].Preset == nil) != (matches[j].Preset == nil) {
			return matches[i].Preset == nil
		}
		return matches[i].ID < matches[j].ID
	})
	var ids []string
	for _, r := range matches {
		ids = append(ids, r.ID)
	}
	if len(matches) == 0 {
		return "ask", "default-ask", ids
	}
	return matches[0].Action, matches[0].ID, ids
}

// Remembered defaults to one remote address, not an ephemeral source port.
func Remembered(f identity.Flow, a identity.Attribution) Filter {
	x := Filter{Application: a.Application.Key, Revision: a.Application.Revision, UID: a.Principal().UID, Direction: f.Direction, Protocol: f.Protocol, RemoteAddress: f.Remote.Addr().String()}
	if f.Direction == "incoming" {
		x.LocalPort = f.Local.Port()
	} else {
		x.RemotePort = f.Remote.Port()
	}
	return x
}

// ProtocolMatches deliberately limits wildcard scope to the supported TCP/UDP
// initiation engine. It never means all IP protocols (ICMP, raw traffic, etc.).
func ProtocolMatches(rule, actual string) bool {
	return (actual == "tcp" || actual == "udp") && (rule == actual || rule == "*")
}
func ProtocolsOverlap(a, b string) bool {
	return ProtocolMatches(a, "tcp") && ProtocolMatches(b, "tcp") || ProtocolMatches(a, "udp") && ProtocolMatches(b, "udp")
}
