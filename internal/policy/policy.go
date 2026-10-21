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
	ZoneModel      string            `json:"zone_model,omitempty"`
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
	ShareWithRoot   bool   `json:"share_with_root,omitempty"`
	RootApplication string `json:"root_application,omitempty"`
	// Invocation is historical display context, never a permission matcher.
	Invocation *identity.Invocation `json:"invocation,omitempty"`
	Preset     *Preset              `json:"preset,omitempty"`
	Version    uint64               `json:"version,omitempty"`
	Executable string               `json:"executable,omitempty"`
	Created    time.Time            `json:"created"`
	Disabled   bool                 `json:"disabled"`
	Schema     int                  `json:"schema,omitempty"`
	ID         string               `json:"id"`
	Priority   int                  `json:"priority"`
	Filter     Filter               `json:"filter"`
	Action     string               `json:"action"`
	Expires    time.Time            `json:"expires"`
}

func (r Rule) CanShareRoot() bool {
	return r.validRootPair() && r.ShareWithRoot
}

// Accept old structurally valid pairs on load so startup can persist revocation.
// Matching and new scope construction always require CanShareRoot.
func (r Rule) validRootPair() bool {
	return r.Preset == nil && r.Filter.UID != 0 && !r.Filter.AllPrograms && !r.Filter.AllUIDs && r.Filter.Process.IsZero() && r.Executable != "" && r.Filter.Application == identity.ApplicationKey(r.Filter.UID, identity.Application{Kind: "native", Executable: r.Executable})
}

func (r Rule) MatchesApplication(key, revision string, uid uint32) bool {
	if r.Filter.Revision != revision {
		return false
	}
	return (r.Filter.Application == key && r.Filter.UID == uid) || (uid == 0 && r.RootApplication != "" && r.RootApplication == key && r.CanShareRoot())
}

func (r Rule) Validate() error {
	if r.RootApplication != "" && (!r.validRootPair() || r.RootApplication != identity.ApplicationKey(0, identity.Application{Kind: "native", Executable: r.Executable})) {
		return fmt.Errorf("invalid paired root application scope")
	}

	if i := r.Invocation; i != nil && (i.Mode != "file" || len(i.Name) > 256 || len(i.Path) > 4096 || len(i.Revision) > 256 || i.Application != nil) {
		return fmt.Errorf("invalid invocation display context")
	}
	if len(r.Executable) > 4096 {
		return fmt.Errorf("executable display path too long")
	}
	if r.Schema != 0 && r.Schema != 1 && r.Schema != 2 && r.Schema != 3 && r.Schema != 4 && r.Schema != 5 && r.Schema != 6 {
		return fmt.Errorf("unsupported rule schema")
	}
	if r.Schema != 2 && r.Schema != 3 && r.Schema != 4 && r.Schema != 5 && r.Schema != 6 && (r.Filter.RemoteAddress != "" || r.Filter.LocalPort != 0 || r.Filter.RemotePort != 0) {
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
		if (r.Schema != 3 && r.Schema != 4 && r.Schema != 6) || b.ID == "" || b.Session == "" || b.BootID == "" || b.PID <= 0 || b.Start == "" || b.NetNS == "" || b.MountNS == "" || b.PIDNS == "" || b.Executable == "" || b.Revision != r.Filter.Revision || b.UID != r.Filter.UID {
			return fmt.Errorf("schema3 complete process identity required")
		}
	} else if r.Schema == 3 {
		return fmt.Errorf("schema3 requires a process binding")
	}
	if (r.Schema == 6 && (r.Filter.ZoneModel != identity.AutomaticZoneModel || r.Filter.NetworkZone == "")) || (r.Schema != 6 && r.Filter.ZoneModel != "") {
		return fmt.Errorf("automatic zones require explicit schema6 binding")
	}
	if r.Filter.NetworkZone != "" && r.Filter.NetworkZone != "local" && r.Filter.NetworkZone != "internet" {
		return fmt.Errorf("invalid network zone")
	}
	if (r.Filter.NetworkZone != "" || r.Filter.AllPrograms || r.Filter.AllUIDs) && r.Schema != 4 && r.Schema != 5 && r.Schema != 6 {
		return fmt.Errorf("zone target fields require schema4")
	}
	if r.Filter.AllUIDs && (!r.Filter.AllPrograms || r.Filter.UID != 0) {
		return fmt.Errorf("machine target requires allprograms and canonical UID0")
	}
	if r.Filter.AllPrograms && r.Schema != 5 {
		if (r.Schema != 4 && r.Schema != 6) || r.Filter.NetworkZone == "" || r.Filter.Application != "" || r.Filter.Revision != "" || !r.Filter.Process.IsZero() || r.Executable != "" {
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
	if r.Filter.Protocol != "tcp" && r.Filter.Protocol != "udp" && !(r.Filter.Protocol == "*" && (r.Schema == 2 || r.Schema == 3 || r.Schema == 4 || r.Schema == 5 || r.Schema == 6)) {
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
		if (!x.AllPrograms && !r.MatchesApplication(a.Application.Key, a.Application.Revision, a.Principal().UID)) || (x.AllPrograms && !x.AllUIDs && x.UID != a.Principal().UID) || x.Direction != f.Direction || !ProtocolMatches(x.Protocol, f.Protocol) {
			continue
		}
		if x.NetworkZone != "" {
			scope := f.NetworkScope
			if x.ZoneModel == identity.AutomaticZoneModel {
				if scope.Source != identity.AutomaticZoneModel {
					continue
				}
			} else if scope.Source == identity.AutomaticZoneModel {
				scope.State, scope.Zone = scope.LegacyState, scope.LegacyZone
			}
			if scope.State != "known" || scope.Zone != x.NetworkZone {
				continue
			}
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
	// Root sharing is a fallback. Remove inherited candidates only when an
	// explicit root-principal rule actually matches; preserve normal weighting
	// for machine-wide AllUIDs policy and for all other principals.
	if a.Principal().UID == 0 {
		explicit := false
		for _, r := range matches {
			if r.Filter.UID == 0 && !r.Filter.AllUIDs {
				explicit = true
				break
			}
		}
		if explicit {
			kept := matches[:0]
			for _, r := range matches {
				if r.Filter.UID != 0 && r.RootApplication != "" {
					continue
				}
				kept = append(kept, r)
			}
			matches = kept
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		// NetLimiter Blocker: the rule with the higher weight is applied; on
		// equal weight Deny is applied before Allow and Ask.
		if wi, wj := matches[i].Weight(), matches[j].Weight(); wi != wj {
			return wi > wj
		}
		// Explicit legacy priorities keep their stored ordering within a weight.
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		// Observed NetLimiter 5.3.28: equal weight applies Deny, then Allow, then Ask.
		if ri, rj := actionRank(matches[i].Action), actionRank(matches[j].Action); ri != rj {
			return ri < rj
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

func actionRank(a string) int {
	switch a {
	case "block":
		return 0
	case "allow":
		return 1
	}
	return 2
}

// Weight is NetLimiter's Blocker precedence by target: whole machine 1, zone 2,
// application/filter 3. FlowGate process-instance rules (no NetLimiter
// equivalent) are 4 so an instance override keeps beating its application.
func (r Rule) Weight() int {
	switch {
	case !r.Filter.Process.IsZero():
		return 4
	case r.Filter.AllPrograms && r.Filter.NetworkZone != "":
		return 2
	case r.Filter.AllPrograms:
		return 1
	}
	return 3
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
