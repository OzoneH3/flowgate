package policy

import (
	"flowgate/internal/identity"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type Filter struct {
	Application string `json:"application"`
	Revision    string `json:"revision"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	// Remote retains v1 exact endpoint semantics; new fields are additive (schema 2).
	RemoteAddress string `json:"remote_address,omitempty"`
	LocalPort     uint16 `json:"local_port,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
	Remote        string `json:"remote,omitempty"`
	UID           uint32 `json:"uid"`
}
type Rule struct {
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
	if r.Schema != 0 && r.Schema != 1 && r.Schema != 2 {
		return fmt.Errorf("unsupported rule schema")
	}
	if r.Schema != 2 && (r.Filter.RemoteAddress != "" || r.Filter.LocalPort != 0 || r.Filter.RemotePort != 0) {
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
	if r.ID == "" || r.Filter.Application == "" || r.Filter.Revision == "" {
		return fmt.Errorf("rule needs ID, application and revision")
	}
	if r.Action != "allow" && r.Action != "block" && r.Action != "ask" {
		return fmt.Errorf("invalid action")
	}
	if r.Filter.Direction != "incoming" && r.Filter.Direction != "outgoing" {
		return fmt.Errorf("invalid direction")
	}
	if r.Filter.Protocol != "tcp" && r.Filter.Protocol != "udp" {
		return fmt.Errorf("invalid protocol")
	}
	return nil
}
func Evaluate(rules []Rule, f identity.Flow, a identity.Attribution, now time.Time) (string, string, []string) {
	if a.Application == nil || a.Principal() == nil {
		return "block", "unsafe-attribution", nil
	}
	var matches []Rule
	for _, r := range rules {
		x := r.Filter
		if r.Disabled {
			continue
		}
		if !r.Expires.IsZero() && !now.Before(r.Expires) {
			continue
		}
		if x.Application != a.Application.Key || x.Revision != a.Application.Revision || x.UID != a.Principal().UID || x.Direction != f.Direction || x.Protocol != f.Protocol {
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
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
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
