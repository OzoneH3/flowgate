package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flowgate/internal/identity"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Preset struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	EntryID   string `json:"entry_id"`
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
}
type PeerService struct {
	Application string `json:"application"`
	Revision    string `json:"revision"`
	UID         uint32 `json:"uid"`
}

func PresetDigest(r Rule) string {
	r.Version = 0
	r.Created = r.Created.UTC()
	if r.Preset != nil {
		p := *r.Preset
		p.Digest = ""
		r.Preset = &p
	}
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func UneditedPreset(r Rule) bool {
	return r.Preset != nil && r.Preset.Name == "essential-system-networking" && r.Preset.Digest != "" && r.Preset.Digest == PresetDigest(r)
}
func (r Rule) validatePreset() error {
	if r.Preset == nil || r.Preset.Name != "essential-system-networking" || r.Preset.Component == "" || r.Preset.EntryID == "" || r.Preset.Revision == "" {
		return fmt.Errorf("schema5 requires explicit preset provenance")
	}
	f := r.Filter
	if f.InterfaceName != "" {
		if len(f.InterfaceName) > 15 || strings.ContainsAny(f.InterfaceName, "\n\r\t /\\\";") {
			return fmt.Errorf("invalid interface name")
		}
	}
	if f.LocalAddress != "" {
		if _, err := netip.ParseAddr(f.LocalAddress); err != nil {
			return err
		}
	}
	if f.AllPrograms {
		if !f.AllUIDs || f.Application != "" || f.Revision != "" || !f.Process.IsZero() || f.NetworkZone != "" || f.UID != 0 {
			return fmt.Errorf("invalid preset aggregate identity")
		}
		if r.Preset.Component == "dns-stub-client" {
			ip, err := netip.ParseAddr(f.RemoteAddress)
			if err != nil || !ip.IsLoopback() || f.RemotePort != 53 || f.Direction != "outgoing" || f.InterfaceName != "lo" || f.PeerService == (PeerService{}) || f.PeerService.Application == "" || f.PeerService.Revision == "" {
				return fmt.Errorf("stub access requires exact loopback DNS peer/service binding")
			}
		} else if r.Preset.Component == "dhcp" {
			if f.InterfaceName == "" || f.InterfaceName == "lo" || f.Protocol != "udp" || f.PeerService != (PeerService{}) {
				return fmt.Errorf("DHCP bootstrap needs explicit interface and UDP")
			}
			if !((f.LocalPort == 68 && f.RemotePort == 67) || (f.LocalPort == 546 && f.RemotePort == 547)) {
				return fmt.Errorf("invalid DHCP client ports")
			}
			if f.Direction != "outgoing" {
				return fmt.Errorf("DHCP rule describes client output; narrow protocol reply pair generated separately")
			}
		} else {
			return fmt.Errorf("unsupported preset aggregate")
		}
	} else if f.PeerService != (PeerService{}) {
		return fmt.Errorf("peer binding only valid for aggregate stub access")
	}
	return nil
}

type BootstrapInterface struct {
	Name string `json:"name"`
	IPv4 bool   `json:"ipv4"`
	IPv6 bool   `json:"ipv6"`
}

func BootstrapFrom(rules []Rule, now time.Time) []BootstrapInterface {
	out := []BootstrapInterface{}
	for _, r := range rules {
		if r.Preset == nil || r.Preset.Component != "dhcp" || !UneditedPreset(r) || r.Disabled || r.Action != "allow" || !r.Expires.IsZero() && !now.Before(r.Expires) || r.Validate() != nil {
			continue
		}
		i := -1
		for k := range out {
			if out[k].Name == r.Filter.InterfaceName {
				i = k
			}
		}
		if i < 0 {
			out = append(out, BootstrapInterface{Name: r.Filter.InterfaceName})
			i = len(out) - 1
		}
		if r.Filter.LocalPort == 68 {
			out[i].IPv4 = true
		} else {
			out[i].IPv6 = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MigrateRevisions rewrites file-stamp revisions stored in the earlier
// device-dependent form (identity.MigrateStamp). An unedited essential preset
// keeps its unedited state: its digest is re-sealed over the migrated rule.
func MigrateRevisions(r *Rule) bool {
	unedited := UneditedPreset(*r)
	before := [4]string{r.Filter.Revision, r.Filter.Process.Revision, r.Filter.Process.ExecutableRevision, r.Filter.PeerService.Revision}
	r.Filter.Revision = identity.MigrateStamp(r.Filter.Revision)
	r.Filter.Process.Revision = identity.MigrateStamp(r.Filter.Process.Revision)
	r.Filter.Process.ExecutableRevision = identity.MigrateStamp(r.Filter.Process.ExecutableRevision)
	r.Filter.PeerService.Revision = identity.MigrateStamp(r.Filter.PeerService.Revision)
	changed := before != [4]string{r.Filter.Revision, r.Filter.Process.Revision, r.Filter.Process.ExecutableRevision, r.Filter.PeerService.Revision}
	if changed && unedited {
		r.Preset.Digest = PresetDigest(*r)
	}
	return changed
}
