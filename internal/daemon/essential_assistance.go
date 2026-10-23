package daemon

import (
	"flowgate/internal/policy"
	"reflect"
)

// Only durable ordinary Allows can replace optional setup assistance. Comparing
// the complete filter after expanding explicit wildcards keeps identity, UID,
// direction, process, zone and peer-service restrictions independent. A narrower
// or temporary rule is never enough. DHCP bootstrap is not an application rule.
func serviceAssistanceCovered(existing, candidate policy.Rule) bool {
	if existing.Preset != nil || existing.Disabled || existing.Action != "allow" || !existing.Expires.IsZero() || existing.Validate() != nil {
		return false
	}
	a, b := existing.Filter, candidate.Filter
	if a.Protocol == "*" {
		a.Protocol = b.Protocol
	}
	if a.RemoteAddress == "" || a.RemoteAddress == "*" {
		a.RemoteAddress = b.RemoteAddress
	}
	if a.Remote == "" {
		a.Remote = b.Remote
	}
	if a.LocalPort == 0 {
		a.LocalPort = b.LocalPort
	}
	if a.RemotePort == 0 {
		a.RemotePort = b.RemotePort
	}
	if a.InterfaceName == "" && a.InterfaceIndex == 0 {
		a.InterfaceName, a.InterfaceIndex = b.InterfaceName, b.InterfaceIndex
	}
	if a.LocalAddress == "" {
		a.LocalAddress = b.LocalAddress
	}
	return reflect.DeepEqual(a, b)
}
