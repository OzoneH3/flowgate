package identity

import "net"

// IsLoopbackFlow requires kernel interface evidence as well as both addresses.
// A local-network address, a display label, or a claimed remote address alone
// must never exempt external traffic from application policy.
func IsLoopbackFlow(f Flow) bool {
	if f.NetNS != NetNS() || f.Interface == 0 || !f.Local.Addr().Unmap().IsLoopback() || !f.Remote.Addr().Unmap().IsLoopback() || (f.Protocol != "tcp" && f.Protocol != "udp") || (f.Direction != "incoming" && f.Direction != "outgoing") {
		return false
	}
	i, err := net.InterfaceByIndex(int(f.Interface))
	return err == nil && i.Flags&net.FlagLoopback != 0
}
