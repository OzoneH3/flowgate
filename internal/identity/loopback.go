package identity

import (
	"net"
	"net/netip"
)

// IsLoopbackFlow requires kernel loopback-device evidence in our namespace.
// Own assigned addresses qualify too; LAN peers on physical devices do not.
func IsLoopbackFlow(f Flow) bool {
	if f.NetNS != NetNS() || f.Interface == 0 || (f.Protocol != "tcp" && f.Protocol != "udp") || (f.Direction != "incoming" && f.Direction != "outgoing") {
		return false
	}
	i, err := net.InterfaceByIndex(int(f.Interface))
	if err != nil || i.Flags&net.FlagLoopback == 0 {
		return false
	}
	local, remote := f.Local.Addr().Unmap(), f.Remote.Addr().Unmap()
	if local.IsLoopback() && remote.IsLoopback() {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	return sameHostAddresses(local, remote, addresses)
}

func sameHostAddresses(local, remote netip.Addr, addresses []net.Addr) bool {
	assigned := func(a netip.Addr) bool {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return false
		}
		if a.IsLoopback() {
			return true
		}
		for _, address := range addresses {
			p, err := netip.ParsePrefix(address.String())
			if err == nil && p.Addr().Unmap() == a {
				return true
			}
		}
		return false
	}
	return assigned(local) && assigned(remote)
}
