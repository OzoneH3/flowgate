package identity

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"runtime"
)

// IsLoopbackFlow requires kernel loopback-device evidence in our namespace.
// Own assigned addresses qualify too; LAN peers on physical devices do not.
func IsLoopbackFlow(f Flow) bool {
	return isLoopbackFlow(f, linkIsLoopback)
}

// IsLoopbackFlowOnInterfaces shares a freshly collected link snapshot with the
// caller's interface-scoped rule evaluation. No snapshot survives a decision.
func IsLoopbackFlowOnInterfaces(f Flow, interfaces []net.Interface) bool {
	loopback, _ := LoopbackDeviceOnInterfaces(f, interfaces)
	return IsLoopbackFlowOnDevice(f, loopback)
}

// ObserveLoopbackDevice returns fresh device evidence, not an address-scope or
// permission decision. Unknown observations must not suppress a peer lookup.
func ObserveLoopbackDevice(f Flow) (loopback, known bool) {
	if f.Interface == 0 || f.NetNS != NetNS() {
		return false, false
	}
	flags, err := freshLinkFlags(f.Interface, f.NetNS)
	return flags&unix.IFF_LOOPBACK != 0, err == nil
}

func LoopbackDeviceOnInterfaces(f Flow, interfaces []net.Interface) (loopback, known bool) {
	if f.Interface == 0 || f.NetNS != NetNS() {
		return false, false
	}
	for _, iface := range interfaces {
		if iface.Index > 0 && uint32(iface.Index) == f.Interface {
			return iface.Flags&net.FlagLoopback != 0, true
		}
	}
	return false, false
}

// InterfacesForFlow pins the namespace across the fresh dump. The returned
// snapshot is owned by this one evaluation, never a cached network authority.
func InterfacesForFlow(f Flow) ([]net.Interface, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if f.NetNS == "" || f.NetNS != link("/proc/thread-self/ns/net") {
		return nil, fmt.Errorf("link namespace changed")
	}
	return net.Interfaces()
}

func IsLoopbackFlowOnDevice(f Flow, loopback bool) bool {
	return isLoopbackFlow(f, func(uint32) bool { return loopback })
}

func isLoopbackFlow(f Flow, loopback func(uint32) bool) bool {
	if f.NetNS != NetNS() || f.Interface == 0 || (f.Protocol != "tcp" && f.Protocol != "udp") || (f.Direction != "incoming" && f.Direction != "outgoing") {
		return false
	}
	if !loopback(f.Interface) {
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
