package essential

import (
	"context"
	"flowgate/internal/policy"
	"fmt"
	"net"
	"sort"
	"strings"
)

// DHCP discovery is independent of optional DNS/time service discovery. A failed
// or malformed response never broadens the bootstrap exception.
func discoverDHCP(ctx context.Context, env Environment, lookup func(string) (*net.Interface, error)) ([]DHCP, error) {
	b, err := env.Run(ctx, "nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active")
	if err != nil {
		return nil, fmt.Errorf("nmcli active connections failed: %w", err)
	}
	var out []DHCP
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		uuid, name, ok := strings.Cut(line, ":")
		if !ok || uuid == "" {
			return nil, fmt.Errorf("malformed NetworkManager connection")
		}
		if name == "" || name == "lo" {
			continue
		}
		iface, err := lookup(name)
		if err != nil {
			continue
		} // Interface disappeared between snapshots.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		methods, err := env.Run(ctx, "nmcli", "-g", "ipv4.method,ipv6.method", "connection", "show", uuid)
		if err != nil {
			return nil, fmt.Errorf("nmcli connection methods failed: %w", err)
		}
		m := strings.Fields(string(methods))
		if len(m) != 2 {
			return nil, fmt.Errorf("malformed NetworkManager address methods")
		}
		d := DHCP{name, uint32(iface.Index), m[0] == "auto", m[1] == "auto" || m[1] == "dhcp"}
		if d.IPv4 || d.IPv6 {
			out = append(out, d)
		}
	}
	return out, nil
}

// AutomaticBootstrap adds only interface-scoped DHCP to existing saved scopes.
// It neither writes permissions nor enables protection. Callers bound discovery
// with a deadline and retain saved scopes if discovery is unavailable.
func AutomaticBootstrap(ctx context.Context, env Environment, saved []policy.BootstrapInterface) ([]policy.BootstrapInterface, error) {
	dhcp, err := discoverDHCP(ctx, env, net.InterfaceByName)
	if err != nil {
		return saved, err
	}
	return mergeBootstrap(saved, dhcp), nil
}

// GuardBootstrap runs before NetworkManager is available. Only the existing
// DHCP client/server port pairs are permitted on current non-loopback devices;
// active protection replaces this with profile-derived scopes.
func GuardBootstrap(saved []policy.BootstrapInterface) ([]policy.BootstrapInterface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return saved, err
	}
	return guardInterfaces(saved, ifs), nil
}

func guardInterfaces(saved []policy.BootstrapInterface, ifs []net.Interface) []policy.BootstrapInterface {
	var dhcp []DHCP
	for _, iface := range ifs {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		dhcp = append(dhcp, DHCP{iface.Name, uint32(iface.Index), true, true})
	}
	return mergeBootstrap(saved, dhcp)
}

func mergeBootstrap(saved []policy.BootstrapInterface, dhcp []DHCP) []policy.BootstrapInterface {
	byName := map[string]policy.BootstrapInterface{}
	for _, v := range saved {
		byName[v.Name] = v
	}
	for _, d := range dhcp {
		v := byName[d.Name]
		v.Name = d.Name
		v.IPv4 = v.IPv4 || d.IPv4
		v.IPv6 = v.IPv6 || d.IPv6
		byName[d.Name] = v
	}
	out := make([]policy.BootstrapInterface, 0, len(byName))
	for _, v := range byName {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
