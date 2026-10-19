package hostfirewall

import (
	"flowgate/internal/policy"
	"fmt"
	"strings"
)

// The same approved interface/port rules are used by boot guard and active hooks.
// No PID attribution is invented for raw/pre-address DHCP traffic.
func scopedBootstrap(r, table string, ifs []policy.BootstrapInterface) string {
	lines := strings.Split(r, "\n")
	kept := []string{}
	for _, line := range lines {
		if strings.Contains(line, "udp sport 67 udp dport 68 accept") || strings.Contains(line, "udp sport 68 udp dport 67 accept") || strings.Contains(line, "udp sport 547 udp dport 546 accept") || strings.Contains(line, "udp sport 546 udp dport 547 accept") {
			continue
		}
		kept = append(kept, line)
	}
	input, output := "", ""
	for _, v := range ifs {
		check := policy.Rule{Schema: 5, ID: "bootstrap", Action: "allow", Preset: &policy.Preset{Name: "essential-system-networking", Component: "dhcp", EntryID: "bootstrap", Revision: "validated"}, Filter: policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "udp", RemoteAddress: "*", LocalPort: 68, RemotePort: 67, InterfaceName: v.Name}}
		if check.Validate() != nil {
			continue
		}
		if v.IPv4 {
			input += fmt.Sprintf("add rule inet %s input iifname %q meta nfproto ipv4 udp sport 67 udp dport 68 accept\n", table, v.Name)
			output += fmt.Sprintf("add rule inet %s output oifname %q meta nfproto ipv4 udp sport 68 udp dport 67 accept\n", table, v.Name)
		}
		if v.IPv6 {
			input += fmt.Sprintf("add rule inet %s input iifname %q ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n", table, v.Name)
			output += fmt.Sprintf("add rule inet %s output oifname %q ip6 daddr { fe80::/10, ff02::1:2 } udp sport 546 udp dport 547 accept\n", table, v.Name)
		}
	}
	r = strings.Join(kept, "\n")
	in := "add rule inet " + table + " input "
	out := "add rule inet " + table + " output "
	r = strings.Replace(r, in, input+in, 1)
	r = strings.Replace(r, out, output+out, 1)
	return r
}
