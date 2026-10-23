package readiness

import (
	"context"
	"fmt"
	"testing"
)

func TestTunnelNamesNeverBypassCompatibilityChecks(t *testing.T) {
	for _, name := range []string{"tailscale0", "vpn0", "renamed0"} {
		for _, kind := range []string{"tun", "wireguard", "xfrm"} {
			env := fakeEnv()
			base := env.Run
			env.Run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "ip" && len(args) > 2 && args[2] == "rule" {
					return []byte(`[]`), nil
				}
				if cmd == "ip" {
					return []byte(fmt.Sprintf(`[{"ifname":%q,"linkinfo":{"info_kind":%q}}]`, name, kind)), nil
				}
				if cmd != "nft" {
					t.Fatalf("unexpected product-specific inspection: %s", cmd)
				}
				return base(ctx, cmd, args...)
			}
			found := false
			for _, c := range Firewall(context.Background(), env) {
				if c.ID == "firewall.interfaces" {
					found = (kind == "tun" && c.Status == Ready) || (kind != "tun" && c.Status == Blocked && c.Code == "firewall_conflict")
				}
			}
			if !found {
				t.Fatalf("%s/%s bypassed tunnel checks", name, kind)
			}
		}
	}
}
