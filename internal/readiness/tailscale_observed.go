package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Startup examines the rules that exist, not whether a VPN client has finished
// logging in. Missing Tailscale hooks/routes/marks confer no permission and must
// not deadlock startup behind the boot guard. Present opaque mark operations
// still need the independently exported, bounded masks already reviewed here.
func observedTailscaleRules(ctx context.Context, env Environment, nft []byte) Check {
	c := Check{ID: "firewall.tailscale", Status: Blocked, Code: "firewall_conflict", Next: "Inspect conflicting mark/routing rules; no automatic firewall changes"}
	fail := func(err error) Check { c.Detail = err.Error(); return c }
	if err := tailscaleNFTMode(nft, false); err != nil {
		return fail(err)
	}
	kernel, err := opaqueMarkCounts(nft)
	if err != nil {
		return fail(err)
	}
	exported := map[string]int{}
	if len(kernel) > 0 {
		backend, err := env.Run(ctx, "iptables", "--version")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		if !strings.Contains(string(backend), "nf_tables") {
			return fail(fmt.Errorf("Opaque mark inspection requires iptables-nft export"))
		}
		for _, family := range []string{"ip", "ip6"} {
			tool := "iptables-save"
			if family == "ip6" {
				tool = "ip6tables-save"
			}
			for _, table := range []string{"filter", "mangle"} {
				b, err := env.Run(ctx, tool, "-t", table)
				if err != nil {
					return ProbeFailure(c.ID, err)
				}
				if err = tailscaleExportMode(b, table, false); err != nil {
					return fail(fmt.Errorf("%s/%s: %w", tool, table, err))
				}
				for _, line := range strings.Split(string(b), "\n") {
					f := strings.Fields(line)
					if len(f) < 3 || f[0] != "-A" {
						continue
					}
					for i := 2; i+1 < len(f); i++ {
						if (f[i] == "-j" && (f[i+1] == "MARK" || f[i+1] == "CONNMARK")) || (f[i] == "-m" && f[i+1] == "connmark") {
							exported[family+"/"+table+"/"+f[1]+"/"+f[i+1]]++
						}
					}
				}
			}
		}
		// Refuse snapshots that disagree, including concurrent installation/removal.
		for key, n := range kernel {
			if exported[key] != n {
				return fail(fmt.Errorf("Kernel/export mark snapshot differs at %s; retry inspection", key))
			}
		}
		for key, n := range exported {
			if kernel[key] != n {
				return fail(fmt.Errorf("Export/kernel mark snapshot differs at %s; retry inspection", key))
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		b, err := env.Run(ctx, "ip", "-j", family, "rule", "show")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		if err = tailscaleRoutingMode(b, family, false); err != nil {
			return fail(err)
		}
	}
	c.Status = Ready
	c.Code = "tailscale_rules_inspected"
	c.Next = ""
	c.Detail = "Present packet/conntrack mark operations and routing selectors inspected; no Tailscale login/version/preferences or required-rule startup gate. Traffic remains subject to ordinary application permissions."
	return c
}

func opaqueMarkCounts(b []byte) (map[string]int, error) {
	var n struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, object := range n.Nftables {
		raw, ok := object["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Family, Table, Chain string
			Expr                 []map[string]json.RawMessage
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			return nil, err
		}
		for _, expr := range rule.Expr {
			var xt struct{ Name string }
			if json.Unmarshal(expr["xt"], &xt) != nil {
				continue
			}
			if xt.Name == "MARK" || xt.Name == "CONNMARK" || xt.Name == "connmark" {
				counts[rule.Family+"/"+rule.Table+"/"+rule.Chain+"/"+xt.Name]++
			}
		}
	}
	return counts, nil
}
