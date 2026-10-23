package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Compatibility depends on bounded live mark semantics, never vendor names.
// Opaque xt marks require a matching independently exported representation.
func compatibleFirewallRules(ctx context.Context, env Environment, nft []byte) Check {
	c := Check{ID: "firewall.mark_compatibility", Status: Blocked, Code: "firewall_conflict", Next: "Inspect conflicting mark/routing rules; no automatic firewall changes"}
	fail := func(err error) Check { c.Detail = err.Error(); return c }
	if err := compatibleNFT(nft); err != nil {
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
			for _, table := range []string{"filter", "mangle", "nat", "raw", "security"} {
				needed := false
				for key := range kernel {
					if strings.HasPrefix(key, family+"/"+table+"/") {
						needed = true
					}
				}
				if !needed {
					continue
				}
				b, err := env.Run(ctx, tool, "-t", table)
				if err != nil {
					return ProbeFailure(c.ID, err)
				}
				if err = compatibleExport(b); err != nil {
					return fail(fmt.Errorf("%s/%s: %w", tool, table, err))
				}
				again, err := env.Run(ctx, tool, "-t", table)
				if err != nil {
					return ProbeFailure(c.ID, err)
				}
				if !reflect.DeepEqual(exportRuleLines(b), exportRuleLines(again)) {
					return fail(fmt.Errorf("mark export changed during inspection"))
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
		latest, err := env.Run(ctx, "nft", "-j", "list", "ruleset")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		if err = compatibleNFT(latest); err != nil {
			return fail(err)
		}
		latestCounts, err := opaqueMarkCounts(latest)
		if err != nil || !reflect.DeepEqual(kernel, latestCounts) {
			return fail(fmt.Errorf("kernel mark snapshot changed during inspection"))
		}
	}
	for _, family := range []string{"-4", "-6"} {
		b, err := env.Run(ctx, "ip", "-j", family, "rule", "show")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		if err = compatibleRouting(b); err != nil {
			return fail(err)
		}
	}
	c.Status = Ready
	c.Code = "mark_masks_disjoint"
	c.Next = ""
	c.Detail = "Packet/conntrack mark masks and routing selectors are disjoint from reserved bits. Tunnel and transport traffic remain subject to ordinary application permissions."
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

func exportRuleLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "-A ") {
			out = append(out, line)
		}
	}
	return out
}
