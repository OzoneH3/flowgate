package hostfirewall

import (
	"context"
	"encoding/json"
	"flowgate/internal/policy"
	"fmt"
	"log"
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
	input, output := bootstrapRules(table, ifs)
	r = strings.Join(kept, "\n")
	in := "add rule inet " + table + " input "
	out := "add rule inet " + table + " output "
	chains := fmt.Sprintf("add chain inet %s dhcp_input\nadd chain inet %s dhcp_output\n", table, table)
	// Incoming-only output marking precedes the first input rule. Declare both
	// DHCP chains before the first rule in any chain, so neither jump is a
	// forward reference in the kernel transaction.
	firstRule := "add rule inet " + table + " "
	r = strings.Replace(r, firstRule, chains+input+output+firstRule, 1)
	r = strings.Replace(r, in, "add rule inet "+table+" input jump dhcp_input\n"+in, 1)
	return strings.Replace(r, out, "add rule inet "+table+" output jump dhcp_output\n"+out, 1)
}

func bootstrapRules(table string, ifs []policy.BootstrapInterface) (string, string) {
	input, output := "", ""
	for _, v := range ifs {
		check := policy.Rule{Schema: 5, ID: "bootstrap", Action: "allow", Preset: &policy.Preset{Name: "essential-system-networking", Component: "dhcp", EntryID: "bootstrap", Revision: "validated"}, Filter: policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "udp", RemoteAddress: "*", LocalPort: 68, RemotePort: 67, InterfaceName: v.Name}}
		if check.Validate() != nil {
			continue
		}
		if v.IPv4 {
			input += fmt.Sprintf("add rule inet %s dhcp_input iifname %q meta nfproto ipv4 udp sport 67 udp dport 68 accept\n", table, v.Name)
			output += fmt.Sprintf("add rule inet %s dhcp_output oifname %q meta nfproto ipv4 udp sport 68 udp dport 67 accept\n", table, v.Name)
		}
		if v.IPv6 {
			input += fmt.Sprintf("add rule inet %s dhcp_input iifname %q ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n", table, v.Name)
			output += fmt.Sprintf("add rule inet %s dhcp_output oifname %q ip6 daddr { fe80::/10, ff02::1:2 } udp sport 546 udp dport 547 accept\n", table, v.Name)
		}
	}
	return input, output
}

// Refresh only DHCP chains, in one nft transaction, after verifying ownership.
// The cleanup lock also protects the persisted digest from the watchdog.
func refreshBootstrap(ctx context.Context, dir string, record *Record, next []policy.BootstrapInterface) error {
	return evaluationLock(dir, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		present, err := owns(*record)
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("owned interception table disappeared during DHCP refresh")
		}
		before, err := nft("-j", "list", "table", "inet", Table)
		if err != nil {
			return err
		}
		digest, err := digestTableJSON(before)
		if err != nil {
			return err
		}
		if digest != record.TableDigest {
			return fmt.Errorf("owned interception table changed during DHCP refresh")
		}
		input, output := bootstrapRules(Table, next)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := batch(fmt.Sprintf("flush chain inet %s dhcp_input\nflush chain inet %s dhcp_output\n", Table, Table) + input + output); err != nil {
			// nft transactions are atomic. Retry an unchanged table next tick;
			// never excuse a partially changed or foreign table.
			if unchanged, probeErr := tableDigest(); probeErr == nil && unchanged == record.TableDigest {
				log.Printf("WARNING: DHCP refresh transaction failed; retaining active scopes: %v", err)
				return nil
			}
			return err
		}
		after, err := nft("-j", "list", "table", "inet", Table)
		if err != nil {
			return err
		}
		if err := verifyDHCPRuleCounts(after, strings.Count(input, "\n"), strings.Count(output, "\n")); err != nil {
			return err
		}
		oldRest, err := nonDHCPDigest(before)
		if err != nil {
			return err
		}
		newRest, err := nonDHCPDigest(after)
		if err != nil {
			return err
		}
		if oldRest != newRest {
			return fmt.Errorf("non-DHCP interception changed during DHCP refresh")
		}
		digest, err = digestTableJSON(after)
		if err != nil {
			return err
		}
		updated := *record
		updated.Bootstrap = next
		updated.TableDigest = digest
		if err := save(dir, updated); err != nil {
			return err
		}
		*record = updated
		return nil
	})
}

// Only rule entries in the two DHCP chains may change; chain definitions,
// jumps, policy and every other object remain part of this comparison.
func nonDHCPDigest(raw []byte) (string, error) {
	var table map[string][]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &table); err != nil {
		return "", err
	}
	entries := table["nftables"][:0]
	for _, item := range table["nftables"] {
		var rule struct{ Chain string }
		if body, ok := item["rule"]; ok {
			if err := json.Unmarshal(body, &rule); err != nil {
				return "", err
			}
			if rule.Chain == "dhcp_input" || rule.Chain == "dhcp_output" {
				continue
			}
		}
		entries = append(entries, item)
	}
	table["nftables"] = entries
	raw, err := json.Marshal(table)
	if err != nil {
		return "", err
	}
	return digestTableJSON(raw)
}

func verifyDHCPRuleCounts(raw []byte, input, output int) error {
	var table struct {
		NFTables []struct{ Rule *struct{ Chain string } }
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		return err
	}
	for _, entry := range table.NFTables {
		if entry.Rule == nil {
			continue
		}
		switch entry.Rule.Chain {
		case "dhcp_input":
			input--
		case "dhcp_output":
			output--
		}
	}
	if input != 0 || output != 0 {
		return fmt.Errorf("DHCP chain rules changed during refresh")
	}
	return nil
}
