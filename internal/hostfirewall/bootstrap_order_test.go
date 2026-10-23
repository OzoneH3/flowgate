package hostfirewall

import (
	"flowgate/internal/identity"
	"flowgate/internal/policy"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func bootstrapOrderCases() map[string]string {
	scope := []policy.BootstrapInterface{{Name: "approved0", IPv4: true, IPv6: true}}
	return map[string]string{
		"incoming-empty":  profileRules("order", "incoming"),
		"both-empty":      profileRules("order", "both"),
		"guard-empty":     guardRules("order"),
		"incoming-scoped": profileRules("order", "incoming", scope...),
		"both-scoped":     profileRules("order", "both", scope...),
		"guard-scoped":    guardRules("order", scope...),
	}
}

func TestEssentialBootstrapChainsDeclaredBeforeUse(t *testing.T) {
	for name, tx := range bootstrapOrderCases() {
		t.Run(name, func(t *testing.T) {
			declared := map[string]bool{}
			for _, line := range strings.Split(tx, "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 5 && fields[0] == "add" && fields[1] == "chain" {
					declared[fields[4]] = true
				}
				for i := range fields {
					if fields[i] == "jump" && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "dhcp_") && !declared[fields[i+1]] {
						t.Fatalf("forward reference before DHCP chain exists: %s", line)
					}
				}
			}
			if !declared["dhcp_input"] || !declared["dhcp_output"] {
				t.Fatal("missing scoped chains")
			}
		})
	}
}

// nft's check transaction validates real kernel rule/chain references without
// installing a table. It is still gated to the disposable guest/lab namespace.
func TestEssentialBootstrapChainOrderKernel(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == identity.NetNS() {
		t.Skip("private lab namespace required")
	}
	for name, tx := range bootstrapOrderCases() {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("nft", "--check", "--file", "-")
			cmd.Stdin = strings.NewReader(tx)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("kernel rejected chain order: %v\n%s", err, out)
			}
		})
	}
}
