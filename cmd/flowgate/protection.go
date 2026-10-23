package main

import (
	"encoding/json"
	"flag"
	"flowgate/internal/essential"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/policy"
	"flowgate/internal/store"
	"fmt"
	"os"
	"time"
)

// Local root recovery intentionally does not depend on the GUI or API. Stop the
// service first; the recorded consumer must be absent before touching its table.
func protectionLocalCommand(op string, args []string) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	state := fs.String("state", "/run/flowgate-enforcement", "private ownership record")
	database := fs.String("bootstrap-database", "", "root-owned stored preset scopes for interface DHCP bootstrap")
	desired := fs.String("desired", "", "optional durable mode; monitoring skips boot guard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("root required for local guard/recovery")
	}
	if op == "protection-guard" {
		if *desired != "" {
			b, err := os.ReadFile(*desired)
			if err != nil {
				return err
			}
			var d struct {
				Schema int
				Mode   string
			}
			if json.Unmarshal(b, &d) != nil || d.Schema != 1 {
				return fmt.Errorf("invalid desired mode")
			}
			if d.Mode == "monitoring" {
				return nil
			}
			if d.Mode != "incoming" && d.Mode != "both" {
				return fmt.Errorf("invalid desired mode")
			}
		}
		var bootstrap []policy.BootstrapInterface
		if *database != "" {
			rules, err := store.ReadRules(*database)
			if err != nil {
				return err
			}
			bootstrap = policy.BootstrapFrom(rules, time.Now())
		}
		bootstrap, err := essential.GuardBootstrap(bootstrap)
		if err != nil {
			fmt.Fprintln(os.Stderr, "WARNING: automatic DHCP bootstrap discovery unavailable; retaining saved scopes:", err)
		}
		return hostfirewall.InstallGuard(*state, bootstrap...)
	}
	if err := hostfirewall.RecoverContinuous(*state); err != nil {
		return err
	}
	return hostfirewall.RemoveGuard(*state)
}
