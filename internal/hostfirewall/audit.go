package hostfirewall

import (
	"context"
	"encoding/json"
	"flowgate/internal/readiness"
	"fmt"
	"strings"
	"time"
)

// Re-run foreign-configuration readiness without mistaking our verified exact
// table and own queue for foreign conflicts. A digest check of our table occurs
// separately every second. Unknown/new foreign configuration fails closed.
func (m *Evaluation) auditEnvironment(parent context.Context, profile string) error {
	env := readiness.Default()
	run, read := env.Run, env.Read
	env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		b, err := run(ctx, name, args...)
		if err != nil {
			return b, err
		}
		if name == "nft" && strings.Join(args, " ") == "-j list ruleset" {
			var v map[string][]map[string]json.RawMessage
			if err = json.Unmarshal(b, &v); err != nil {
				return nil, err
			}
			filtered := v["nftables"][:0]
			for _, o := range v["nftables"] {
				own := false
				for _, raw := range o {
					var p struct {
						Table  string
						Name   string
						Family string
					}
					json.Unmarshal(raw, &p)
					if p.Family == "inet" && (p.Table == Table || p.Table == GuardTable || p.Name == Table || p.Name == GuardTable) {
						own = true
					}
				}
				if !own {
					filtered = append(filtered, o)
				}
			}
			v["nftables"] = filtered
			return json.Marshal(v)
		}
		return b, nil
	}
	env.Read = func(path string) ([]byte, error) {
		b, err := read(path)
		if strings.HasSuffix(path, "/nfnetlink_queue") && err == nil {
			lines := []string{}
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) == 0 || f[0] != "101" {
					lines = append(lines, l)
				}
			}
			b = []byte(strings.Join(lines, "\n"))
		}
		return b, err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	if err := blocked(readiness.FirewallFor(ctx, env, profile, m.e.AdministratorUID != nil)); err != nil {
		return fmt.Errorf("runtime foreign configuration no longer supported: %w", err)
	}
	return nil
}
