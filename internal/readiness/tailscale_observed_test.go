package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStartupDoesNotRequireTailscaleInitialization(t *testing.T) {
	for _, state := range []string{"empty", "partial", "complete"} {
		t.Run(state, func(t *testing.T) {
			env := tailEnvironment()
			original := env.Run
			nft := tailNFTFixture()
			if state == "empty" {
				nft = []byte(`{"nftables":[]}`)
			}
			if state == "partial" {
				var doc map[string][]map[string]json.RawMessage
				json.Unmarshal(nft, &doc)
				filtered := []map[string]json.RawMessage{}
				for _, o := range doc["nftables"] {
					if raw, ok := o["rule"]; ok {
						var r struct{ Table string }
						json.Unmarshal(raw, &r)
						if r.Table == "mangle" {
							continue
						}
					}
					filtered = append(filtered, o)
				}
				nft, _ = json.Marshal(map[string]any{"nftables": filtered})
			}
			env.Run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				if cmd == "tailscale" || strings.Contains(joined, "route show") {
					t.Fatalf("startup queried VPN client readiness: %s %s", cmd, joined)
				}
				if cmd == "nft" {
					return nft, nil
				}
				if state != "complete" && cmd == "ip" && strings.Contains(joined, "rule show") {
					return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`), nil
				}
				if state == "empty" && (cmd == "iptables" || strings.HasSuffix(cmd, "tables-save")) {
					t.Fatal("unneeded opaque export without opaque marks")
				}
				if state == "partial" && strings.HasSuffix(cmd, "tables-save") && joined == "-t mangle" {
					return []byte("*mangle\nCOMMIT\n"), nil
				}
				return original(ctx, cmd, args...)
			}
			for _, c := range FirewallFor(context.Background(), env, "both", true) {
				if c.Status == Blocked || (c.Status == Unchecked && c.ID != "firewall.queue_census") {
					t.Fatalf("%s: %+v", state, c)
				}
			}
		})
	}
}

func TestStartupStillRejectsMarkConflictsAndRaces(t *testing.T) {
	for _, mode := range []string{"unsafe-mask", "missing-export", "extra-export", "routing-mask", "duplicate", "foreign-queue"} {
		t.Run(mode, func(t *testing.T) {
			env := tailEnvironment()
			original := env.Run
			nft := tailNFTFixture()
			if mode == "duplicate" || mode == "foreign-queue" {
				var n map[string][]any
				json.Unmarshal(nft, &n)
				if mode == "duplicate" {
					n["nftables"] = append(n["nftables"], n["nftables"][3])
				} else {
					n["nftables"] = append(n["nftables"], map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": "INPUT", "expr": []any{map[string]any{"queue": map[string]any{"num": 101}}}}})
				}
				nft, _ = json.Marshal(n)
			}
			env.Run = func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
				b, err := original(ctx, cmd, args...)
				a := strings.Join(args, " ")
				if cmd == "iptables-save" && a == "-t mangle" {
					switch mode {
					case "unsafe-mask":
						b = []byte(strings.ReplaceAll(string(b), "--ctmask 0xff0000", "--ctmask 0xffffffff"))
					case "missing-export":
						b = nil
					case "extra-export":
						b = append(b, []byte(restoreRule+"\n")...)
					}
				}
				if mode == "routing-mask" && cmd == "ip" && strings.Contains(a, "rule show") {
					b = []byte(strings.ReplaceAll(string(b), "0xff0000", "0xffffffff"))
				}
				return b, err
			}
			c := observedTailscaleRules(context.Background(), env, nft)
			if c.Status != Blocked {
				t.Fatal(fmt.Sprintf("accepted %s: %+v", mode, c))
			}
		})
	}
}
