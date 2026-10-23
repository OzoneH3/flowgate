package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGenericMarkMasks(t *testing.T) {
	for _, mask := range []string{"0xff0000", "0xff00"} {
		for _, rule := range []string{
			"-A arbitrary -j MARK --set-xmark 0/" + mask,
			"-A arbitrary -m mark --mark 0/" + mask + " -j ACCEPT",
			"-A arbitrary -m connmark ! --mark 0/" + mask + " -j CONNMARK --restore-mark --nfmask " + mask + " --ctmask " + mask,
			"-A arbitrary -j CONNMARK --save-mark --ctmask " + mask + " --nfmask " + mask,
		} {
			if err := compatibleExport([]byte(rule)); err != nil {
				t.Fatal(rule, err)
			}
		}
	}
	for _, rule := range []string{
		"-A arbitrary -j MARK --set-xmark 0/0xffffffff",
		"-A arbitrary -j MARK --set-xmark 0x10000000/0xff00",
		"-A arbitrary -j MARK --set-mark 12",
		"-A arbitrary -j MARK --and-mark 0xff00",
		"-A arbitrary -j CONNMARK --restore-mark",
		"-A arbitrary -j CONNMARK --save-mark --nfmask 0xff00 --ctmask 0x10000000",
		"-A arbitrary -m connmark --mark 0 -j ACCEPT",
		"-A arbitrary -m mark --mark 0/0x30000000 -j ACCEPT",
		"-A arbitrary -j CT --zone 1",
		"-A arbitrary -j NOTRACK",
	} {
		if err := compatibleExport([]byte(rule)); err == nil {
			t.Fatal("accepted", rule)
		}
	}
}

func TestGenericRoutingMarks(t *testing.T) {
	for _, input := range []string{
		`[{"priority":901,"src":"all","fwmark":"0x400","fwmask":"0xff00","table":"123"}]`,
		`[{"priority":902,"src":"all","table":"456"}]`,
	} {
		if err := compatibleRouting([]byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{
		`[{"fwmark":"0x10000000","fwmask":"0x10000000"}]`,
		`[{"fwmark":"0x400"}]`, `[{"fwmask":"0xff00"}]`,
	} {
		if err := compatibleRouting([]byte(input)); err == nil {
			t.Fatal("accepted", input)
		}
	}
}

func genericMarkFixture(chain string) []byte {
	b, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"rule": map[string]any{"family": "ip", "table": "filter", "chain": chain, "expr": []any{map[string]any{"xt": map[string]any{"name": "MARK", "type": "target"}}}}}}})
	return b
}

func TestGenericCompatibilityProofAndSnapshotMismatch(t *testing.T) {
	for _, chain := range []string{"custom-one", "unrelated-two"} {
		for _, mode := range []string{"safe", "overlap", "missing", "changing"} {
			env := fakeEnv()
			calls := 0
			env.Run = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
				switch cmd {
				case "iptables":
					return []byte("iptables (nf_tables)"), nil
				case "nft":
					return genericMarkFixture(chain), nil
				case "ip":
					return []byte(`[]`), nil
				case "iptables-save":
					calls++
					mask := "0xff00"
					if mode == "overlap" {
						mask = "0x30000000"
					}
					if mode == "missing" {
						return []byte(""), nil
					}
					if mode == "changing" && calls > 1 {
						mask = "0xff0000"
					}
					return []byte(fmt.Sprintf("-A %s -j MARK --set-xmark 0/%s", chain, mask)), nil
				}
				return nil, fmt.Errorf("unexpected probe %s %v", cmd, args)
			}
			c := compatibleFirewallRules(context.Background(), env, genericMarkFixture(chain))
			if (c.Status == Ready) != (mode == "safe") {
				t.Fatalf("%s %s: %+v", chain, mode, c)
			}
		}
	}
}

func TestNativeMarkReadsAreBounded(t *testing.T) {
	safe := `{"nftables":[{"rule":{"family":"inet","table":"foreign","chain":"arbitrary","expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},65280]},"right":1024}}]}}]}`
	if err := compatibleNFT([]byte(safe)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(safe, "65280", "268435456", 1), strings.Replace(safe, "1024", "268435456", 1), strings.Replace(safe, `"op":"=="`, `"op":"in"`, 1)} {
		if err := compatibleNFT([]byte(bad)); err == nil {
			t.Fatal("unproven native mask accepted")
		}
	}
}
