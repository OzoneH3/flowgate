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

// Stock CachyOS UFW showed these four handles as xt matches. The parallel
// iptables-nft export identified ICMP types 3, 11, 12 and 8 in the same order.
func TestStockUFWICMPCompatibility(t *testing.T) {
	var rules []string
	for handle := 102; handle <= 105; handle++ {
		rules = append(rules, fmt.Sprintf(`{"rule":{"family":"ip","table":"filter","chain":"ufw-before-input","handle":%d,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"protocol"}},"right":"icmp"}},{"xt":{"type":"match","name":"icmp"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`, handle))
	}
	rules = append(rules,
		`{"rule":{"family":"ip","table":"filter","chain":"ufw-after-logging-input","handle":135,"expr":[{"limit":{"rate":3,"burst":10,"per":"minute"}},{"counter":{"packets":9,"bytes":513}},{"xt":{"type":"target","name":"LOG"}}]}}`,
		`{"rule":{"family":"ip","table":"filter","chain":"ufw-user-limit","handle":141,"expr":[{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"REJECT"}}]}}`,
		`{"rule":{"family":"ip6","table":"filter","chain":"ufw6-before-input","handle":52,"expr":[{"xt":{"type":"match","name":"rt"}},{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}`,
		`{"rule":{"family":"ip6","table":"filter","chain":"ufw6-before-input","handle":66,"expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"ipv6-icmp"}},{"xt":{"type":"match","name":"icmp6"}},{"xt":{"type":"match","name":"hl"}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`,
	)
	nft := `{"nftables":[` + strings.Join(rules, ",") + `]}`
	env := fakeEnv()
	env.Run = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		if cmd == "ip" {
			return []byte(`[]`), nil
		}
		t.Fatalf("pure ICMP compatibility should not need a side export: %s %v", cmd, args)
		return nil, nil
	}
	if check := compatibleFirewallRules(context.Background(), env, []byte(nft)); check.Status != Ready {
		t.Fatal(check)
	}
	for _, tc := range []struct{ old, replacement string }{
		{`"type":"match","name":"icmp"`, `"type":"target","name":"icmp"`},
		{`"type":"match","name":"icmp"`, `"type":"match","name":"recent"`},
		{`"type":"match","name":"icmp"`, `"type":"match","name":"icmp6"`},
		{`"type":"match","name":"icmp"`, `"name":"icmp"`},
		{`{"accept":null}`, `{"queue":{"num":101}}`},
	} {
		check := compatibleFirewallRules(context.Background(), env,
			[]byte(strings.Replace(nft, tc.old, tc.replacement, 1)))
		if check.Status != Blocked || !strings.Contains(check.Detail, "ip/filter/ufw-before-input rule handle 102") {
			t.Fatalf("unproven expression not localized: %+v", check)
		}
	}
	if err := compatibleNFT([]byte(strings.Replace(nft, `"type":"target","name":"LOG"`, `"type":"watcher","name":"LOG"`, 1))); err == nil || !strings.Contains(err.Error(), "ufw-after-logging-input rule handle 135") {
		t.Fatalf("wrong-kind LOG did not remain blocked: %v", err)
	}
}
