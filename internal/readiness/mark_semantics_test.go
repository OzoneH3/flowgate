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

func TestXTMultiportReadiness(t *testing.T) {
	const multiport = `{"xt":{"type":"match","name":"multiport"}}`
	const comment = `{"xt":{"type":"match","name":"comment"}}`
	const queue = `{"queue":{"num":101}}`
	for _, tc := range []struct {
		name, family, expr, refusal string
	}{
		{"IPv4 port match", "ip", multiport + "," + comment, ""},
		{"IPv6 port match", "ip6", multiport + "," + comment, ""},
		{"wrong type", "ip", strings.Replace(multiport, `"match"`, `"target"`, 1), "unsupported opaque expression"},
		{"wrong family", "inet", multiport, "unsupported opaque expression"},
		{"unexpected fields", "ip", `{"xt":{"type":"match","name":"multiport","extra":true}}`, "unsupported opaque expression"},
		{"wrong comment type", "ip", multiport + "," + strings.Replace(comment, `"match"`, `"target"`, 1), "unsupported opaque expression comment (target)"},
		{"queue before match", "ip", queue + "," + multiport + "," + comment, "unproven mark/queue/zone/notrack/offload expression"},
		{"queue after matches", "ip", multiport + "," + comment + "," + queue, "unproven mark/queue/zone/notrack/offload expression"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nft := fmt.Sprintf(`{"nftables":[{"rule":{"family":%q,"table":"filter","chain":"ufw-user-input","handle":134,"expr":[%s,{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}]}`, tc.family, tc.expr)
			env := fakeEnv()
			env.Run = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
				switch cmd + " " + strings.Join(args, " ") {
				case "nft -j list ruleset":
					return []byte(nft), nil
				case "ip -j -d link show", "ip -j -4 rule show", "ip -j -6 rule show":
					return []byte("[]"), nil
				default:
					return nil, fmt.Errorf("unexpected probe %s %v", cmd, args)
				}
			}
			seen := 0
			for _, check := range FirewallFor(context.Background(), env, "both", true) {
				if check.ID != "firewall.mark_compatibility" && check.ID != "firewall.ruleset" {
					continue
				}
				seen++
				t.Log(check.ID, check.Status, check.Code, check.Detail)
				if tc.refusal == "" {
					if check.Status != Ready {
						t.Errorf("port match was refused: %+v", check)
					}
					continue
				}
				want := tc.family + "/filter/ufw-user-input rule handle 134: " + tc.refusal
				if check.Status != Blocked || check.Code != "firewall_conflict" || !strings.HasPrefix(check.Detail, want) {
					t.Errorf("expected refusal %q, got %+v", want, check)
				}
			}
			if seen != 2 {
				t.Fatalf("expected both readiness checks, found %d", seen)
			}
		})
	}
}

func TestMarkAwareFIBReadiness(t *testing.T) {
	const marked = `{"match":{"op":"==","left":{"fib":{"result":"oif","flags":["saddr","mark","iif"]}},"right":0}}`
	const markFree = `{"match":{"op":"==","left":{"fib":{"result":"oif","flags":["saddr","iif"]}},"right":0}}`
	const acceptedXT = `{"xt":{"type":"target","name":"LOG"}}`
	for _, tc := range []struct {
		name  string
		expr  string
		block bool
	}{
		{"mark alone", marked, true},
		{"mark after xt", acceptedXT + "," + marked, true},
		{"mark before xt", marked + "," + acceptedXT, true},
		{"scalar mark flag", strings.Replace(marked, `["saddr","mark","iif"]`, `"mark"`, 1), true},
		{"mark-free lookup", markFree, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nft := fmt.Sprintf(`{"nftables":[{"rule":{"family":"ip","table":"filter","chain":"input","handle":42,"expr":[%s,{"drop":null}]}}]}`, tc.expr)
			env := fakeEnv()
			env.Run = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
				switch cmd + " " + strings.Join(args, " ") {
				case "nft -j list ruleset":
					return []byte(nft), nil
				case "ip -j -d link show", "ip -j -4 rule show", "ip -j -6 rule show":
					return []byte("[]"), nil
				default:
					return nil, fmt.Errorf("unexpected probe %s %v", cmd, args)
				}
			}
			seen := 0
			for _, check := range FirewallFor(context.Background(), env, "both", true) {
				switch check.ID {
				case "firewall.mark_compatibility", "firewall.ruleset":
				default:
					continue
				}
				seen++
				t.Log(check.ID, check.Status, check.Code, check.Detail)
				if tc.block {
					if check.Status != Blocked || check.Code != "firewall_conflict" ||
						check.Detail != "ip/filter/input rule handle 42: packet-mark FIB lookup is not proven compatible" {
						t.Errorf("expected a localized FIB refusal, got %+v", check)
					}
				} else if check.Status != Ready {
					t.Errorf("mark-free FIB was refused: %+v", check)
				}
			}
			if seen != 2 {
				t.Fatalf("expected both readiness checks, found %d", seen)
			}
		})
	}
}

func TestStrictIPv6ReversePathReadiness(t *testing.T) {
	const guard = `{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"match":{"op":"==","left":{"fib":{"result":"oif","flags":["saddr","mark","iif"]}},"right":false}},{"drop":null}`
	const defaults = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`
	const unsafeRPDB = `[{"priority":100,"fwmark":"0x10000000","fwmask":"0x10000000","table":"100"}]`
	for _, tc := range []struct {
		name, hook, expr, routes, suffix, refusal string
	}{
		{"stock strict IPv6 reverse path", "prerouting", guard, defaults, "", ""},
		{"wrong hook", "input", guard, defaults, "", "rule handle 141: packet-mark FIB lookup"},
		{"wrong protocol", "prerouting", strings.Replace(guard, `"ipv6"`, `"ipv4"`, 1), defaults, "", "rule handle 141: packet-mark FIB lookup"},
		{"wrong lookup", "prerouting", strings.Replace(guard, `"saddr"`, `"daddr"`, 1), defaults, "", "rule handle 141: packet-mark FIB lookup"},
		{"wrong verdict", "prerouting", strings.Replace(guard, `"drop"`, `"accept"`, 1), defaults, "", "rule handle 141: packet-mark FIB lookup"},
		{"queue in same rule", "prerouting", `{"queue":{"num":102}},` + guard, defaults, "", "rule handle 141: unproven mark/queue"},
		{"writer in later rule", "prerouting", guard, defaults, `,{"rule":{"family":"inet","table":"other","chain":"pre","handle":142,"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"ct":{"key":"mark"}}}}]}}`, "rule handle 142: native mark/mangle writer"},
		{"overlapping policy route", "prerouting", guard, unsafeRPDB, "", "routing mark selector overlaps reserved bits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use arbitrary names so the proof depends on the hook and
			// expression, without any reliance on the firewall vendor.
			nft := fmt.Sprintf(`{"nftables":[{"chain":{"family":"inet","table":"other","name":"pre","type":"filter","hook":%q,"prio":10}},{"rule":{"family":"inet","table":"other","chain":"pre","handle":141,"expr":[%s]}}%s]}`, tc.hook, tc.expr, tc.suffix)
			env := fakeEnv()
			env.Run = func(_ context.Context, cmd string, args ...string) ([]byte, error) {
				switch cmd + " " + strings.Join(args, " ") {
				case "nft -j list ruleset":
					return []byte(nft), nil
				case "ip -j -d link show", "ip -j -4 rule show":
					return []byte("[]"), nil
				case "ip -j -6 rule show":
					return []byte(tc.routes), nil
				default:
					return nil, fmt.Errorf("unexpected probe %s %v", cmd, args)
				}
			}
			seen := 0
			for _, check := range FirewallFor(context.Background(), env, "both", true) {
				if check.ID != "firewall.mark_compatibility" && check.ID != "firewall.ruleset" {
					continue
				}
				seen++
				t.Log(check.ID, check.Status, check.Code, check.Detail)
				if tc.refusal == "" {
					if check.Status != Ready {
						t.Errorf("strict IPv6 reverse-path guard refused: %+v", check)
					}
				} else if check.Status != Blocked || check.Code != "firewall_conflict" || !strings.Contains(check.Detail, tc.refusal) {
					t.Errorf("expected refusal %q, got %+v", tc.refusal, check)
				}
			}
			if seen != 2 {
				t.Fatalf("expected both readiness checks, found %d", seen)
			}
		})
	}
}
