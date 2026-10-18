package readiness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const restoreRule = "-A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -m connmark ! --mark 0x0/0xff0000 -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000"
const saveRule = "-A OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000"
const filterRules = "-A INPUT -j ts-input\n-A ts-input -i tailscale0 -j ACCEPT\n-A ts-input -p udp -m udp --dport 41641 -j ACCEPT\n-A ts-forward -i tailscale0 -j MARK --set-xmark 0x40000/0xff0000\n-A ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT\n"

func tailNFTFixture() []byte {
	objects := []any{}
	for _, family := range []string{"ip", "ip6"} {
		for _, ch := range []struct {
			table, name, hook, kind string
			priority                int
		}{{"filter", "INPUT", "input", "filter", 0}, {"mangle", "OUTPUT", "output", "route", -150}, {"mangle", "PREROUTING", "prerouting", "filter", -150}} {
			objects = append(objects, map[string]any{"chain": map[string]any{"family": family, "table": ch.table, "name": ch.name, "hook": ch.hook, "type": ch.kind, "prio": ch.priority}})
		}
		for _, target := range []struct{ table, chain, name string }{{"filter", "ts-forward", "MARK"}, {"mangle", "PREROUTING", "CONNMARK"}, {"mangle", "OUTPUT", "CONNMARK"}, {"mangle", "PREROUTING", "connmark"}} {
			objects = append(objects, map[string]any{"rule": map[string]any{"family": family, "table": target.table, "chain": target.chain, "expr": []any{map[string]any{"xt": map[string]any{"name": target.name}}}}})
		}
	}
	b, _ := json.Marshal(map[string]any{"nftables": objects})
	return b
}
func tailEnvironment() Environment {
	env := fakeEnv()
	env.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		a := strings.Join(args, " ")
		switch name {
		case "nft":
			return tailNFTFixture(), nil
		case "tailscale":
			if strings.HasPrefix(a, "version") {
				return []byte(`{"short":"1.104.1","daemonLong":"1.104.1"}`), nil
			}
			return []byte(`{"WantRunning":true,"NetfilterMode":2}`), nil
		case "iptables":
			return []byte("iptables v1.8.13 (nf_tables)"), nil
		case "iptables-save", "ip6tables-save":
			if a == "-t filter" {
				return []byte(filterRules), nil
			}
			return []byte(restoreRule + "\n" + saveRule + "\n"), nil
		case "ip":
			if a == "-j -d link show" {
				return []byte(`[{"ifname":"tailscale0","linkinfo":{"info_kind":"tun"}}]`), nil
			}
			if strings.Contains(a, "route show") {
				return []byte(`[]`), nil
			}
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":5210,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"main"},{"priority":5230,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"default"},{"priority":5250,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","action":"unreachable"},{"priority":5270,"src":"all","table":"52"},{"priority":32766,"src":"all","table":"main"}]`), nil
		}
		return nil, fmt.Errorf("unhandled probe")
	}
	return env
}
func TestTailscaleProfileAndRouting(t *testing.T) {
	if TailscaleMask&FlowGateMask != 0 {
		t.Fatal("allocation overlap")
	}
	for _, tc := range []struct {
		profile string
		admin   bool
		want    string
	}{{"incoming", true, "tailscale_client_supported"}, {"incoming", false, "administrator_required"}, {"both", true, "tailscale_profile_unsupported"}} {
		c := Tailscale(context.Background(), tailEnvironment(), tailNFTFixture(), tc.profile, tc.admin)
		if c.Code != tc.want {
			t.Fatal(c)
		}
	}
	for _, tc := range []struct{ name, match, replacement string }{{"full-mask", "--ctmask 0xff0000", "--ctmask 0xffffffff"}, {"packet-full-mask", "--nfmask 0xff0000", "--nfmask 0xffffffff"}, {"full-value", "--set-xmark 0x40000/0xff0000", "--set-xmark 0x40000/0xffffffff"}} {
		table := "mangle"
		rules := restoreRule + "\n" + saveRule
		if tc.name == "full-value" {
			table = "filter"
			rules = filterRules
		}
		if err := tailscaleExport([]byte(strings.ReplaceAll(rules, tc.match, tc.replacement)), table); err == nil {
			t.Fatal(tc.name, "accepted")
		}
	}
	env := tailEnvironment()
	for _, c := range FirewallFor(context.Background(), env, "incoming", true) {
		if c.Status == Blocked || c.Status == Unchecked && c.ID != "firewall.queue_census" {
			t.Fatal(c)
		}
	}
	original := env.Run
	env.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		b, e := original(ctx, name, args...)
		if name == "ip" && strings.Contains(strings.Join(args, " "), "rule show") {
			b = []byte(strings.Replace(string(b), "0xff0000", "0xffffffff", 1))
		}
		return b, e
	}
	if c := Tailscale(context.Background(), env, tailNFTFixture(), "incoming", true); c.Status != Blocked {
		t.Fatal("routing conflict", c)
	}
}
func TestTailscaleOpaqueTargetsAndHooks(t *testing.T) {
	original := string(tailNFTFixture())
	for _, tc := range []struct{ from, to string }{{`"name":"CONNMARK"`, `"name":"CT"`}, {`"prio":-150`, `"prio":15`}, {`"name":"MARK"`, `"name":"CONNMARK"`}} {
		if err := tailscaleNFT([]byte(strings.Replace(original, tc.from, tc.to, 1))); err == nil {
			t.Fatal("unsupported target/hook accepted", tc)
		}
	}
	for _, expr := range []string{`{"mangle":{"key":{"ct":{"key":"mark"}},"value":524288}}`, `{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"ct":{"key":"mark"}}}}`, `{"match":{"left":{"ct":{"key":"mark"}},"right":0,"op":"=="}}`} {
		mutated := strings.Replace(original, `"expr":[`, `"expr":[`+expr+`,`, 1)
		if err := tailscaleNFT([]byte(mutated)); err == nil {
			t.Fatal("unmasked read/write accepted", expr)
		}
	}
}

func TestDockerDNATDoesNotHideMarkConflicts(t *testing.T) {
	for _, family := range []string{"ip", "ip6"} {
		appendRule := func(table, chain, name, kind string, extra ...any) []byte {
			var n map[string][]any
			if err := json.Unmarshal(tailNFTFixture(), &n); err != nil {
				t.Fatal(err)
			}
			expr := []any{map[string]any{"xt": map[string]any{"name": name, "type": kind}}}
			expr = append(expr, extra...)
			n["nftables"] = append(n["nftables"], map[string]any{"rule": map[string]any{"family": family, "table": table, "chain": chain, "expr": expr}})
			b, _ := json.Marshal(n)
			return b
		}
		b := appendRule("nat", "DOCKER", "DNAT", "target")
		if c := Tailscale(context.Background(), tailEnvironment(), b, "incoming", true); c.Status != Ready {
			t.Fatal(family, c)
		}
		for _, b := range [][]byte{
			appendRule("filter", "DOCKER", "DNAT", "target"),
			appendRule("nat", "other", "DNAT", "target"),
			appendRule("nat", "DOCKER", "DNAT", "match"),
			appendRule("nat", "DOCKER", "OTHER", "target"),
			appendRule("nat", "DOCKER", "DNAT", "target", map[string]any{"xt": map[string]any{"name": "MARK", "type": "target"}}),
			appendRule("nat", "DOCKER", "DNAT", "target", map[string]any{"mangle": map[string]any{"key": map[string]any{"ct": map[string]any{"key": "mark"}}, "value": 0}}),
		} {
			if err := tailscaleNFT(b); err == nil {
				t.Fatal(family, "accepted unsupported DNAT placement/target or adjacent mark write")
			}
		}
		if c := Tailscale(context.Background(), tailEnvironment(), b, "both", true); c.Code != "tailscale_profile_unsupported" {
			t.Fatal("DNAT changed outgoing refusal", c)
		}
	}
}
