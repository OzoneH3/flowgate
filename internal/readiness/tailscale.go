package readiness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const TailscaleMask uint32 = 0x00ff0000
const FlowGateMask uint32 = 0x30000000

// Tailscale is a deliberately bounded client profile, not a general mark solver.
// Opaque xt targets require an independent iptables-nft export with exact masks.
func Tailscale(ctx context.Context, env Environment, nft []byte, profile string, administrator bool) Check {
	c := Check{ID: "firewall.tailscale", Status: Blocked, Code: "tailscale_unsupported", Next: "Use tailscale-inspect for bounded read-only evidence; do not bypass preflight"}
	fail := func(s string) Check { c.Detail = s; return c }
	version, err := env.Run(ctx, "tailscale", "version", "--daemon", "--json")
	if err != nil {
		return ProbeFailure(c.ID, err)
	}
	var versions struct {
		Short  string `json:"short"`
		Daemon string `json:"daemonLong"`
	}
	if json.Unmarshal(version, &versions) != nil || versions.Short != "1.104.1" || versions.Daemon != "1.104.1" {
		return fail("Tailscale CLI/daemon build outside the inspected 1.104.1 client profile")
	}
	prefs, err := env.Run(ctx, "tailscale", "debug", "prefs")
	if err != nil {
		return ProbeFailure(c.ID, err)
	}
	var p struct {
		RouteAll        bool
		ExitNodeID      string
		ExitNodeIP      string
		AdvertiseRoutes []string
		NetfilterMode   int
		WantRunning     bool
	}
	if json.Unmarshal(prefs, &p) != nil {
		return fail("Invalid Tailscale preferences")
	}
	if p.RouteAll || p.ExitNodeID != "" || (p.ExitNodeIP != "" && p.ExitNodeIP != "invalid IP") || len(p.AdvertiseRoutes) != 0 || p.NetfilterMode != 2 || !p.WantRunning {
		return fail("Only running netfilter-on Tailscale client with no accepted subnet routes, exit node or advertised routes is supported")
	}
	backend, err := env.Run(ctx, "iptables", "--version")
	if err != nil {
		return ProbeFailure(c.ID, err)
	}
	if !bytes.Contains(backend, []byte("nf_tables")) {
		return fail("Only the observed iptables-nft backend is supported, not legacy or native nft Tailscale variants")
	}
	if err := tailscaleNFT(nft); err != nil {
		return fail(err.Error())
	}
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		for _, table := range []string{"filter", "mangle"} {
			b, err := env.Run(ctx, tool, "-t", table)
			if err != nil {
				return ProbeFailure(c.ID, err)
			}
			if err := tailscaleExport(b, table); err != nil {
				return fail(fmt.Sprintf("%s/%s: %v", tool, table, err))
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		b, err := env.Run(ctx, "ip", "-j", family, "rule", "show")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		if err := tailscaleRouting(b, family); err != nil {
			return fail(err.Error())
		}
		b, err = env.Run(ctx, "ip", "-j", family, "route", "show", "table", "52")
		if err != nil {
			return ProbeFailure(c.ID, err)
		}
		var routes []map[string]any
		if json.Unmarshal(b, &routes) != nil {
			return fail("Invalid Tailscale table52 routes")
		}
		for _, r := range routes {
			if r["dev"] != "tailscale0" || r["dst"] == "default" || r["dst"] == "0.0.0.0/0" || r["dst"] == "::/0" || r["gateway"] != nil {
				return fail("Table52 contains unsupported default, gateway or non-tunnel routes")
			}
		}
	}
	if profile != "incoming" && profile != "both" {
		c.Code = "tailscale_profile_unsupported"
		return fail("Only incoming or both local-host admission profiles supported")
	}
	if !administrator {
		c.Code = "administrator_required"
		return fail("Tailscale transport belongs to a system UID: explicit --administrator grant is required to answer its ordinary application prompts")
	}
	c.Status = Ready
	c.Code = "tailscale_client_supported"
	c.Detail = "Tailscale 1.104.1 iptables-nft client; packet/conntrack copy masks 0x00ff0000 disjoint from 0x30000000; routing 5210/5230/5250/5270 inspected; incoming and outgoing local-host TCP/UDP admissions. No transport exemption: current tailscaled listener prompts as UID0; administrator must approve it separately from inner applications. Other firewall drops still apply; post-preflight changes require re-evaluation."
	c.Next = "Monitor must release its database before explicit evaluation; this check never stops it or activates enforcement"
	return c
}
func tailscaleExport(b []byte, table string) error {
	expected := map[string]int{}
	if table == "mangle" {
		expected["-A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -m connmark ! --mark 0x0/0xff0000 -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000"] = 1
		expected["-A OUTPUT -m conntrack --ctstate NEW -m mark ! --mark 0x0/0xff0000 -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000"] = 1
	} else {
		expected["-A ts-forward -i tailscale0 -j MARK --set-xmark 0x40000/0xff0000"] = 1
	}
	seen := map[string]int{}
	inputHook := false
	inputTun := false
	transport := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "-A INPUT -j ts-input" {
			inputHook = true
		}
		if line == "-A ts-input -i tailscale0 -j ACCEPT" {
			inputTun = true
		}
		if strings.HasPrefix(line, "-A ts-input -p udp -m udp --dport ") && strings.HasSuffix(line, " -j ACCEPT") {
			f := strings.Fields(line)
			v, _ := strconv.Atoi(f[7])
			if v > 0 && v < 65536 {
				transport = true
			}
		}
		// Every mark operation (reads included) must fit this finite profile. The
		// one masked ts-forward read is represented natively by nft and checked there.
		if strings.Contains(line, "MARK") || strings.Contains(line, "--mark") {
			if table == "filter" && line == "-A ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT" {
				continue
			}
			if expected[line] != 1 {
				return fmt.Errorf("unsupported mark read/write or copy mask (full assignments and extra copies refused)")
			}
			seen[line]++
		}
		if strings.Contains(line, "--ctzone") || strings.Contains(line, "NOTRACK") || strings.Contains(line, "NFQUEUE") {
			return fmt.Errorf("zone/notrack/queue outside supported profile")
		}
	}
	for line, count := range expected {
		if seen[line] != count {
			return fmt.Errorf("expected mark target absent or duplicated")
		}
	}
	if table == "filter" && (!inputHook || !inputTun || !transport) {
		return fmt.Errorf("Tailscale input hook, tunnel accept or transport listener rule absent")
	}
	return nil
}
func tailscaleRouting(b []byte, family string) error {
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil {
		return fmt.Errorf("Invalid policy routing response")
	}
	got := map[int]bool{}
	for _, r := range rows {
		pr, ok := r["priority"].(float64)
		if !ok {
			return fmt.Errorf("Unidentified routing priority")
		}
		n := int(pr)
		switch n {
		case 0, 32766, 32767:
			table := map[int]string{0: "local", 32766: "main", 32767: "default"}[n]
			if r["table"] != table || len(r) > 3 {
				return fmt.Errorf("Nonstandard baseline routing rule")
			}
		case 5210, 5230, 5250:
			if r["fwmark"] != "0x80000" || r["fwmask"] != "0xff0000" || r["src"] != "all" {
				return fmt.Errorf("Tailscale policy routing mask/selector differs")
			}
			if n == 5250 {
				if r["action"] != "unreachable" || len(r) != 5 {
					return fmt.Errorf("Unsupported Tailscale unreachable route rule")
				}
			} else {
				table := "main"
				if n == 5230 {
					table = "default"
				}
				if r["table"] != table || len(r) != 5 {
					return fmt.Errorf("Unsupported Tailscale lookup rule")
				}
			}
		case 5270:
			if r["table"] != "52" || r["src"] != "all" || len(r) != 3 {
				return fmt.Errorf("Unsupported Tailscale table52 selector")
			}
		default:
			return fmt.Errorf("Additional policy routing rule outside supported profile")
		}
		if got[n] {
			return fmt.Errorf("Duplicate policy routing priority")
		}
		got[n] = true
	}
	for _, n := range []int{0, 5210, 5230, 5250, 5270, 32766} {
		if !got[n] {
			return fmt.Errorf("%s Tailscale routing priority%d missing", family, n)
		}
	}
	return nil
}

// Validate both kernel-visible matches and the locations/count of opaque xt
// writers. The companion export validates their hidden masks, not their names.
func tailscaleNFT(b []byte) error {
	var n struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(b, &n) != nil {
		return fmt.Errorf("Invalid nft JSON")
	}
	expected := map[string]int{}
	for _, family := range []string{"ip", "ip6"} {
		expected[family+"/filter/ts-forward/MARK"] = 1
		expected[family+"/mangle/PREROUTING/CONNMARK"] = 1
		expected[family+"/mangle/OUTPUT/CONNMARK"] = 1
		expected[family+"/mangle/PREROUTING/connmark"] = 1
	}
	seen := map[string]int{}
	hooks := map[string]bool{}
	for _, o := range n.Nftables {
		if _, ok := o["flowtable"]; ok {
			return fmt.Errorf("Offload table outside supported profile")
		}
		if raw, ok := o["chain"]; ok {
			var ch map[string]any
			json.Unmarshal(raw, &ch)
			family, _ := ch["family"].(string)
			table, _ := ch["table"].(string)
			name, _ := ch["name"].(string)
			key := family + "/" + table + "/" + name
			required := map[string]struct {
				hook string
				prio float64
				kind string
			}{"filter/INPUT": {"input", 0, "filter"}, "mangle/OUTPUT": {"output", -150, "route"}, "mangle/PREROUTING": {"prerouting", -150, "filter"}}
			if want, ok := required[table+"/"+name]; ok && (family == "ip" || family == "ip6") {
				if ch["hook"] != want.hook || ch["prio"] != want.prio || ch["type"] != want.kind {
					return fmt.Errorf("Tailscale hook placement changed at%s", key)
				}
				hooks[key] = true
			}
		}
		raw, ok := o["rule"]
		if !ok {
			continue
		}
		var r map[string]any
		json.Unmarshal(raw, &r)
		family, _ := r["family"].(string)
		table, _ := r["table"].(string)
		chain, _ := r["chain"].(string)
		loc := family + "/" + table + "/" + chain
		var visit func(any) error
		visit = func(v any) error {
			switch x := v.(type) {
			case map[string]any:
				if xt, ok := x["xt"].(map[string]any); ok {
					name, _ := xt["name"].(string)
					key := loc + "/" + name
					switch name {
					case "MARK", "CONNMARK", "connmark":
						if expected[key] != 1 {
							return fmt.Errorf("Opaque mark operation at unsupported location%s", key)
						}
						seen[key]++
					case "conntrack", "addrtype", "MASQUERADE": // no mark assignment; NAT/drop coexistence remains independent
					case "DNAT":
						// xt_nat's DNAT target changes the destination tuple, not
						// packet/conntrack marks. Docker's published-port chain is
						// orthogonal to local INPUT admission; forwarded container
						// traffic is not covered by our incoming-only profile.
						if (family != "ip" && family != "ip6") || table != "nat" || chain != "DOCKER" || xt["type"] != "target" {
							return fmt.Errorf("DNAT outside inspected Docker NAT target location")
						}
					default:
						return fmt.Errorf("Opaque compatibility expression%s not supported", name)
					}
					return nil
				}
				if _, ok := x["mangle"]; ok {
					return fmt.Errorf("Native mark/mangle writer outside inspected iptables-nft profile")
				}
				if m, ok := x["match"].(map[string]any); ok && hasMark(m) {
					left, ok := m["left"].(map[string]any)
					if !ok {
						return fmt.Errorf("Unmasked mark comparison")
					}
					arr, ok := left["&"].([]any)
					if !ok || len(arr) != 2 || arr[1] != float64(TailscaleMask) {
						return fmt.Errorf("Mark read mask differs or intersects reserved authority")
					}
					meta, ok := arr[0].(map[string]any)
					if !ok {
						return fmt.Errorf("Unsupported mark input")
					}
					val, ok := meta["meta"].(map[string]any)
					if !ok || val["key"] != "mark" {
						return fmt.Errorf("Unexpected conntrack mark read")
					}
					value, ok := m["right"].(float64)
					if !ok || (value != 0 && value != 262144) {
						return fmt.Errorf("Unexpected masked mark comparison")
					}
					return nil
				}
				for k, y := range x {
					if k == "queue" || k == "notrack" || k == "flow" || k == "flowtable" || (k == "key" && y == "zone") {
						return fmt.Errorf("Queue/zone/notrack/offload outside supported profile")
					}
					if k == "key" && y == "mark" {
						return fmt.Errorf("Unhandled mark expression")
					}
					if err := visit(y); err != nil {
						return err
					}
				}
			case []any:
				for _, y := range x {
					if err := visit(y); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := visit(r["expr"]); err != nil {
			return fmt.Errorf("%s: %w", loc, err)
		}
	}
	for key, count := range expected {
		if seen[key] != count {
			return fmt.Errorf("Missing/duplicated kernel mark operation%s", key)
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		for _, suffix := range []string{"filter/INPUT", "mangle/OUTPUT", "mangle/PREROUTING"} {
			if !hooks[family+"/"+suffix] {
				return fmt.Errorf("Required Tailscale hook missing")
			}
		}
	}
	return nil
}
func hasMark(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if x["key"] == "mark" {
			return true
		}
		for _, y := range x {
			if hasMark(y) {
				return true
			}
		}
	case []any:
		for _, y := range x {
			if hasMark(y) {
				return true
			}
		}
	}
	return false
}
