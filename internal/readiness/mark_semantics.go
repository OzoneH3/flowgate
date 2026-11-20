package readiness

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const flowGateMarkMask uint32 = 0x30000000

func markNumber(v any) (uint32, bool) {
	switch n := v.(type) {
	case float64:
		if n >= 0 && n <= math.MaxUint32 && n == math.Trunc(n) {
			return uint32(n), true
		}
	case string:
		u, err := strconv.ParseUint(n, 0, 32)
		return uint32(u), err == nil
	}
	return 0, false
}
func disjoint(mask uint32) bool { return mask != 0 && mask&flowGateMarkMask == 0 }
func maskedValue(s string) bool {
	v, m, ok := strings.Cut(s, "/")
	value, vok := markNumber(v)
	mask, mok := markNumber(m)
	return ok && vok && mok && disjoint(mask) && value & ^mask == 0
}

// Only finite, explicit mark operations are accepted. Unsupported syntax does
// not fall back to a chain/interface name or a permissive default mask.
func compatibleExport(b []byte) error {
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "-A" {
			continue
		}
		for _, token := range f {
			if token == "NOTRACK" || token == "NFQUEUE" || token == "CT" || token == "--ctzone" {
				return fmt.Errorf("queue/zone/notrack operation is unsupported")
			}
		}
		relevant := strings.Contains(line, "MARK") || strings.Contains(line, "--mark") || strings.Contains(line, "connmark")
		if !relevant {
			continue
		}
		if strings.ContainsAny(line, "\"'\\") {
			return fmt.Errorf("quoted/escaped mark expression cannot be proven")
		}
		for i := 2; i < len(f); i++ {
			if f[i] == "--mark" {
				if i+1 >= len(f) || !maskedValue(f[i+1]) {
					return fmt.Errorf("mark read overlaps reserved bits or lacks an explicit mask")
				}
				i++
				continue
			}
			if f[i] != "-j" || i+1 >= len(f) || (f[i+1] != "MARK" && f[i+1] != "CONNMARK") {
				continue
			}
			target, args := f[i+1], f[i+2:]
			if len(args) == 2 {
				switch args[0] {
				case "--set-xmark", "--set-mark":
					if maskedValue(args[1]) {
						break
					}
					return fmt.Errorf("mark assignment overlaps reserved bits")
				case "--or-mark", "--xor-mark", "--and-mark":
					v, ok := markNumber(args[1])
					if args[0] == "--and-mark" {
						v = ^v
					}
					if !ok || v&flowGateMarkMask != 0 {
						return fmt.Errorf("mark bit operation overlaps reserved bits")
					}
				default:
					return fmt.Errorf("unsupported mark operation")
				}
			} else if target == "CONNMARK" && len(args) == 5 && (args[0] == "--save-mark" || args[0] == "--restore-mark") {
				masks := map[string]uint32{}
				for j := 1; j < len(args); j += 2 {
					v, ok := markNumber(args[j+1])
					if !ok || !disjoint(v) || (args[j] != "--nfmask" && args[j] != "--ctmask") {
						return fmt.Errorf("unproven packet/conntrack copy mask")
					}
					masks[args[j]] = v
				}
				if len(masks) != 2 || masks["--nfmask"] != masks["--ctmask"] {
					return fmt.Errorf("copy masks must be explicit, equal and disjoint")
				}
			} else {
				return fmt.Errorf("unbounded mark operation")
			}
			break
		}
	}
	return nil
}

func compatibleRouting(b []byte) error {
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil {
		return fmt.Errorf("invalid routing selectors")
	}
	for _, r := range rows {
		value, has := r["fwmark"]
		if !has {
			if _, maskOnly := r["fwmask"]; maskOnly {
				return fmt.Errorf("routing mask without mark")
			}
			continue
		}
		v, vok := markNumber(value)
		m, mok := markNumber(r["fwmask"])
		if !vok || !mok || !disjoint(m) || v & ^m != 0 {
			return fmt.Errorf("routing mark selector overlaps reserved bits or lacks an explicit mask")
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
func markInput(v any) bool {
	x, ok := v.(map[string]any)
	if !ok || len(x) != 1 {
		return false
	}
	for _, kind := range []string{"meta", "ct"} {
		if m, ok := x[kind].(map[string]any); ok && len(m) == 1 && m["key"] == "mark" {
			return true
		}
	}
	return false
}

func fibUsesPacketMark(fib map[string]any) bool {
	switch flags := fib["flags"].(type) {
	case string:
		return flags == "mark"
	case []any:
		for _, flag := range flags {
			if flag == "mark" {
				return true
			}
		}
	}
	return false
}

func compatibleNFT(b []byte) error {
	var n struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(b, &n) != nil {
		return fmt.Errorf("invalid nft JSON")
	}
	for _, o := range n.Nftables {
		if _, ok := o["flowtable"]; ok {
			return fmt.Errorf("offload table is unsupported")
		}
		raw, ok := o["rule"]
		if !ok {
			continue
		}
		var r struct {
			Family, Table, Chain string
			Handle               uint64
			Expr                 any
		}
		if json.Unmarshal(raw, &r) != nil || r.Expr == nil {
			return fmt.Errorf("invalid rule")
		}
		var visit func(any) error
		visit = func(v any) error {
			switch x := v.(type) {
			case map[string]any:
				// A marked FIB lookup takes the whole packet mark as an
				// input. No disjoint mask can be proven from this node.
				if fib, ok := x["fib"].(map[string]any); ok && fibUsesPacketMark(fib) {
					return fmt.Errorf("packet-mark FIB lookup is not proven compatible")
				}
				if xt, ok := x["xt"].(map[string]any); ok {
					switch xt["name"] {
					case "MARK", "CONNMARK", "connmark":
						if r.Family != "ip" && r.Family != "ip6" {
							return fmt.Errorf("opaque mark family cannot be exported")
						}
						switch r.Table {
						case "filter", "mangle", "nat", "raw", "security":
						default:
							return fmt.Errorf("opaque mark table cannot be exported")
						}
					case "conntrack", "addrtype", "MASQUERADE", "DNAT", "SNAT":
					case "icmp", "icmp6", "hl", "rt", "multiport", "LOG", "REJECT":
						// These matches inspect protocol headers. LOG continues
						// traversal and REJECT denies the packet like native
						// reject. None uses reserved marks to choose a verdict.
						ip := r.Family == "ip"
						ip6 := r.Family == "ip6"
						match := xt["type"] == "match" && (ip && xt["name"] == "icmp" ||
							ip6 && (xt["name"] == "icmp6" || xt["name"] == "hl" || xt["name"] == "rt") ||
							(ip || ip6) && xt["name"] == "multiport")
						target := xt["type"] == "target" && (ip || ip6) &&
							(xt["name"] == "LOG" || xt["name"] == "REJECT")
						if len(x) != 1 || len(xt) != 2 || !(match || target) {
							return fmt.Errorf("unsupported opaque expression %v (%v)", xt["name"], xt["type"])
						}
					default:
						return fmt.Errorf("unsupported opaque expression %v", xt["name"])
					}
					return nil
				}
				if _, ok := x["mangle"]; ok {
					return fmt.Errorf("native mark/mangle writer is not proven")
				}
				if m, ok := x["match"].(map[string]any); ok && hasMark(m) {
					left, ok := m["left"].(map[string]any)
					if !ok || len(left) != 1 {
						return fmt.Errorf("unmasked mark comparison")
					}
					a, ok := left["&"].([]any)
					if !ok || len(a) != 2 || !markInput(a[0]) {
						return fmt.Errorf("unsupported mark input")
					}
					mask, mok := markNumber(a[1])
					value, vok := markNumber(m["right"])
					if !mok || !vok || !disjoint(mask) || value & ^mask != 0 {
						return fmt.Errorf("mark read overlaps reserved bits")
					}
					if m["op"] != "==" && m["op"] != "!=" {
						return fmt.Errorf("unsupported mark comparison")
					}
					return nil
				}
				for k, y := range x {
					if k == "queue" || k == "notrack" || k == "flow" || k == "flowtable" || (k == "key" && (y == "zone" || y == "mark")) {
						return fmt.Errorf("unproven mark/queue/zone/notrack/offload expression")
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
		if err := visit(r.Expr); err != nil {
			if r.Handle != 0 {
				return fmt.Errorf("%s/%s/%s rule handle %d: %w", r.Family, r.Table, r.Chain, r.Handle, err)
			}
			return fmt.Errorf("%s/%s/%s: %w", r.Family, r.Table, r.Chain, err)
		}
	}
	return nil
}
