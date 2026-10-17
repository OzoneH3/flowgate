package main

import (
	"context"
	"encoding/json"
	"flag"
	"flowgate/internal/hostfirewall"
	"flowgate/internal/readiness"
	"fmt"
	"strings"
	"time"
)

// Narrow fixed read-only probes; never a root command runner or raw prefs dump.
func tailscaleInspectCommand(args []string) error {
	fs := flag.NewFlagSet("tailscale-inspect", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("no positional arguments supported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env := readiness.Default()
	out := map[string]any{"schema_version": 1, "scope": "read-only Tailscale coexistence inspection; no mutation, queue bind or collector"}
	run := func(key, cmd string, args ...string) []byte {
		b, e := env.Run(ctx, cmd, args...)
		if e != nil {
			out[key] = readiness.ProbeFailure(key, e)
			return nil
		}
		return b
	}
	if b := run("version", "tailscale", "version", "--daemon", "--json"); b != nil {
		var v map[string]any
		if json.Unmarshal(b, &v) == nil {
			out["version"] = v
		} else {
			out["version"] = "invalid version response"
		}
	}
	if b := run("preferences", "tailscale", "debug", "prefs"); b != nil {
		var p map[string]json.RawMessage
		if json.Unmarshal(b, &p) == nil {
			summary := map[string]any{}
			for _, k := range []string{"RouteAll", "NoSNAT", "NetfilterMode", "ShieldsUp", "WantRunning", "RunSSH", "ExitNodeAllowLANAccess", "NoStatefulFiltering"} {
				if v, ok := p[k]; ok {
					summary[k] = v
				}
			}
			var routes []string
			json.Unmarshal(p["AdvertiseRoutes"], &routes)
			summary["advertised_route_count"] = len(routes)
			var id, ip string
			json.Unmarshal(p["ExitNodeID"], &id)
			json.Unmarshal(p["ExitNodeIP"], &ip)
			summary["exit_node_selected"] = id != "" || (ip != "" && ip != "invalid IP")
			out["preferences"] = summary
		}
	}
	if b := run("nft", "nft", "-j", "list", "ruleset"); b != nil {
		var n struct {
			Nftables []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal(b, &n) == nil {
			chains := []map[string]any{}
			marks := []map[string]any{}
			compat := []map[string]any{}
			tables := []map[string]any{}
			for _, o := range n.Nftables {
				for _, kind := range []string{"table", "chain", "rule"} {
					if v, ok := o[kind]; ok {
						var x map[string]any
						json.Unmarshal(v, &x)
						if kind == "table" {
							tables = append(tables, map[string]any{"family": x["family"], "name": x["name"]})
						}
						if kind == "chain" {
							chains = append(chains, map[string]any{"family": x["family"], "table": x["table"], "name": x["name"], "type": x["type"], "hook": x["hook"], "prio": x["prio"], "policy": x["policy"]})
						}
						if kind == "rule" {
							var selectMarks func(any)
							selectMarks = func(v any) {
								switch t := v.(type) {
								case map[string]any:
									if xt, ok := t["xt"]; ok {
										compat = append(compat, map[string]any{"family": x["family"], "table": x["table"], "chain": x["chain"], "xt": xt})
										return
									}
									if _, ok := t["mangle"]; ok {
										marks = append(marks, map[string]any{"family": x["family"], "table": x["table"], "chain": x["chain"], "statement": t})
										return
									}
									if _, ok := t["match"]; ok {
										b, _ := json.Marshal(t)
										if containsMark(t) {
											marks = append(marks, map[string]any{"family": x["family"], "table": x["table"], "chain": x["chain"], "statement": json.RawMessage(b)})
										}
										return
									}
									for _, z := range t {
										selectMarks(z)
									}
								case []any:
									for _, z := range t {
										selectMarks(z)
									}
								}
							}
							selectMarks(x["expr"])
						}
					}
				}
			}
			out["nft"] = map[string]any{"tables": tables, "chains": chains, "mark_statements": marks, "compat": compat}
		}
	}
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		for _, table := range []string{"mangle", "filter"} {
			key := tool + "." + table
			if b := run(key, tool, "-t", table); b != nil {
				lines := []string{}
				for _, line := range strings.Split(string(b), "\n") {
					if strings.Contains(line, "MARK") || strings.Contains(line, "ts-") {
						parts := strings.Fields(line)
						for i := 1; i < len(parts); i++ {
							if parts[i-1] == "-s" || parts[i-1] == "-d" {
								parts[i] = "<address-redacted>"
							}
						}
						lines = append(lines, strings.Join(parts, " "))
					}
				}
				out[key] = lines
			}
		}
	}
	if b := run("iptables_backend", "iptables", "--version"); b != nil {
		out["iptables_backend"] = string(b)
	}
	for _, family := range []string{"-4", "-6"} {
		if b := run("rules"+family, "ip", "-j", family, "rule", "show"); b != nil {
			var rows []map[string]any
			if json.Unmarshal(b, &rows) == nil {
				for _, r := range rows {
					for _, key := range []string{"src", "dst"} {
						if v, ok := r[key]; ok && v != "all" {
							r[key] = "<non-all selector>"
						}
					}
				}
				out["rules"+family] = rows
			}
		}
		if b := run("routes52"+family, "ip", "-j", family, "route", "show", "table", "52"); b != nil {
			var rows []map[string]any
			if json.Unmarshal(b, &rows) == nil {
				summary := map[string]int{"routes": len(rows), "default_routes": 0, "tailscale0_routes": 0}
				for _, r := range rows {
					if r["dst"] == "default" {
						summary["default_routes"]++
					}
					if r["dev"] == "tailscale0" {
						summary["tailscale0_routes"]++
					}
				}
				out["routes52"+family] = summary
			}
		}
	}
	if marks, err := hostfirewall.MarkCensus(); err == nil {
		out["conntrack_marks"] = marks
	} else {
		out["conntrack_marks"] = readiness.ProbeFailure("conntrack_marks", err)
	}
	output(out)
	return nil
}
func containsMark(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if x["key"] == "mark" {
			return true
		}
		for _, y := range x {
			if containsMark(y) {
				return true
			}
		}
	case []any:
		for _, y := range x {
			if containsMark(y) {
				return true
			}
		}
	}
	return false
}
