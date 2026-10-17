package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"flowgate/internal/daemon"
	"flowgate/internal/policy"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Without explicit tokens, list/display exactly one version and use that same
// version after confirmation. Never retry a conflicting or ambiguous mutation.
func deleteRuleCLI(args []string, input io.Reader, output io.Writer) error {
	fs := flag.NewFlagSet("rule-delete", flag.ContinueOnError)
	path := fs.String("socket", ".workspace/run/control.sock", "policy API socket")
	id := fs.String("id", "", "rule ID")
	generation := fs.String("generation", "", "backend generation (requires --expected-version)")
	version := fs.String("expected-version", "", "exact server-issued version, including 0")
	yes := fs.Bool("yes", false, "confirm the listed version without interactive input")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id required")
	}
	var expected uint64
	if (*generation == "") != (*version == "") {
		return fmt.Errorf("--generation and --expected-version must be supplied together")
	}
	if *generation == "" {
		r, err := daemon.Call(*path, daemon.Request{Version: 1, Operation: "list"})
		if err != nil {
			return err
		}
		supported := false
		for _, cap := range r.Capabilities {
			if cap == daemon.ConditionalDeleteCapability {
				supported = true
			}
		}
		if !supported {
			return fmt.Errorf("backend does not advertise %s; no legacy fallback", daemon.ConditionalDeleteCapability)
		}
		if r.ReadOnly {
			return fmt.Errorf("read-only backend")
		}
		var selected *policy.Rule
		for _, rule := range r.Rules {
			if rule.ID == *id {
				copy := rule
				selected = &copy
				break
			}
		}
		if selected == nil {
			return fmt.Errorf("rule not found in authorized snapshot")
		}
		b, _ := json.MarshalIndent(selected, "", "  ")
		fmt.Fprintln(output, string(b))
		*generation = r.Generation
		expected = selected.Version
	} else {
		parsed, err := strconv.ParseUint(*version, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid expected version: %w", err)
		}
		expected = parsed
		fmt.Fprintf(output, "Delete %s at version %d, backend %s\n", *id, expected, *generation)
	}
	if !*yes {
		fmt.Fprint(output, "Delete this version? [y/N] ")
		line, err := bufio.NewReader(input).ReadString('\n')
		if err != nil || strings.ToLower(strings.TrimSpace(line)) != "y" {
			return fmt.Errorf("deletion cancelled")
		}
	}
	r, err := daemon.Call(*path, daemon.Request{Version: 1, Operation: "rule-delete", ID: *id, Generation: *generation, ExpectedVersion: &expected})
	if err != nil {
		if r.ErrorCode != "" {
			return fmt.Errorf("%s: %s", r.ErrorCode, r.Error)
		}
		if r.Error != "" {
			return fmt.Errorf("backend rejected deletion: %s", r.Error)
		}
		return fmt.Errorf("deletion outcome uncertain; inspect authoritative rules before retrying: %w", err)
	}
	return json.NewEncoder(output).Encode(r)
}
