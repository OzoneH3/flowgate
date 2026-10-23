package main

import (
	"context"
	"flag"
	"flowgate/internal/diagnostics"
	"flowgate/internal/hostfirewall"
	"fmt"
	"os"
	"time"
)

func doctorCommand(args []string) error {
	o := diagnostics.Defaults()
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.StringVar(&o.Profile, "profile", o.Profile, "planned evaluation profile: incoming or both; no activation")
	fs.BoolVar(&o.Administrator, "administrator", false, "inspect planned explicit selected-peer administrator configuration; does not grant API permission")
	upgrade := fs.Bool("upgrade-preflight", false, "read-only candidate firewall checks after verified owned cleanup")
	jsonOutput := fs.Bool("json", false, "versioned JSON check output")
	fs.StringVar(&o.Helper, "udp-helper", o.Helper, "explicitly selected optional helper (inspected, never executed)")
	fs.StringVar(&o.State, "state", o.State, "existing controller state directory; never created")
	fs.StringVar(&o.Controller, "controller-socket", o.Controller, "existing control socket (list only)")
	collector := fs.String("udp-socket", "", "existing selected-user collector socket (list only)")
	uid := fs.Uint("uid", uint(o.UID), "selected GUI UID for collector path; does not change peer authorization")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.Profile != "incoming" && o.Profile != "both" {
		return fmt.Errorf("profile must be incoming or both")
	}
	if uint64(*uid) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid selected UID")
	}
	o.UID = uint32(*uid)
	o.Collector = fmt.Sprintf("/run/flowgate-traffic/%d/api.sock", o.UID)
	if *collector != "" {
		o.Collector = *collector
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if *upgrade {
		if os.Geteuid() != 0 {
			return fmt.Errorf("upgrade preflight requires root for complete kernel inspection")
		}
		checks, err := hostfirewall.UpgradePreflight(ctx, o.State, o.Profile)
		if err != nil {
			return err
		}
		output(map[string]any{"schema_version": 1, "checks": checks})
		return nil
	}
	r := diagnostics.Collect(ctx, o)
	if *jsonOutput {
		output(r)
	} else {
		diagnostics.Human(os.Stdout, r)
	}
	return nil // Findings are data; a nonzero exit means invalid invocation/build error.
}
