package main

import (
	"context"
	"flag"
	"flowgate/internal/diagnostics"
	"fmt"
	"os"
	"time"
)

func doctorCommand(args []string) error {
	o := diagnostics.Defaults()
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOutput := fs.Bool("json", false, "versioned JSON check output")
	fs.StringVar(&o.Helper, "udp-helper", o.Helper, "explicitly selected optional helper (inspected, never executed)")
	fs.StringVar(&o.State, "state", o.State, "existing controller state directory; never created")
	fs.StringVar(&o.Controller, "controller-socket", o.Controller, "existing control socket (list only)")
	collector := fs.String("udp-socket", "", "existing selected-user collector socket (list only)")
	uid := fs.Uint("uid", uint(o.UID), "selected GUI UID for collector path; does not change peer authorization")
	if err := fs.Parse(args); err != nil {
		return err
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
	r := diagnostics.Collect(ctx, o)
	if *jsonOutput {
		output(r)
	} else {
		diagnostics.Human(os.Stdout, r)
	}
	return nil // Findings are data; a nonzero exit means invalid invocation/build error.
}
