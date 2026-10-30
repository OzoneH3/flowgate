package hostfirewall

import (
	"context"
	"flowgate/internal/readiness"
	"fmt"
	"os"
)

// UpgradePreflight predicts compatibility after deliberate Stop without touching
// interception. Only verified owned objects are omitted. Activation still runs
// its full preflight, exclusive bind and ownership checks after installation.
func UpgradePreflight(ctx context.Context, dir, profile string) ([]readiness.Check, error) {
	// A fresh install has no state directory and therefore no owned objects to
	// omit. Inspect the complete ruleset rather than creating state here.
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return readiness.FirewallFor(ctx, readiness.Default(), profile, true), nil
	} else if err != nil {
		return nil, err
	}
	host := false
	if r, err := Read(dir); err == nil {
		present, err := owns(r)
		if err != nil {
			return nil, err
		}
		if present {
			digest, err := tableDigestForFormat(Table, r.DigestFormat)
			if err != nil || digest != r.TableDigest || r.Start == "" || startID(r.PID) != r.Start {
				return nil, fmt.Errorf("cannot verify current consumer and owned interception before upgrade")
			}
			host = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	guard, err := guardOwned(dir)
	if err != nil {
		return nil, err
	}
	return readiness.FirewallFor(ctx, foreignEnvironment(readiness.Default(), host, guard), profile, true), nil
}
