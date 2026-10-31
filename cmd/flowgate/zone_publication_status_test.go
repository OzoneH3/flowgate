package main

import (
	"errors"
	"flowgate/internal/readiness"
	"strings"
	"testing"
)

func TestZonePublicationFailureVisibleWithoutRollingBackNetwork(t *testing.T) {
	if len(zonePublicationChecks(nil)) != 0 {
		t.Fatal("healthy publication degraded")
	}
	checks := zonePublicationChecks(errors.New("epoch write failed"))
	if len(checks) != 1 || checks[0].Status != readiness.Optional || !strings.Contains(checks[0].Detail, "ordinary verification") || !strings.Contains(checks[0].Detail, "epoch write failed") {
		t.Fatalf("publication failure hidden: %+v", checks)
	}
}

func TestSocketSessionFailureIsOptionalAndExplicit(t *testing.T) {
	if len(socketSessionChecks(nil)) != 0 {
		t.Fatal("healthy session degraded")
	}
	checks := socketSessionChecks(errors.New("kernel capability unavailable"))
	if len(checks) != 1 || checks[0].Status != readiness.Optional || !strings.Contains(checks[0].Detail, "queue protection remains active") || !strings.Contains(checks[0].Next, "restart") {
		t.Fatal(checks)
	}
}

func TestUnconfirmedConnectionRevocationIsBlocked(t *testing.T) {
	checks := zonePublicationChecks(errors.New("KERNEL REVOCATION UNCONFIRMED: injected"))
	if len(checks) != 1 || checks[0].Status != readiness.Blocked {
		t.Fatal("unsafe revocation shown as optional", checks)
	}
}
