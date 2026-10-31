package main

import (
	"flowgate/internal/readiness"
	"strings"
)

// Use the existing advisory-health UI; publishing a new network snapshot must
// not be rolled back because accelerator revocation failed.
func zonePublicationChecks(err error) []readiness.Check {
	if err == nil {
		return nil
	}
	severity := readiness.Optional
	if strings.Contains(err.Error(), "KERNEL REVOCATION UNCONFIRMED") {
		return []readiness.Check{{ID: "network.zone_publication", Status: readiness.Blocked, Code: "socket_revocation_unconfirmed", Detail: "Protection cannot confirm removal of prior connection authorization: " + err.Error(), Next: "Protection requires attention. Inspect the reported kernel failure and use the guarded protection recovery workflow."}}
	}
	return []readiness.Check{{
		ID: "network.zone_publication", Status: severity, Code: "socket_acceleration_unavailable",
		Detail: "Socket acceleration is unavailable; traffic uses ordinary verification: " + err.Error(),
		Next:   "Inspect socket authorization status. New authorization is disabled; revocation uses the kernel epoch or confirmed grant removal. A deliberate protection restart retries acceleration.",
	}}
}

func socketSessionChecks(err error) []readiness.Check {
	if err == nil {
		return nil
	}
	return []readiness.Check{{ID: "firewall.socket_acceleration", Status: readiness.Optional, Code: "socket_acceleration_unavailable",
		Detail: "Socket acceleration is off for this protection session; ordinary queue protection remains active: " + err.Error(),
		Next:   "Inspect the reported cause. A deliberate protection restart retries acceleration; existing rules and shaping settings remain unchanged."}}
}
