package main

import "flowgate/internal/readiness"

// Use the existing advisory-health UI; publishing a new network snapshot must
// not be rolled back because accelerator revocation failed.
func zonePublicationChecks(err error) []readiness.Check {
	if err == nil {
		return nil
	}
	return []readiness.Check{{
		ID: "network.zone_publication", Status: readiness.Optional, Code: "socket_acceleration_unavailable",
		Detail: "Socket acceleration is unavailable; traffic uses ordinary verification: " + err.Error(),
		Next:   "Inspect socket authorization status. Existing grants expire within their original 250 ms maximum; new authorization is disabled. A deliberate protection restart retries acceleration.",
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
