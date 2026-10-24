package identity

// Attribution reason codes describe the observation that produced a result.
// They are diagnostics, not permission authority or proof of a root cause.
// Empty codes are retained for legacy/injected results; consumers must not infer
// a code from human-readable evidence. Future codes must remain safe to ignore.
const (
	ReasonAttributionNotRequired       = "attribution_not_required"
	ReasonNoUserspaceOwnerObserved     = "no_userspace_owner_observed"
	ReasonNoSocketObserved             = "no_socket_observed"
	ReasonNamespaceMismatch            = "namespace_mismatch"
	ReasonSocketCensusUnavailable      = "socket_census_unavailable"
	ReasonSocketChanged                = "socket_changed"
	ReasonMultipleCandidates           = "multiple_candidates"
	ReasonProcessVisibilityIncomplete  = "process_visibility_incomplete"
	ReasonRuntimeIdentityUnverified    = "runtime_identity_unverified"
	ReasonNativeOwnerObserved          = "native_owner_observed"
	ReasonRuntimeOwnerObserved         = "runtime_owner_observed"
	ReasonBrokerClientAssociation      = "broker_client_association"
	ReasonRuntimeSessionChanged        = "runtime_session_changed"
	ReasonRuntimeBrokerUnavailable     = "runtime_broker_unavailable"
	ReasonRuntimeEvidenceIncomplete    = "runtime_evidence_incomplete"
	ReasonRuntimeCensusUnavailable     = "runtime_census_unavailable"
	ReasonRuntimeOwnershipChanged      = "runtime_ownership_changed"
	ReasonRuntimeOwnerAmbiguous        = "runtime_owner_ambiguous"
	ReasonRuntimeHolderConflict        = "runtime_holder_conflict"
	ReasonRuntimeCapabilityUnavailable = "runtime_capability_unavailable"
	ReasonRuntimeObserverUnavailable   = "runtime_observer_unavailable"
	ReasonLocalhostExempt              = "localhost_exempt"
)

// Set both fields at every producing/overriding branch so a runtime refusal
// cannot retain an earlier native-success diagnostic. It changes no authority.
func (a *Attribution) setReason(code, reason string) {
	a.ReasonCode, a.Reason = code, reason
}
