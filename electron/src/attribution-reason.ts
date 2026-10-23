// Diagnostic categories supplied by the backend. Never infer these from prose,
// ownership labels or verdicts, and never use them as permission authority.
const LABELS: Readonly<Record<string, string>> = Object.freeze({
  no_socket_observed: 'No matching socket observed',
  namespace_mismatch: 'Outside observer network namespace',
  socket_census_unavailable: 'Socket census unavailable',
  socket_changed: 'Socket evidence changed',
  multiple_candidates: 'Ambiguous owner candidates',
  process_visibility_incomplete: 'Process visibility incomplete',
  runtime_identity_unverified: 'Runtime identity unverified',
  native_owner_observed: 'Native owner observed',
  runtime_owner_observed: 'Runtime owner corroborated',
  broker_client_association: 'Broker/client association',
  runtime_session_changed: 'Runtime session changed',
  runtime_broker_unavailable: 'Runtime broker unavailable',
  runtime_evidence_incomplete: 'Runtime evidence incomplete',
  runtime_census_unavailable: 'Runtime census unavailable',
  runtime_ownership_changed: 'Runtime ownership changed',
  runtime_owner_ambiguous: 'Runtime owner ambiguous',
  runtime_holder_conflict: 'Runtime and Linux holders disagree',
  runtime_capability_unavailable: 'Runtime capability unavailable',
  runtime_observer_unavailable: 'Runtime observer unavailable',
  localhost_exempt: 'Localhost exemption (not owner identification)',
});

// Additive optional metadata: malformed values must not discard the record or
// its original evidence. Preserve well-formed future codes without guessing.
export function parseAttributionReasonCode(value: unknown): string | undefined {
  return typeof value === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(value)
    ? value : undefined;
}

export function attributionReasonLabel(code: string): string {
  return Object.hasOwn(LABELS, code) ? LABELS[code] : 'Unrecognized attribution category';
}
