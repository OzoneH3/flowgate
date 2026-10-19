// Backend-configured policy zones; this module formats/validates, never classifies addresses.
export const AUTOMATIC_ZONE_CAPABILITY = 'automatic-network-zones-v1';
export const ZONE_MIGRATION_CAPABILITY = 'zone-migration-v1';
export const AUTOMATIC_ZONE_MODEL = 'automatic-peer-v1';
export const LEGACY_ZONE_MODEL = 'configured-prefix-v1';
export const ZONE_CAPABILITY = 'network-zone-policy-v1';
export type NetworkZone = 'local' | 'internet';
export interface NetworkZones {
  model: string;
  registry_version?: string;
  network_revision?: string;
  network_state?: string;
  revision: string;
  local_prefixes: string[];
  internet_prefixes: string[];
  reason: string;
}
export const zoneLabel = (zone?: string) =>
  zone === 'local' ? 'Local Network' : zone === 'internet' ? 'Internet' : 'Any network';
export function parseNetworkZones(value: unknown): NetworkZones | undefined {
  if (value === undefined) return;
  const v = value as NetworkZones;
  if (
    !v ||
    ![LEGACY_ZONE_MODEL, AUTOMATIC_ZONE_MODEL].includes(v.model) ||
    typeof v.revision !== 'string' ||
    !v.revision ||
    v.revision.length > 128
  )
    throw Error('Unsupported network-zone definition');
  for (const key of ['local_prefixes', 'internet_prefixes'] as const)
    if (
      !Array.isArray(v[key]) ||
      v[key].length > 512 ||
      v[key].some((p) => typeof p !== 'string' || p.length > 128)
    )
      throw Error('Invalid network-zone prefixes');
  for (const key of ['registry_version', 'network_revision', 'network_state'] as const)
    if (v[key] !== undefined && (typeof v[key] !== 'string' || v[key]!.length > 4096))
      throw Error('Invalid network-zone metadata');
  return {
    model: v.model,
    ...(v.registry_version !== undefined ? { registry_version: v.registry_version } : {}),
    ...(v.network_revision !== undefined ? { network_revision: v.network_revision } : {}),
    ...(v.network_state !== undefined ? { network_state: v.network_state } : {}),
    revision: v.revision,
    local_prefixes: [...v.local_prefixes],
    internet_prefixes: [...v.internet_prefixes],
    reason: typeof v.reason === 'string' ? v.reason : '',
  };
}
export interface ZoneSource {
  generation: string;
  zone: NetworkZone;
  scope: 'machine' | 'self';
  revision: string;
  direction: 'incoming' | 'outgoing';
}

export const zoneModelLabel = (model?: string) =>
  model === AUTOMATIC_ZONE_MODEL ? 'Automatic peer classification' : 'Legacy configured prefixes';
// Formatting only. Prefix arrays under the automatic model are overrides, not
// an exhaustive inventory of Internet or Local peers.
export function zoneDefinitionDetails(z?: NetworkZones) {
  if (!z) return 'Network classification unavailable';
  return [
    zoneModelLabel(z.model),
    z.reason,
    z.network_state && `Network snapshot: ${z.network_state}`,
    z.registry_version && `Registry: ${z.registry_version}`,
    z.network_revision && `Network revision: ${z.network_revision}`,
    z.model === AUTOMATIC_ZONE_MODEL
      ? 'Prefix lists are configured overrides, not exhaustive coverage.'
      : 'Existing rules keep these configured prefixes until explicitly migrated.',
  ]
    .filter(Boolean)
    .join(' · ');
}
export function zoneRuleLabel(rule: {
  schema?: number;
  filter: { network_zone?: string; zone_model?: string };
}) {
  return rule.filter.network_zone
    ? `${zoneLabel(rule.filter.network_zone)} · ${rule.filter.zone_model === AUTOMATIC_ZONE_MODEL ? 'automatic' : 'legacy prefixes'}`
    : 'Any network';
}
