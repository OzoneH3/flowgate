// Backend-configured policy zones; this module formats/validates, never classifies addresses.
export const ZONE_CAPABILITY = 'network-zone-policy-v1';
export type NetworkZone = 'local' | 'internet';
export interface NetworkZones {
  model: string;
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
    v.model !== 'configured-prefix-v1' ||
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
  return {
    model: v.model,
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
