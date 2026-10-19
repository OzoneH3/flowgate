import type { RequestEvent, Scope, SocketRow } from './protocol';
// Presentation only. Zone classification never changes the decision's permission scope.
export function connectionPresentation(flow: RequestEvent['flow']) {
  const direction =
    flow.direction === 'incoming'
      ? 'Incoming'
      : flow.direction === 'outgoing'
        ? 'Outgoing'
        : 'Unknown direction';
  const zone =
    flow.network_scope?.state === 'known'
      ? flow.network_scope.zone === 'local'
        ? 'Local Network'
        : 'Internet'
      : 'Zone unavailable';
  return {
    direction,
    zone,
    relation:
      flow.direction === 'incoming'
        ? 'Remote peer → this program'
        : flow.direction === 'outgoing'
          ? 'This program → remote peer'
          : 'Initiation direction unavailable',
  };
}
export function permissionTarget(
  scope: Scope,
  protocol: string,
  zone: 'any' | 'local' | 'internet' = 'any',
) {
  return scope === 'once'
    ? protocol === 'udp'
      ? 'Once · this UDP tuple · 30 seconds'
      : protocol === 'tcp'
        ? 'Once · this TCP connection · 30s admission'
        : 'Once · backend-defined scope'
    : `Application + peer/service · ${zone === 'local' ? 'Local Network' : zone === 'internet' ? 'Internet' : 'Any network'} · ${scope === 'application' ? '1 hour' : 'persistent'}`;
}
export function parseConnectionZone(value: unknown): SocketRow['network_scope'] {
  if (value === undefined) return;
  if (!value || typeof value !== 'object') throw Error('Invalid network scope');
  const n = value as Record<string, unknown>;
  if (
    !['known', 'unavailable'].includes(String(n.state)) ||
    (n.state === 'known' && !['local', 'internet'].includes(String(n.zone)))
  )
    throw Error('Invalid network scope');
  return {
    legacy_state: typeof n.legacy_state === 'string' ? n.legacy_state.slice(0, 256) : undefined,
    legacy_zone: typeof n.legacy_zone === 'string' ? n.legacy_zone.slice(0, 256) : undefined,
    legacy_revision: typeof n.legacy_revision === 'string' ? n.legacy_revision.slice(0, 256) : undefined,
    state: n.state as 'known' | 'unavailable',
    zone: n.state === 'known' ? (n.zone as 'local' | 'internet') : undefined,
    revision: typeof n.revision === 'string' ? n.revision : '',
    source: typeof n.source === 'string' ? n.source : '',
    reason: typeof n.reason === 'string' ? n.reason : '',
  };
}
