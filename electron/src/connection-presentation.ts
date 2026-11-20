import type { RequestEvent, Scope, SocketRow } from './protocol';
import { zoneLabel } from './network-zones';
// Known zone with its classification basis; a custom prefix override is never
// presented as if the automatic classifier had chosen it.
export function scopeZoneText(scope: SocketRow['network_scope']) {
  if (scope?.state !== 'known') return scope?.reason || 'Classification unavailable';
  return (
    zoneLabel(scope.zone) +
    (scope.basis === 'custom'
      ? ' · custom classification'
      : scope.basis === 'automatic'
        ? ' · automatic'
        : ' · configured policy zone')
  );
}
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
      ? zoneLabel(flow.network_scope.zone) +
        (flow.network_scope.basis === 'custom' ? ' (custom)' : '')
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

// The daemon emits these Once details only for its verified whole-application
// UDP Ask paths. Use the preview as evidence instead of evaluating rule scope here.
const outgoingUDPOnce = 'Allow Once permits later datagrams on this UDP tuple for 30 seconds. Already queued datagrams will be discarded.';
const incomingUDPOnce = 'Block Once drops queued datagrams. The next datagram can open a new request.';

export function compactUDPOnce(event: Pick<RequestEvent, 'flow' | 'ask_rule' | 'scope_previews'>) {
  const preview = event.scope_previews.once;
  if (event.flow.protocol !== 'udp' || !event.ask_rule || !preview) return;
  if (event.flow.direction === 'outgoing' && preview === outgoingUDPOnce) {
    return {
      summary: 'Allow drops waiting datagrams and permits later sends for 30 seconds. Deny drops both.',
      allow: outgoingUDPOnce + ' No rule is saved.',
      block: 'Deny drops waiting datagrams and blocks later sends on this UDP tuple for 30 seconds. No rule is saved.',
    };
  }
  if (event.flow.direction === 'incoming' && preview.endsWith(' ' + incomingUDPOnce)) {
    return {
      summary: 'Allow permits waiting datagrams and later sends for 30 seconds. Deny drops waiting datagrams. The next send can prompt again.',
      allow: 'Allow permits waiting datagrams and later sends on this UDP tuple for 30 seconds. No rule is saved.',
      block: 'Deny drops waiting datagrams. The next send can prompt again. No rule is saved.',
    };
  }
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
    basis: n.basis === 'custom' || n.basis === 'automatic' ? n.basis : undefined,
  };
}
