import { parseConnectionZone } from './connection-presentation';
import { parseRule, type Decision, type RequestEvent, type Rule } from './protocol';
export const REMEMBER_ZONE_CAPABILITY = 'decision-zone-remember-v1';
export interface DecisionPreview {
  token: string;
  expires_at: string;
  event_id: string;
  action: 'allow' | 'block';
  scope: 'application' | 'persistent';
  network_zone: 'any' | 'local' | 'internet';
  zone_revision: string;
  generation: string;
  scope_preview: string;
  rule: Rule;
  connection_network: NonNullable<RequestEvent['flow']['network_scope']>;
}
const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
export function parseDecisionPreview(raw: unknown): DecisionPreview {
  const p = obj(raw);
  for (const key of ['token', 'event_id', 'zone_revision', 'generation', 'scope_preview'])
    if (
      typeof p[key] !== 'string' ||
      !p[key] ||
      String(p[key]).length > (key === 'scope_preview' ? 8192 : 256)
    )
      throw Error('Invalid decision preview');
  if (
    !['allow', 'block'].includes(String(p.action)) ||
    !['application', 'persistent'].includes(String(p.scope)) ||
    !['any', 'local', 'internet'].includes(String(p.network_zone)) ||
    !Number.isFinite(Date.parse(String(p.expires_at)))
  )
    throw Error('Invalid decision preview');
  const connection = parseConnectionZone(p.connection_network);
  if (!connection) throw Error('Decision preview classification missing');
  return {
    token: String(p.token),
    expires_at: String(p.expires_at),
    event_id: String(p.event_id),
    action: p.action as DecisionPreview['action'],
    scope: p.scope as DecisionPreview['scope'],
    network_zone: p.network_zone as DecisionPreview['network_zone'],
    zone_revision: String(p.zone_revision),
    generation: String(p.generation),
    scope_preview: String(p.scope_preview),
    rule: parseRule(p.rule),
    connection_network: connection,
  };
}
export function agreesWithDecision(p: DecisionPreview, d: Decision, e: RequestEvent, now: number) {
  const app = e.attribution.application,
    f = p.rule.filter;
  if (
    p.generation !== d.generation ||
    p.event_id !== d.id ||
    p.action !== d.action ||
    p.scope !== d.scope ||
    p.network_zone !== d.network_zone ||
    p.zone_revision !== d.zone_revision ||
    (d.network_zone !== 'any' &&
      (p.connection_network.state !== 'known' ||
        p.connection_network.zone !== d.network_zone ||
        p.connection_network.revision !== d.zone_revision ||
        e.flow.network_scope?.state !== 'known' ||
        e.flow.network_scope.zone !== d.network_zone ||
        e.flow.network_scope.revision !== d.zone_revision)) ||
    Date.parse(p.expires_at) <= now ||
    Date.parse(p.expires_at) > Date.parse(e.deadline) ||
    !p.scope_preview ||
    !app ||
    f.application !== app.key ||
    f.revision !== app.revision ||
    f.direction !== e.flow.direction ||
    f.protocol !== e.flow.protocol ||
    !e.remembered_filter ||
    f.uid !== e.remembered_filter.uid ||
    f.remote_address !== e.remembered_filter.remote_address ||
    (f.remote || '') !== (e.remembered_filter.remote || '') ||
    f.local_port !== e.remembered_filter.local_port ||
    f.remote_port !== e.remembered_filter.remote_port ||
    (d.scope === 'persistent'
      ? !p.rule.expires.startsWith('0001-')
      : !Number.isFinite(Date.parse(p.rule.expires)) ||
        Date.parse(p.rule.expires) <= now ||
        Math.abs(Date.parse(p.rule.expires) - Date.parse(p.rule.created) - 3600000) > 1000) ||
    p.rule.action !== d.action ||
    p.rule.version !== 1 ||
    p.rule.disabled ||
    !p.rule.id ||
    (e.attribution.owners.length > 0 &&
      e.attribution.owners.some((owner) => owner.uid !== f.uid)) ||
    f.process ||
    f.all_programs ||
    f.all_uids ||
    (f.network_zone || 'any') !== d.network_zone ||
    (d.preview_token && p.token !== d.preview_token)
  )
    throw Error('Preview does not match the displayed decision scope');
  return p;
}
export const sameRememberedRule = (a: Rule, b: Rule) => JSON.stringify(a) === JSON.stringify(b);
