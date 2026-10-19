import { parseConnectionZone } from './connection-presentation';
import { canManageRules, parseRule, type ClientState, type Decision, type ObservedSource, type RequestEvent, type Rule } from './protocol';
import { authoritativePolicy } from './policy';
import type { Row } from './model';
export const REMEMBER_ZONE_CAPABILITY = 'decision-zone-remember-v1';
// NetLimiter 5.3.28 Remember: application always; protocol, process, remote
// address and remote (incoming: local) port optional; optional deletion time.
export const REMEMBER_FIELDS_CAPABILITY = 'decision-remember-fields-v1';
export type RememberFields = NonNullable<Decision['remember']>;
export const DEFAULT_REMEMBER: RememberFields = Object.freeze({
  address: false,
  port: false,
  protocol: false,
  process: false,
});
// "Delete the rule after:" exactly as NetLimiter offers it; 0 = Do not delete.
export const REMEMBER_DURATIONS: readonly { label: string; seconds: number }[] = [
  { label: 'Do not delete', seconds: 0 },
  { label: '1 minute', seconds: 60 },
  { label: '5 minutes', seconds: 300 },
  { label: '10 minutes', seconds: 600 },
  { label: '30 minutes', seconds: 1800 },
  { label: '1 hour', seconds: 3600 },
  { label: '6 hours', seconds: 21600 },
  { label: '12 hours', seconds: 43200 },
];
export interface RememberChoice {
  fields: RememberFields;
  duration: number;
}
export const rememberFieldsSupported = (capabilities?: string[]) =>
  !!capabilities?.includes(REMEMBER_FIELDS_CAPABILITY);
export const rememberScope = (duration: number): 'application' | 'persistent' =>
  duration ? 'application' : 'persistent';
// Reviewed Remember request. No zone choice (NetLimiter has none): network_zone any.
export function rememberDecision(
  base: { generation: string; id: string; action: 'allow' | 'block' },
  choice: RememberChoice,
  zoneRevision: string,
): Decision {
  if (!REMEMBER_DURATIONS.some((d) => d.seconds === choice.duration))
    throw Error('Unsupported rule deletion time');
  const scope = rememberScope(choice.duration);
  return {
    generation: base.generation,
    id: base.id,
    action: base.action,
    scope,
    network_zone: 'any',
    zone_revision: zoneRevision,
    remember: {
      address: choice.fields.address === true,
      port: choice.fields.port === true,
      protocol: choice.fields.protocol === true,
      process: choice.fields.process === true,
    },
    ...(scope === 'application' ? { duration_seconds: choice.duration } : {}),
  };
}
// Any change of a checkbox or deletion time yields a different key; a preview
// reviewed for another key must not be submitted.
export const rememberKey = (choice: RememberChoice) =>
  JSON.stringify([
    choice.fields.address,
    choice.fields.port,
    choice.fields.protocol,
    choice.fields.process,
    choice.duration,
  ]);
export interface RememberOption {
  field: keyof RememberFields | 'application';
  label: string;
  available: boolean;
  reason?: string;
}
// "Create rule for:" rows. Application is fixed (always part of the rule).
export function rememberOptions(e: RequestEvent, applicationName: string): RememberOption[] {
  const incoming = e.flow.direction === 'incoming',
    f = e.remembered_filter,
    owner = e.attribution.owners.length === 1 ? e.attribution.owners[0] : undefined,
    address = f?.remote_address || hostOf(e.flow.remote),
    port = incoming
      ? f?.local_port || portOf(e.flow.local)
      : f?.remote_port || portOf(e.flow.remote);
  return [
    { field: 'application', label: applicationName, available: true },
    { field: 'protocol', label: e.flow.protocol.toUpperCase() || 'Protocol', available: true },
    {
      field: 'process',
      label: owner ? `Process ${owner.pid}` : 'Process',
      available: !!owner && e.attribution.visibility_complete,
      reason:
        owner && e.attribution.visibility_complete
          ? 'Only this process instance; inactive when it exits'
          : 'Needs one verified owning process',
    },
    { field: 'address', label: `Remote address ${address}`, available: !!address },
    {
      field: 'port',
      label: `${incoming ? 'Local port' : 'Remote port'} ${port || ''}`.trim(),
      available: !!port,
    },
  ];
}
function hostOf(endpoint: string) {
  const m = /^\[(.*)\]:\d+$/.exec(endpoint) || /^([^:]*):\d+$/.exec(endpoint);
  return m ? m[1] : endpoint;
}
function portOf(endpoint: string) {
  const m = /:(\d+)$/.exec(endpoint);
  return m ? Number(m[1]) : 0;
}
// A preview refusal is not a submitted decision. Keep it attached to the exact
// generation/event, so polling cannot make the same unverified request actionable.
export interface DecisionReviewFailure {
  code: string;
  message: string;
  terminal: true;
}
export function terminalReviewFailure(code: string, message: string): DecisionReviewFailure | undefined {
  return ['identity_changed', 'stale_decision', 'connection_ended', 'process_exited', 'request_ended'].includes(code)
    ? { code, message, terminal: true }
    : undefined;
}
export function reviewFailureOf(event: RequestEvent | undefined): DecisionReviewFailure | undefined {
  const local = (event as (RequestEvent & { reviewFailure?: DecisionReviewFailure }) | undefined)?.reviewFailure;
  return local ?? (event?.revalidation ? terminalReviewFailure(event.revalidation.code, event.revalidation.reason) : undefined);
}
export function reviewFailureSummary(failure: DecisionReviewFailure) {
  return ['connection_ended', 'request_ended'].includes(failure.code)
    ? 'Connection ended. No decision was submitted.'
    : failure.code === 'process_exited'
      ? 'The requesting process exited. No decision was submitted.'
      : failure.code === 'stale_decision'
        ? 'Request no longer pending. No decision was submitted.'
        : 'This request can no longer be verified. No decision was submitted.';
}
// A new Activity observation is only a candidate for the existing authoritative
// observed-rule preview. No PID, path or displayed application name grants authority.
export function freshApplicationRuleSource(state: ClientState, original: RequestEvent): ObservedSource | undefined {
  const c = state.control, activity = state.observation.activity, app = original.attribution.application;
  const uid = original.remembered_filter?.uid;
  if (!canManageRules(c) || !c.capabilities?.includes('observed-rule-create-v1') ||
      !app?.key || !app.revision || !Number.isSafeInteger(uid) || !activity ||
      !['incoming', 'outgoing'].includes(original.flow.direction)) return;
  for (const socket of activity.rows) {
    if (socket.owners.length !== 1 || socket.ownership_category !== 'visible-holder') continue;
    const process = activity.processes[socket.owners[0]];
    if (!process || process.uid !== uid || process.application.key !== app.key ||
        process.application.revision !== app.revision || process.application.executable !== app.executable) continue;
    const association = authoritativePolicy({ kind: 'socket', socket, process } as Row, state);
    if (!association.application) continue;
    return { generation: c.generation, row_id: socket.id, process_id: process.id,
      direction: original.flow.direction as 'incoming' | 'outgoing', target_scope: 'application' };
  }
}
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
  remember?: RememberFields;
  duration_seconds?: number;
  summary?: string;
  replaces?: { id: string; version: number };
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
  const remember = p.remember === undefined || p.remember === null ? undefined : obj(p.remember),
    replaces = p.replaces === undefined || p.replaces === null ? undefined : obj(p.replaces);
  if (
    (remember &&
      ['address', 'port', 'protocol', 'process'].some((k) => typeof remember[k] !== 'boolean')) ||
    (p.duration_seconds !== undefined &&
      (!Number.isSafeInteger(p.duration_seconds) || Number(p.duration_seconds) < 0)) ||
    (p.summary !== undefined && (typeof p.summary !== 'string' || p.summary.length > 1024)) ||
    (replaces &&
      (typeof replaces.id !== 'string' ||
        !replaces.id ||
        replaces.id.length > 256 ||
        !Number.isSafeInteger(replaces.version) ||
        Number(replaces.version) < 1))
  )
    throw Error('Invalid decision preview');
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
    remember: remember
      ? {
          address: remember.address as boolean,
          port: remember.port as boolean,
          protocol: remember.protocol as boolean,
          process: remember.process as boolean,
        }
      : undefined,
    duration_seconds: p.duration_seconds === undefined ? undefined : Number(p.duration_seconds),
    summary: typeof p.summary === 'string' ? p.summary : undefined,
    replaces: replaces ? { id: String(replaces.id), version: Number(replaces.version) } : undefined,
  };
}
export function agreesWithDecision(p: DecisionPreview, d: Decision, e: RequestEvent, now: number) {
  const app = e.attribution.application,
    f = p.rule.filter,
    rf = e.remembered_filter,
    // Legacy reviewed scope keeps the exact remembered peer/service and one hour.
    keep = d.remember ?? { address: true, port: true, protocol: true, process: false },
    lifetime = d.remember ? (d.duration_seconds ?? 0) : 3600,
    created = Date.parse(p.rule.created),
    expires = Date.parse(p.rule.expires),
    owner = e.attribution.owners.length === 1 ? e.attribution.owners[0] : undefined;
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
    (d.remember &&
      (!p.remember ||
        !p.summary ||
        rememberKey({ fields: p.remember, duration: p.duration_seconds ?? 0 }) !==
          rememberKey({ fields: d.remember, duration: d.duration_seconds ?? 0 }) ||
        (d.remember.process && d.network_zone !== 'any'))) ||
    !app ||
    f.application !== app.key ||
    f.revision !== app.revision ||
    f.direction !== e.flow.direction ||
    f.protocol !== (keep.protocol ? e.flow.protocol : '*') ||
    !rf ||
    f.uid !== rf.uid ||
    f.remote_address !== (keep.address ? rf.remote_address : '*') ||
    (f.remote || '') !== (rf.remote || '') ||
    f.local_port !== (keep.port ? rf.local_port : 0) ||
    f.remote_port !== (keep.port ? rf.remote_port : 0) ||
    (d.scope === 'persistent'
      ? !p.rule.expires.startsWith('0001-')
      : !Number.isFinite(expires) ||
        expires <= now ||
        expires > now + lifetime * 1000 + 5000 ||
        (!p.replaces && Math.abs(expires - created - lifetime * 1000) > 1000)) ||
    p.rule.action !== d.action ||
    (p.replaces
      ? p.rule.id !== p.replaces.id || p.rule.version !== p.replaces.version + 1
      : p.rule.version !== 1) ||
    p.rule.disabled ||
    !p.rule.id ||
    (e.attribution.owners.length > 0 &&
      e.attribution.owners.some((owner) => owner.uid !== f.uid)) ||
    (keep.process ? !f.process || !owner || f.process.pid !== owner.pid : !!f.process) ||
    f.all_programs ||
    f.all_uids ||
    (f.network_zone || 'any') !== d.network_zone ||
    (d.preview_token && p.token !== d.preview_token)
  )
    throw Error('Preview does not match the displayed decision scope');
  return p;
}
// Text shown before a Remember is submitted: the backend's compact summary
// (without the action word: Allow and Deny share the scope) and, when the
// preview updates a rule in place, which one (Ask rule -> Allow/Deny).
export function rememberReviewText(
  allow?: DecisionPreview,
  block?: DecisionPreview,
  askRule?: { id: string; version: number },
) {
  if (!allow || !block) return '';
  const scope = (allow.summary || allow.scope_preview).replace(/^Allow /, ''),
    r = allow.replaces;
  const note = !r
    ? ''
    : askRule && askRule.id === r.id
      ? ` · replaces Ask rule ${r.id} (Ask → Allow/Deny)`
      : ` · updates existing rule ${r.id}`;
  return `Rule: ${scope}${note}`;
}
export const sameRememberedRule = (a: Rule, b: Rule) => JSON.stringify(a) === JSON.stringify(b);
