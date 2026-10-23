import { REMEMBER_DURATIONS, rememberScope, reviewFailureOf, type RememberFields } from './decision-remember';
import { parseRule, type RequestEvent, type Rule } from './protocol';

// request-application-rule-v1: save an application rule for FUTURE connections
// from a retained, ended request. The backend uses the identity it captured from
// the verified requester and validates the executable itself; the ended request
// is never decided or released.
export const REQUEST_RULE_CAPABILITY = 'request-application-rule-v1';
export type RuleAction = 'allow' | 'block' | 'ask';
export interface RequestRuleChoice {
  generation: string;
  id: string;
  action: RuleAction;
  scope: 'application' | 'persistent';
  network_zone: 'any';
  zone_revision: string;
  remember: RememberFields;
  duration_seconds?: number;
  preview_token?: string;
}
export interface RequestRulePreview {
  token: string;
  expires_at: string;
  event_id: string;
  action: RuleAction;
  scope_preview: string;
  summary: string;
  rule: Rule;
  replaces: { id: string; version: number } | null;
}
export function requestRuleChoice(
  base: { generation: string; id: string; action: RuleAction },
  fields: RememberFields,
  duration: number,
  zoneRevision: string,
): RequestRuleChoice {
  if (!REMEMBER_DURATIONS.some((d) => d.seconds === duration)) throw Error('Unsupported rule expiry duration');
  const scope = rememberScope(duration);
  return {
    generation: base.generation,
    id: base.id,
    action: base.action,
    scope,
    network_zone: 'any',
    zone_revision: zoneRevision,
    remember: {
      address: fields.address === true,
      port: fields.port === true,
      protocol: fields.protocol === true,
      process: fields.process === true,
    },
    ...(scope === 'application' ? { duration_seconds: duration } : {}),
  };
}
const KEYS = ['generation', 'id', 'action', 'scope', 'network_zone', 'zone_revision', 'remember', 'duration_seconds', 'preview_token'];
const str = (v: unknown, max = 256) => typeof v === 'string' && v.length > 0 && v.length <= max;
export function validateRequestRule(v: unknown, save = false): RequestRuleChoice {
  const d = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>,
    r = (d.remember && typeof d.remember === 'object' ? d.remember : undefined) as Record<string, unknown> | undefined;
  if (
    Object.keys(d).some((k) => !KEYS.includes(k)) ||
    !str(d.generation) || !str(d.id, 64) ||
    !['allow', 'block', 'ask'].includes(d.action as string) ||
    !['application', 'persistent'].includes(d.scope as string) ||
    d.network_zone !== 'any' || typeof d.zone_revision !== 'string' || d.zone_revision.length > 256 ||
    !r || Object.keys(r).sort().join(',') !== 'address,port,process,protocol' ||
    Object.values(r).some((x) => typeof x !== 'boolean') ||
    (d.scope === 'application'
      ? !REMEMBER_DURATIONS.some((x) => x.seconds > 0 && x.seconds === d.duration_seconds)
      : d.duration_seconds !== undefined) ||
    (save ? !str(d.preview_token, 128) : d.preview_token !== undefined)
  )
    throw Error('Invalid application-rule request');
  return d as unknown as RequestRuleChoice;
}
export function parseRequestRulePreview(raw: unknown, choice: RequestRuleChoice): RequestRulePreview {
  const p = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  for (const k of ['token', 'expires_at', 'event_id', 'scope_preview', 'summary'])
    if (typeof p[k] !== 'string' || !(p[k] as string)) throw Error('Invalid application-rule preview');
  const rule = parseRule(p.rule);
  const replaces = p.replaces && typeof p.replaces === 'object' ? (p.replaces as { id: string; version: number }) : null;
  if (p.event_id !== choice.id || p.action !== choice.action || rule.action !== choice.action ||
      !!rule.filter.process || (!choice.remember.protocol && rule.filter.protocol !== '*') ||
      (!choice.remember.address && rule.filter.remote_address !== '*') ||
      (!choice.remember.port && (rule.filter.local_port || rule.filter.remote_port)))
    throw Error('Application-rule preview does not match the selected scope');
  return { token: p.token as string, expires_at: p.expires_at as string, event_id: p.event_id as string, action: choice.action,
    scope_preview: p.scope_preview as string, summary: p.summary as string, rule, replaces };
}
// An ended request whose verified identity the backend still retains.
export function requestRuleAvailable(e: RequestEvent | undefined, capabilities?: string[]) {
  return !!e && !!reviewFailureOf(e) && !!e.request_rule?.available && !!capabilities?.includes(REQUEST_RULE_CAPABILITY);
}
export function processInstanceEnded(e: RequestEvent | undefined) {
  return e?.request_rule?.process_state === 'ended';
}
export const requestRuleKey = (c: RequestRuleChoice) =>
  JSON.stringify([c.generation, c.id, c.action, c.scope, c.zone_revision, c.remember, c.duration_seconds ?? 0]);
// request-sandbox-identity-v1: a sandboxed (other mount namespace) process
// exited and its executable has no host-visible backing file, so no reusable
// identity exists. Permanent for that request: shown once, never re-reviewed.
export const IDENTITY_UNVERIFIABLE_CODE = 'identity_unverifiable';
export const IDENTITY_UNVERIFIABLE_TEXT =
  'No rule can be saved from this ended request: the sandboxed program exited and FlowGate can no longer verify its file. Choose Remember while its next request is still open.';
export const identityUnverifiable = (message: string) =>
  message.startsWith(IDENTITY_UNVERIFIABLE_CODE + ': ') || message.includes('Backend rejected: ' + IDENTITY_UNVERIFIABLE_CODE + ': ');
