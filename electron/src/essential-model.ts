import { parseRule, type Rule } from './protocol';
export const ESSENTIAL_CAPABILITY = 'essential-system-networking-v1';
export interface EssentialOptions {
  tailscale: boolean;
  tailscale_incoming: boolean;
  tailscale_http: boolean;
  discovery: boolean;
}
export const essentialDefaults = (): EssentialOptions => ({
  tailscale: false,
  tailscale_incoming: false,
  tailscale_http: false,
  discovery: false,
});
export interface EssentialComponent {
  id: string;
  title: string;
  state: 'ready' | 'unavailable' | 'optional';
  essential: boolean;
  details: string[];
  revision: string;
  service?: unknown;
}
export interface EssentialStatus {
  revision: string;
  components: EssentialComponent[];
  rule_ids: string[];
  issues: string[];
}
export interface EssentialPreview extends EssentialStatus {
  token: string;
  expires_at: string;
  operation: 'apply' | 'remove';
  options: EssentialOptions;
  rules: Rule[];
  preserved_rule_ids: string[];
}
export interface EssentialReceipt {
  token: string;
  operation: 'apply' | 'remove';
  rule_ids: string[];
  rules: Rule[];
  removed_rule_ids: string[];
}
export interface EssentialView {
  monitoring: boolean;
  supported: boolean;
  connected: boolean;
  permitted: boolean;
  canStatus: boolean;
  generation: string;
  busy: boolean;
  phase: 'idle' | 'review' | 'confirmed' | 'unknown' | 'error';
  message: string;
  status?: EssentialStatus;
  preview?: EssentialPreview;
  receipt?: EssentialReceipt;
  canApply: boolean;
  canReconcile: boolean;
}
const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Invalid Essential response');
  return v as Record<string, unknown>;
};
const text = (v: unknown, max = 8192) => {
  if (typeof v !== 'string' || v.length > max) throw Error('Invalid Essential text');
  return v;
};
const list = <T>(v: unknown, fn: (x: unknown) => T, max = 512) => {
  if (!Array.isArray(v) || v.length > max) throw Error('Invalid Essential list');
  return v.map(fn);
};
const strings = (v: unknown) => list(v, (x) => text(x));
export function essentialOptions(v: unknown): EssentialOptions {
  const o = object(v);
  const keys = Object.keys(essentialDefaults());
  if (
    Object.keys(o).sort().join() !== keys.sort().join() ||
    keys.some((k) => typeof o[k] !== 'boolean')
  )
    throw Error('Invalid Essential options');
  return Object.fromEntries(keys.map((k) => [k, o[k]])) as unknown as EssentialOptions;
}
function components(v: unknown) {
  return list(v, (x) => {
    const c = object(x);
    if (
      !['ready', 'unavailable', 'optional'].includes(String(c.state)) ||
      typeof c.essential !== 'boolean'
    )
      throw Error('Invalid Essential component');
    return {
      id: text(c.id),
      title: text(c.title),
      state: c.state as EssentialComponent['state'],
      essential: c.essential,
      details: strings(c.details),
      revision: text(c.revision),
      ...(c.service ? { service: c.service } : {}),
    };
  });
}
export function essentialStatus(v: unknown): EssentialStatus {
  const s = object(v);
  return {
    revision: text(s.revision),
    components: components(s.components),
    rule_ids: strings(s.rule_ids),
    issues: strings(s.issues),
  };
}
function operation(v: unknown) {
  if (v !== 'apply' && v !== 'remove') throw Error('Invalid Essential operation');
  return v;
}
export function essentialPreview(v: unknown): EssentialPreview {
  const p = object(v);
  if (!Number.isFinite(Date.parse(text(p.expires_at)))) throw Error('Invalid Essential expiry');
  const rules = list(p.rules, parseRule);
  if (
    rules.some((r) => r.schema !== 5 || r.preset?.name !== 'essential-system-networking') ||
    new Set(rules.map((r) => r.id)).size !== rules.length
  )
    throw Error('Invalid Essential rule ownership');
  return {
    ...essentialStatus({ ...p, rule_ids: rules.map((r) => r.id) }),
    token: text(p.token, 256),
    expires_at: text(p.expires_at),
    operation: operation(p.operation),
    options: essentialOptions(p.options),
    rules,
    preserved_rule_ids: strings(p.preserved_rule_ids),
  };
}
export function essentialReceipt(v: unknown): EssentialReceipt {
  const r = object(v);
  return {
    token: text(r.token, 256),
    operation: operation(r.operation),
    rule_ids: strings(r.rule_ids),
    rules: list(r.rules, parseRule),
    removed_rule_ids: strings(r.removed_rule_ids),
  };
}
export const sameEssentialOptions = (a: EssentialOptions, b: EssentialOptions) =>
  Object.keys(essentialDefaults()).every(
    (k) => a[k as keyof EssentialOptions] === b[k as keyof EssentialOptions],
  );
export function agreesWithEssential(p: EssentialPreview, r: EssentialReceipt) {
  const sameIds = (a: string[], b: string[]) =>
    JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  return (
    r.token === p.token &&
    r.operation === p.operation &&
    (p.operation === 'apply'
      ? sameIds(
          r.rule_ids,
          p.rules.map((r) => r.id),
        ) &&
        r.removed_rule_ids.length === 0 &&
        JSON.stringify([...r.rules].sort((a, b) => a.id.localeCompare(b.id))) ===
          JSON.stringify([...p.rules].sort((a, b) => a.id.localeCompare(b.id)))
      : sameIds(
          r.removed_rule_ids,
          p.rules.map((r) => r.id),
        ) &&
        r.rule_ids.length === 0 &&
        r.rules.length === 0)
  );
}
export function essentialRuleLabel(r: Rule) {
  const f = r.filter;
  const target = f.peer_service
    ? `All programs${f.all_uids ? ' · all users' : ''} → local service ${f.peer_service.application} · UID ${f.peer_service.uid}`
    : f.all_programs
      ? `All programs${f.all_uids ? ' · all users' : ''}`
      : `${r.executable || f.application} · UID ${f.uid}`;
  return `${r.preset?.component === 'dhcp' ? 'DHCP durable interface protocol exception' : r.preset?.component || 'Essential'} · ${r.action === 'allow' ? 'Allow' : 'Deny'} ${f.direction} ${f.protocol.toUpperCase()} · ${target} · local ${f.local_address || '*'}:${f.local_port || '*'} → ${f.remote_address || '*'}:${f.remote_port || '*'}${f.interface_name || f.interface_index ? ` · interface ${f.interface_name || 'index'} (${f.interface_index || 'Any index'})` : ''}${!f.remote_address || f.remote_address === '*' ? ' · Any destination' : ''} · ${r.expires.startsWith('0001-') ? 'No expiry' : `Expires ${r.expires}`}`;
}
