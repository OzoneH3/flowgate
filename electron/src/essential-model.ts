import { accountLabel } from './accounts';
import { parseRule, type Rule } from './protocol';
export const ESSENTIAL_ASSISTANCE_CAPABILITY = 'essential-optional-services-v1';
export const ESSENTIAL_CAPABILITY = 'essential-system-networking-v1';
// Daemons without this capability silently ignore excluded_interfaces, so the
// field is never sent to them and a reviewed exclusion blocks Apply there.
export const ESSENTIAL_EXCLUSION_CAPABILITY = 'essential-interface-exclusion-v1';
export const MAX_EXCLUDED_INTERFACES = 16;
export interface EssentialOptions {
  service_assistance: boolean;
  discovery: boolean;
  // Canonical: sorted, de-duplicated, validated; empty = none (omitted on the wire).
  excluded_interfaces: string[];
}
export type EssentialToggle = Exclude<keyof EssentialOptions, 'excluded_interfaces'>;
export const ESSENTIAL_TOGGLES: EssentialToggle[] = [
  'service_assistance',
  'discovery',
];
export const essentialDefaults = (): EssentialOptions => ({
  service_assistance: false,
  discovery: false,
  excluded_interfaces: [],
});
// Mirrors the daemon's interface-name rule (1..15 printable ASCII, no
// whitespace, '/', ':' or '.'/'..'); loopback stub scopes cannot be excluded.
export function validExcludedInterface(n: unknown): n is string {
  return (
    typeof n === 'string' &&
    n.length >= 1 &&
    n.length <= 15 &&
    n !== '.' &&
    n !== '..' &&
    n !== 'lo' &&
    /^[!-~]+$/.test(n) &&
    !/[/:]/.test(n)
  );
}
export function canonicalExclusions(v: unknown): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.length > 64) throw Error('Invalid excluded interfaces');
  for (const n of v)
    if (!validExcludedInterface(n)) throw Error(`Invalid excluded interface ${JSON.stringify(n)}`);
  const out = [...new Set(v as string[])].sort();
  if (out.length > MAX_EXCLUDED_INTERFACES) throw Error('Too many excluded interfaces');
  return out;
}
// Request body: exclusions are sent only when present and the daemon honours them.
export function essentialWireOptions(o: EssentialOptions, exclusionSupported: boolean, assistanceSupported = false) {
  const { excluded_interfaces, service_assistance, ...legacy } = o;
  if (service_assistance && !assistanceSupported) throw Error('Optional DNS/time assistance requires a matching backend. Nothing was sent.');
  const rest = assistanceSupported ? { ...legacy, service_assistance } : legacy;
  if (!excluded_interfaces.length) return rest;
  if (!exclusionSupported)
    throw Error(
      'This daemon cannot honour interface exclusions (essential-interface-exclusion-v1 missing). Nothing was sent.',
    );
  return { ...rest, excluded_interfaces: [...excluded_interfaces] };
}
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
  options?: EssentialOptions;
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
  // Daemon honours essential_options.excluded_interfaces.
  exclusionSupported: boolean;
  assistanceSupported: boolean;
  // Persisted reviewed exclusion set (preselected in the view).
  reviewedExclusions: string[];
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
  const raw = object(v);
  const o: Record<string, unknown> = { service_assistance: false, ...raw };
  // Accept only disabled retired fields from older daemon responses.
  for (const key of ['tailscale', 'tailscale_incoming', 'tailscale_http']) {
    if (key in o && o[key] !== false) throw Error('Vendor transport presets are no longer supported');
    delete o[key];
  }
  const keys = Object.keys(o).filter((k) => k !== 'excluded_interfaces');
  if (
    keys.sort().join() !== [...ESSENTIAL_TOGGLES].sort().join() ||
    ESSENTIAL_TOGGLES.some((k) => typeof o[k] !== 'boolean')
  )
    throw Error('Invalid Essential options');
  return {
    ...(Object.fromEntries(ESSENTIAL_TOGGLES.map((k) => [k, o[k]])) as Record<
      EssentialToggle,
      boolean
    >),
    excluded_interfaces: canonicalExclusions(o.excluded_interfaces ?? undefined),
  };
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
    ...(r.options !== undefined ? { options: essentialOptions(r.options) } : {}),
  };
}
export const sameEssentialOptions = (a: EssentialOptions, b: EssentialOptions) =>
  ESSENTIAL_TOGGLES.every((k) => a[k] === b[k]) &&
  JSON.stringify(a.excluded_interfaces) === JSON.stringify(b.excluded_interfaces);
export interface ExclusionCandidate {
  name: string;
  detail: string;
}
const EXCLUDED_ISSUE =
    /^Excluded by review, not proposed: (\S+) \((.*)\); its configuration is unchanged$/,
  EXCLUDED_EMPTY = /^Excluded interface (\S+) has no discovered DNS\/DHCP entries now/;
// Interfaces that carry discovered upstream DNS/DHCP, derived only from the
// backend review (preset DNS/DHCP rule interface scopes and exclusion issues),
// plus persisted/selected names so excluded interfaces stay visible.
export function exclusionCandidates(
  source: { rules?: Rule[]; issues: string[] } | undefined,
  keep: string[] = [],
): ExclusionCandidate[] {
  const found = new Map<string, Set<string>>();
  const add = (name: string, what?: string) => {
    if (!validExcludedInterface(name)) return;
    const set = found.get(name) || new Set<string>();
    if (what) set.add(what);
    found.set(name, set);
  };
  for (const r of source?.rules || []) {
    const f = r.filter,
      c = r.preset?.component;
    if (f.direction !== 'outgoing' || !f.interface_name) continue;
    if (c === 'dns') add(f.interface_name, `DNS ${f.remote_address}:${f.remote_port}`);
    else if (c === 'dhcp') add(f.interface_name, 'DHCP');
  }
  for (const issue of source?.issues || []) {
    const m = EXCLUDED_ISSUE.exec(issue);
    if (m) for (const what of m[2].split(', ')) add(m[1], what);
    const e = EXCLUDED_EMPTY.exec(issue);
    if (e) add(e[1], 'no DNS/DHCP discovered now');
  }
  for (const name of keep) add(name);
  return [...found]
    .map(([name, what]) => ({ name, detail: [...what].join(', ') }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
export const exclusionSummary = (x: string[]) => `Excluded: ${x.length ? x.join(', ') : 'none'}`;
export function agreesWithEssential(p: EssentialPreview, r: EssentialReceipt) {
  const sameIds = (a: string[], b: string[]) =>
    JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  return (
    r.token === p.token &&
    r.operation === p.operation &&
    (!r.options || sameEssentialOptions(r.options, p.options)) &&
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
    ? `All programs${f.all_uids ? ' · all users' : ''} → local service ${f.peer_service.application} · ${accountLabel(f.peer_service.uid)}`
    : f.all_programs
      ? `All programs${f.all_uids ? ' · all users' : ''}`
      : `${r.executable || f.application} · ${accountLabel(f.uid)}`;
  return `${r.preset?.component === 'dhcp' ? 'DHCP durable interface protocol exception' : r.preset?.component || 'Essential'} · ${r.action === 'allow' ? 'Allow' : 'Deny'} ${f.direction} ${f.protocol.toUpperCase()} · ${target} · local ${f.local_address || '*'}:${f.local_port || '*'} → ${f.remote_address || '*'}:${f.remote_port || '*'}${f.interface_name || f.interface_index ? ` · interface ${f.interface_name || 'index'} (${f.interface_index || 'Any index'})` : ''}${!f.remote_address || f.remote_address === '*' ? ' · Any destination' : ''} · ${r.expires.startsWith('0001-') ? 'No expiry' : `Expires ${r.expires}`}`;
}
