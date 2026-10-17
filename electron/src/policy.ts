import type { ClientState, RuleFilter } from './protocol';
import type { Row } from './model';
export const POLICY_CAPABILITY = 'policy-explanations-v1';
export interface PolicyRuleRef {
  id: string;
  version: string;
  action: string;
  priority: number;
  scope: RuleFilter;
  disabled: boolean;
  expired: boolean;
  active: boolean;
  expires: string;
}
export interface PolicyDefault {
  known: boolean;
  action: string;
  reason: string;
}
export interface DirectionPolicy {
  direction: string;
  configured: string;
  action: string;
  reason: string;
  rules: PolicyRuleRef[];
  active_rules: number;
  disabled_rules: number;
  expired_rules: number;
  potential_overlapping_actions: boolean;
  configured_default: PolicyDefault;
  runtime_default: PolicyDefault;
  enforcement: { state: string; covered: boolean; reason: string };
}
export interface ApplicationPolicy {
  ref: string;
  identity: { key: string; revision: string; uid: number };
  process_ids: string[];
  incoming: DirectionPolicy;
  outgoing: DirectionPolicy;
}
export interface PolicyView {
  snapshot: {
    generation: string;
    token: string;
    sequence: string;
    evaluated_at: string;
    valid_until?: string;
    meaning: string;
  };
  activity_sequence: string;
  activity_collected: string;
  activity_available: boolean;
  complete: boolean;
  reason: string;
  applications: ApplicationPolicy[];
  rows: {
    row_id: string;
    status: string;
    reason: string;
    application_ref: string;
    decision_authority: boolean;
  }[];
}
const obj = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw Error('Invalid policy object');
  return v as Record<string, unknown>;
};
const str = (v: unknown, optional = false): string => {
  if (v === undefined && optional) return '';
  if (typeof v !== 'string' || v.length > 16384) throw Error('Invalid policy text');
  return v;
};
const bool = (v: unknown) => {
  if (typeof v !== 'boolean') throw Error('Invalid policy flag');
  return v;
};
const num = (v: unknown, max = 0xffffffff) => {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0 || v > max)
    throw Error('Invalid policy number');
  return v;
};
const list = (v: unknown, max: number): unknown[] => {
  if (!Array.isArray(v) || v.length > max) throw Error('Invalid policy batch');
  return v;
};
export const decimal = (v: unknown) => {
  const s = str(v);
  if (!/^(0|[1-9][0-9]{0,19})$/.test(s) || BigInt(s) > 18446744073709551615n)
    throw Error('Invalid exact policy integer');
  return s;
};
const date = (v: unknown) => {
  const s = str(v);
  if (!Number.isFinite(Date.parse(s))) throw Error('Invalid policy time');
  return s;
};
const def = (v: unknown): PolicyDefault => {
  const d = obj(v);
  const known = bool(d.known),
    action = str(d.action, true);
  if (known && !['allow', 'block', 'ask'].includes(action)) throw Error('Invalid known default');
  return { known, action, reason: str(d.reason) };
};
function direction(v: unknown, expected: string): DirectionPolicy {
  const d = obj(v),
    e = obj(d.enforcement);
  if (
    d.direction !== expected ||
    !['absent', 'inactive_only', 'scoped', 'mixed', 'uniform'].includes(str(d.configured))
  )
    throw Error('Invalid directional policy');
  if (d.configured === 'uniform' && !['allow', 'block'].includes(str(d.action)))
    throw Error('Invalid uniform action');
  return {
    direction: expected,
    configured: str(d.configured),
    action: str(d.action, true),
    reason: str(d.reason),
    active_rules: num(d.active_rules),
    disabled_rules: num(d.disabled_rules),
    expired_rules: num(d.expired_rules),
    potential_overlapping_actions: bool(d.potential_overlapping_actions),
    configured_default: def(d.configured_default),
    runtime_default: def(d.runtime_default),
    enforcement: { state: str(e.state), covered: bool(e.covered), reason: str(e.reason) },
    rules: list(d.rules, 8192).map((v) => {
      const r = obj(v),
        f = obj(r.scope);
      if (typeof r.priority !== 'number' || !Number.isSafeInteger(r.priority))
        throw Error('Invalid priority');
      return {
        id: str(r.id),
        version: decimal(r.version),
        action: str(r.action),
        priority: r.priority,
        disabled: bool(r.disabled),
        expired: bool(r.expired),
        active: bool(r.active),
        expires: date(r.expires),
        scope: {
          application: str(f.application),
          revision: str(f.revision),
          uid: num(f.uid),
          direction: str(f.direction),
          protocol: str(f.protocol),
          remote: str(f.remote, true),
          remote_address: str(f.remote_address, true),
          local_port: f.local_port === undefined ? 0 : num(f.local_port, 65535),
          remote_port: f.remote_port === undefined ? 0 : num(f.remote_port, 65535),
        },
      };
    }),
  };
}
export function parsePolicyView(raw: unknown): PolicyView {
  const v = obj(raw),
    s = obj(v.snapshot);
  const view: PolicyView = {
    snapshot: {
      generation: str(s.generation),
      token: str(s.token),
      sequence: decimal(s.sequence),
      evaluated_at: date(s.evaluated_at),
      valid_until: s.valid_until ? date(s.valid_until) : undefined,
      meaning: str(s.meaning),
    },
    activity_sequence: decimal(v.activity_sequence),
    activity_collected: date(v.activity_collected),
    activity_available: bool(v.activity_available),
    complete: bool(v.complete),
    reason: str(v.reason, true),
    applications: list(v.applications, 256).map((v) => {
      const a = obj(v),
        i = obj(a.identity);
      return {
        ref: str(a.ref),
        identity: { key: str(i.key), revision: str(i.revision), uid: num(i.uid) },
        process_ids: list(a.process_ids, 2048).map((v) => str(v)),
        incoming: direction(a.incoming, 'incoming'),
        outgoing: direction(a.outgoing, 'outgoing'),
      };
    }),
    rows: list(v.rows, 2048).map((v) => {
      const r = obj(v);
      return {
        row_id: str(r.row_id),
        status: str(r.status),
        reason: str(r.reason),
        application_ref: str(r.application_ref, true),
        decision_authority: bool(r.decision_authority),
      };
    }),
  };
  if (
    !view.snapshot.generation ||
    !view.snapshot.token ||
    new Set(view.applications.map((a) => a.ref)).size !== view.applications.length ||
    new Set(view.rows.map((r) => r.row_id)).size !== view.rows.length
  )
    throw Error('Invalid policy identities');
  return view;
}
export function authoritativePolicy(
  row: Row,
  state: ClientState,
): { application?: ApplicationPolicy; reason: string } {
  const c = state.control,
    v = c.policy;
  if (
    !c.connected ||
    !v ||
    v.snapshot.generation !== c.generation ||
    state.observation.generation !== c.generation ||
    !state.observation.connected
  )
    return {
      reason:
        c.policyError ||
        'Authoritative policy unavailable; connect Activity and policy to the same daemon.',
    };
  if (
    (v.snapshot.valid_until && Date.parse(v.snapshot.valid_until) <= (c.serverNow ?? Infinity)) ||
    !v.activity_available
  )
    return { reason: v.reason || 'Policy expired or observation unavailable; refreshing.' };
  const activity = state.observation.activity;
  if (
    !activity ||
    !Number.isSafeInteger(activity.sequence) ||
    BigInt(v.activity_sequence) > BigInt(activity.sequence) ||
    Date.parse(v.activity_collected) > Date.parse(activity.collected)
  )
    return { reason: 'Policy association awaits its Activity snapshot; no identity is rebound.' };
  if ((c.serverNow ?? Infinity) - Date.parse(v.activity_collected) > 45000)
    return { reason: 'Policy observation association is stale; refreshing.' };
  if (row.displayApplication || row.socket?.display_application)
    return { reason: 'Shared/display-only identity is not a policy target.' };
  const p =
    row.process ||
    (row.socket?.owners.length === 1
      ? state.observation.activity?.processes[row.socket.owners[0]]
      : undefined);
  if (!p) return { reason: 'No supported single-process application identity.' };
  const a = v.applications.find(
    (a) =>
      a.identity.key === p.application.key &&
      a.identity.revision === p.application.revision &&
      a.identity.uid === p.uid &&
      a.process_ids.includes(p.id),
  );
  if (row.socket) {
    const association = v.rows.find((r) => r.row_id === row.socket!.id);
    if (
      !association ||
      association.status !== 'observed_native' ||
      association.application_ref !== a?.ref
    )
      return {
        reason: association?.reason || 'Socket not associated in the current policy batch.',
      };
  }
  return a
    ? { application: a, reason: v.snapshot.meaning }
    : { reason: v.reason || 'Application not supported or outside this bounded policy batch.' };
}
export function policyLabel(d: DirectionPolicy) {
  return d.configured === 'uniform'
    ? `${d.action === 'block' ? 'Block' : d.action === 'allow' ? 'Allow' : d.action} · app-wide`
    : d.configured === 'absent'
      ? 'No rule'
      : d.configured === 'inactive_only'
        ? 'Disabled / expired'
        : d.configured === 'mixed'
          ? `Mixed · ${d.rules.length}`
          : `Scoped · ${d.rules.length}`;
}
export function policyRuleDescription(r: PolicyRuleRef) {
  const f = r.scope;
  return `${r.expired ? 'Expired' : r.disabled ? 'Disabled' : r.active ? 'Enabled' : 'Inactive'} ${r.action} · ${f.direction} ${f.protocol} · remote ${f.remote_address || f.remote || 'any'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'} · expires ${r.expires.startsWith('0001-') ? 'never' : r.expires} · ${r.id} v${r.version}`;
}
