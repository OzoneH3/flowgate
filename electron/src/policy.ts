import { parseNetworkZones, type NetworkZones, type NetworkZone } from './network-zones';
import { parseProcessTarget, type ProcessTarget } from './process-rules';
import type { ClientState, RuleFilter } from './protocol';
import type { Row } from './model';
export const POLICY_CAPABILITY = 'policy-explanations-v1';
// Application/process quick setter sets the ONE canonical whole-target rule (create or update in
// place); never a scoped rule. Without it the direction summary carries no application_rule.
export const APPLICATION_POLICY_CAPABILITY = 'application-policy-v1';
export interface PolicyRuleRef {
  root_application?: string;
  id: string;
  version: string;
  action: string;
  priority: number;
  scope: RuleFilter;
  disabled: boolean;
  expired: boolean;
  active: boolean;
  expires: string;
  target_scope?: 'application' | 'process' | 'zone';
  target_state?: string;
  target_reason?: string;
  // application = whole target, all zones; zone = whole target, one zone; scoped = restricted.
  kind?: 'application' | 'zone' | 'scoped';
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
  // The node's OWN canonical rule (null = none); undefined = daemon without application-policy-v1.
  application_rule?: PolicyRuleRef | null;
  scoped_rules?: number;
}
export interface ApplicationPolicy {
  zone_fallback_rule_ids?: string[];
  ref: string;
  identity: { key: string; revision: string; uid: number };
  process_ids: string[];
  incoming: DirectionPolicy;
  outgoing: DirectionPolicy;
}
export interface ProcessPolicy {
  zone_fallback_rule_ids?: string[];
  ref: string;
  process_id: string;
  application_ref: string;
  target: ProcessTarget;
  state: string;
  reason: string;
  precedence: string;
  incoming: DirectionPolicy;
  outgoing: DirectionPolicy;
  application_incoming: DirectionPolicy;
  application_outgoing: DirectionPolicy;
}
export interface PolicyView {
  network_zones?: NetworkZones;
  zones?: { zone: NetworkZone; incoming: DirectionPolicy; outgoing: DirectionPolicy }[];
  processes?: ProcessPolicy[];
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
function ruleRef(v: unknown): PolicyRuleRef {
  const r = obj(v),
    f = obj(r.scope);
  if (typeof r.priority !== 'number' || !Number.isSafeInteger(r.priority))
    throw Error('Invalid priority');
  return {
    target_scope:
      r.target_scope === undefined
        ? undefined
        : r.target_scope === 'process'
          ? 'process'
          : r.target_scope === 'zone'
            ? 'zone'
            : r.target_scope === 'application'
              ? 'application'
              : (() => {
                  throw Error('Invalid target scope');
                })(),
    root_application: str(r.root_application, true) || undefined,
    target_state: str(r.target_state, true),
    target_reason: str(r.target_reason, true),
    kind:
      r.kind === undefined || r.kind === ''
        ? undefined
        : ['application', 'zone'].includes(str(r.kind))
          ? (r.kind as PolicyRuleRef['kind'])
          : 'scoped', // unknown kinds are never presented as the node's own rule
    id: str(r.id),
    version: decimal(r.version),
    action: str(r.action),
    priority: r.priority,
    disabled: bool(r.disabled),
    expired: bool(r.expired),
    active: bool(r.active),
    expires: date(r.expires),
    scope: {
      zone_model: f.zone_model === 'automatic-peer-v1' ? 'automatic-peer-v1' : undefined,
      network_zone: ['local', 'internet'].includes(String(f.network_zone))
        ? (f.network_zone as NetworkZone)
        : undefined,
      all_programs: f.all_programs === true || undefined,
      all_uids: f.all_uids === true || undefined,
      process: parseProcessTarget(f.process),
      application: str(f.application, true),
      revision: str(f.revision, true),
      uid: f.uid === undefined && f.all_programs === true ? 0 : num(f.uid),
      direction: str(f.direction),
      protocol: str(f.protocol),
      remote: str(f.remote, true),
      remote_address: str(f.remote_address, true),
      local_port: f.local_port === undefined ? 0 : num(f.local_port, 65535),
      remote_port: f.remote_port === undefined ? 0 : num(f.remote_port, 65535),
    },
  };
}
// Never accept a non-canonical ref as the node's own rule.
const ownRef = (r: PolicyRuleRef, expected: string) => {
  if ((r.kind && r.kind !== 'application') || r.scope.direction !== expected)
    throw Error('Invalid application rule');
  return r;
};
function direction(v: unknown, expected: string): DirectionPolicy {
  const d = obj(v),
    e = obj(d.enforcement);
  if (
    d.direction !== expected ||
    !['absent', 'inactive_only', 'scoped', 'mixed', 'uniform'].includes(str(d.configured))
  )
    throw Error('Invalid directional policy');
  if (d.configured === 'uniform' && !['allow', 'block', 'ask'].includes(str(d.action)))
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
    rules: list(d.rules, 8192).map((v) => ruleRef(v)),
    application_rule:
      d.application_rule === undefined
        ? undefined
        : d.application_rule === null
          ? null
          : ownRef(ruleRef(d.application_rule), expected),
    scoped_rules: d.scoped_rules === undefined ? undefined : num(d.scoped_rules),
  };
}
export function parsePolicyView(raw: unknown): PolicyView {
  const v = obj(raw),
    s = obj(v.snapshot);
  const view: PolicyView = {
    network_zones: parseNetworkZones(v.network_zones),
    zones:
      v.zones === undefined
        ? undefined
        : list(v.zones, 2).map((value) => {
            const z = obj(value);
            if (!['local', 'internet'].includes(str(z.zone))) throw Error('Invalid policy zone');
            return {
              zone: z.zone as NetworkZone,
              incoming: direction(z.incoming, 'incoming'),
              outgoing: direction(z.outgoing, 'outgoing'),
            };
          }),
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
    processes:
      v.processes === undefined
        ? undefined
        : list(v.processes, 2048).map((value) => {
            const p = obj(value),
              target = parseProcessTarget(p.target, true);
            if (!target || !['active', 'inactive'].includes(str(p.state)))
              throw Error('Invalid process policy');
            return {
              zone_fallback_rule_ids:
                p.zone_fallback_rule_ids === undefined
                  ? undefined
                  : list(p.zone_fallback_rule_ids, 8192).map((v) => str(v)),
              ref: str(p.ref),
              process_id: str(p.process_id),
              application_ref: str(p.application_ref, true),
              target,
              state: str(p.state),
              reason: str(p.reason),
              precedence: str(p.precedence),
              incoming: direction(p.incoming, 'incoming'),
              outgoing: direction(p.outgoing, 'outgoing'),
              application_incoming: direction(p.application_incoming, 'incoming'),
              application_outgoing: direction(p.application_outgoing, 'outgoing'),
            };
          }),
    applications: list(v.applications, 256).map((v) => {
      const a = obj(v),
        i = obj(a.identity);
      return {
        zone_fallback_rule_ids:
          a.zone_fallback_rule_ids === undefined
            ? undefined
            : list(a.zone_fallback_rule_ids, 8192).map((v) => str(v)),
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
const policyIndexes = new WeakMap<
  PolicyView,
  {
    apps: Map<string, ApplicationPolicy[]>;
    rows: Map<string, PolicyView['rows'][number]>;
    processes: Map<string, ProcessPolicy[]>;
  }
>();
function indexPolicy(v: PolicyView) {
  let index = policyIndexes.get(v);
  if (index) return index;
  index = {
    apps: new Map(),
    rows: new Map(v.rows.map((r) => [r.row_id, r])),
    processes: new Map(),
  };
  for (const app of v.applications)
    for (const pid of app.process_ids) {
      const list = index.apps.get(pid) || [];
      list.push(app);
      index.apps.set(pid, list);
    }
  for (const p of v.processes || []) {
    const list = index.processes.get(p.process_id) || [];
    list.push(p);
    index.processes.set(p.process_id, list);
  }
  policyIndexes.set(v, index);
  return index;
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
  if (row.runtimeApplication) {
    const r=row.runtimeApplication;
    const a=v.applications.find(a=>a.identity.key===r.application.key && a.identity.revision===r.application.revision && a.identity.uid===r.uid && (row.policyRows||row.rows).some(s=>v.rows.some(p=>p.row_id===s.id && p.status==='observed_runtime' && p.application_ref===a.ref)));
    return a ? {application:a,reason:v.snapshot.meaning} : {reason:'Runtime application association awaits a fresh policy snapshot.'};
  }
  if (row.displayApplication || (row.socket?.display_application && row.socket.owners.length > 1))
    return { reason: 'Shared/display-only identity is not a policy target.' };
  const p =
    row.process ||
    (row.socket?.owners.length === 1
      ? state.observation.activity?.processes[row.socket.owners[0]]
      : undefined);
  if (!p) return { reason: 'No supported single-process application identity.' };
  const a = (indexPolicy(v).apps.get(p.id) || []).find(
    (a) =>
      a.identity.key === p.application.key &&
      a.identity.revision === p.application.revision &&
      a.identity.uid === p.uid &&
      a.process_ids.includes(p.id),
  );
  if (row.socket) {
    if (row.socket.owners.length !== 1 || row.socket.ownership_category !== 'visible-holder')
      return { reason: 'A current unique visible holder is required for application policy.' };
    const association = indexPolicy(v).rows.get(row.socket!.id);
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
// Association only: policy classification, precedence and liveness come from Go.
export function authoritativeProcessPolicy(
  row: Row,
  state: ClientState,
): ProcessPolicy | undefined {
  if (row.kind !== 'process' && row.kind !== 'socket') return;
  const c = state.control,
    v = c.policy,
    a = state.observation.activity;
  if (!c.capabilities?.includes('process-instance-rules-v1')) return;
  if (
    !c.connected ||
    !state.observation.connected ||
    !v ||
    !a ||
    v.snapshot.generation !== c.generation ||
    state.observation.generation !== c.generation ||
    !v.activity_available ||
    (v.snapshot.valid_until && Date.parse(v.snapshot.valid_until) <= (c.serverNow ?? Infinity)) ||
    BigInt(v.activity_sequence) > BigInt(a.sequence) ||
    Date.parse(v.activity_collected) > Date.parse(a.collected) ||
    (c.serverNow ?? Infinity) - Date.parse(v.activity_collected) > 45000
  )
    return;
  if (
    row.displayApplication ||
    (row.socket &&
      (row.socket.owners.length !== 1 || row.socket.ownership_category !== 'visible-holder'))
  )
    return;
  const p = row.process || (row.socket && a.processes[row.socket.owners[0]]);
  if (!p) return;
  const candidates =
    indexPolicy(v)
      .processes.get(p.id)
      ?.filter(
        (entry) =>
          entry.target.session === c.generation &&
          entry.process_id === p.id &&
          entry.target.pid === p.pid &&
          entry.target.start_ticks === p.start_ticks &&
          entry.target.uid === p.uid &&
          entry.target.executable === p.application.executable &&
          entry.target.revision === p.application.revision,
      ) || [];
  const result = candidates.find((entry) => entry.state === 'active') || candidates[0];
  if (
    row.socket &&
    !(
      indexPolicy(v).rows.get(row.socket!.id)?.status === 'observed_native' &&
      indexPolicy(v).rows.get(row.socket!.id)?.application_ref === result?.application_ref
    )
  )
    return;
  return result;
}
export function policyLabel(d: DirectionPolicy) {
  return d.configured === 'uniform'
    ? `${d.action === 'block' ? 'Block' : d.action === 'allow' ? 'Allow' : d.action === 'ask' ? 'Ask' : d.action}`
    : d.configured === 'absent'
      ? 'No explicit rule'
      : d.configured === 'inactive_only'
        ? 'Inactive rules'
        : d.configured === 'mixed'
          ? `Mixed · ${d.rules.length}`
          : `Scoped · ${d.rules.length}`;
}
export function policyRuleDescription(r: PolicyRuleRef) {
  const f = r.scope;
  return `${r.root_application ? `UID ${f.uid} + root · ` : ''}${r.expired ? 'Expired' : r.disabled ? 'Disabled' : r.active ? 'Enabled' : 'Inactive'} ${r.action} · ${f.direction} ${f.protocol} · remote ${f.remote_address || f.remote || 'any'} · local port ${f.local_port || 'any'} · remote port ${f.remote_port || 'any'} · expires ${r.expires.startsWith('0001-') ? 'never' : r.expires} · ${r.id} v${r.version}`;
}

// Exact backend inventory association only; never classify an endpoint or choose a rule.
export function authoritativeZonePolicy(row: Row, state: ClientState) {
  const c = state.control,
    v = c.policy;
  if (
    row.kind !== 'network' ||
    !c.connected ||
    !c.capabilities?.includes('network-zone-policy-v1') ||
    !v ||
    v.snapshot.generation !== c.generation ||
    v.network_zones?.revision !== c.networkZones?.revision ||
    !Number.isFinite(c.serverNow) ||
    (v.snapshot.valid_until && Date.parse(v.snapshot.valid_until) <= c.serverNow!)
  )
    return;
  return v.zones?.find((z) => z.zone === (row.id === 'network:local' ? 'local' : 'internet'));
}
