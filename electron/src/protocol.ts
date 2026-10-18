import { parseProcessTarget, type ProcessTarget } from './process-rules';
import {
  parseEvaluation,
  type DaemonEvaluationStatus,
  type EvaluationTokens,
} from './evaluation-model';
import type { DecisionLogState } from './decision-log-client';
import type { LogFilter, LogRecord } from './decision-log';
import { parsePolicyView, type PolicyView } from './policy';
// Additive v1 API projection. Backend values are data, never renderer markup.
export interface Application {
  key: string;
  revision: string;
  name: string;
  executable: string;
}
export interface Process {
  thread_group_pid?: number;
  id: string;
  pid: number;
  start_ticks: string;
  uid: number;
  executable: string;
  application: Application;
}
export interface Traffic {
  state?: string;
  available: boolean;
  partial: boolean;
  definition: string;
  source: string;
  reason: string;
  since: string;
  uploaded?: number;
  downloaded?: number;
  upload_bps?: number;
  download_bps?: number;
}
export interface SocketRow {
  ownership_category?: string;
  display_application?: Application;
  id: string;
  ownership: string;
  owners: string[];
  state: string;
  direction: string;
  initiation?: {
    state: 'known' | 'listening' | 'unconnected' | 'unknown' | 'ambiguous';
    direction?: 'incoming' | 'outgoing';
    source: string;
    reason: string;
    observed_at?: string;
  };
  evidence: string;
  socket: {
    protocol: string;
    local: string;
    remote: string;
    uid: number;
    cookie: string;
    netns: string;
    state: number;
  };
  traffic: Traffic;
}
export interface Activity {
  udp?: {
    machine_scope?: boolean;
    state: string;
    reason: string;
    generation: string;
    missed_operations: number;
    collected: string;
    uid: number;
  };
  sequence: number;
  collected: string;
  complete: boolean;
  error: string;
  issues: string[];
  inaccessible_processes: number;
  rows: SocketRow[];
  processes: Record<string, Process>;
}
export interface RequestEvent {
  id: string;
  state: string;
  reason: string;
  deadline: string;
  first_seen: string;
  permission: string;
  flow: { direction: string; protocol: string; local: string; remote: string };
  attribution: {
    status: string;
    reason: string;
    visibility_complete: boolean;
    application?: Application;
    owners: Process[];
  };
  remembered_filter?: RuleFilter;
  scope_previews: Partial<Record<Scope, string>>;
}
export type Scope = 'once' | 'application' | 'persistent';
export type Action = 'allow' | 'block';
export interface TrafficMonitor {
  state: 'disabled' | 'starting' | 'active' | 'stopping' | 'failed';
  available: boolean;
  reason_code: string;
  reason: string;
  generation: string;
  netns: string;
  scope: 'machine' | 'self';
  partial: boolean;
  missed_operations: number;
  collected: string;
}
export interface ExtendedState {
  mode: 'daemon' | 'legacy';
  state: string;
  busy: boolean;
  message: string;
  canEnable: boolean;
  canStop: boolean;
  canView: boolean;
  canControl: boolean;
  partial: boolean;
}
export interface Permissions {
  can_control_evaluation?: boolean;
  can_view_measurements?: boolean;
  can_control_traffic?: boolean;
  role: 'user' | 'administrator';
  observation_scope: 'self' | 'machine' | 'user-visible';
  policy_scope: 'self' | 'machine';
  can_manage_rules: boolean;
  can_decide: boolean;
}
export interface Reply {
  evaluation?: DaemonEvaluationStatus;
  decision_log?: unknown;
  decision_record?: unknown;
  traffic_monitor?: TrafficMonitor;
  policy_view?: PolicyView;
  observed_preview?: ObservedPreview;
  permissions?: Permissions;
  backend_mode?: string;
  version: 1;
  generation: string;
  read_only: boolean;
  mode: string;
  server_time: string;
  error: string;
  error_code: string;
  capabilities: string[];
  deleted_rule?: { id: string; version: number };
  activity?: Activity;
  events: RequestEvent[];
  decision?: RequestEvent;
  rules: Rule[];
  rule_states?: Record<string, RuleTargetState>;
  saved_rule?: Rule;
  scope_preview: string;
  enforcement?: { state: string; detail: string; profile: string; stops_at: string };
}
export interface Attempt {
  phase: 'submitting' | 'acknowledged' | 'rejected' | 'unknown';
  message: string;
  rule?: Rule;
  reconcile?: string;
}
export interface ViewEvent extends RequestEvent {
  remainingMs: number;
  attempt?: Attempt;
}
export interface ClientState {
  observation: {
    connected: boolean;
    message: string;
    generation: string;
    activity?: Activity;
    capabilities?: string[];
    permissions?: Permissions;
    trafficMonitor?: TrafficMonitor;
    evaluation?: DaemonEvaluationStatus;
  };
  control: {
    trafficMonitor?: TrafficMonitor;
    evaluation?: DaemonEvaluationStatus;
    snapshotStarted?: number;
    connected: boolean;
    message: string;
    generation: string;
    readOnly: boolean;
    mode: string;
    enforcement?: Reply['enforcement'];
    permissions?: Permissions;
    backendMode?: string;
    events: ViewEvent[];
    rules?: Rule[];
    rule_states?: Record<string, RuleTargetState>;
    capabilities?: string[];
    serverNow?: number;
    policy?: PolicyView;
    policyError?: string;
  };
}
export interface Decision {
  generation: string;
  id: string;
  action: Action;
  scope: Scope;
}
export interface Bridge {
  applicationIcons(keys: string[]): Promise<Record<string, string | null>>;
  graph(value: { id: string; seconds: number }): Promise<import('./history').GraphView>;
  snapshot(): Promise<ClientState>;
  backgroundStatus(): Promise<{ trayAvailable: boolean; notifications: string }>;
  quit(): Promise<void>;
  onNavigate(fn: (value: { tab: 'requests'; message: string }) => void): () => void;
  extended(action: 'enable' | 'stop'): Promise<void>;
  extendedState(): Promise<ExtendedState>;
  ruleDraft(source: RuleSource): Promise<RuleDraft>;
  ruleReconcile(receipt: string): Promise<Attempt>;
  rulePreview(value: RuleEdit): Promise<RulePreview>;
  ruleSave(receipt: string): Promise<Attempt>;
  ruleDelete(value: { id: string; generation: string; version: number }): Promise<Attempt>;
  evaluation(
    action: EvaluationAction,
    profile?: 'incoming' | 'both' | EvaluationTokens,
  ): Promise<void>;
  evaluationState(): Promise<EvaluationState>;
  preferences(value?: Preferences): Promise<Preferences>;
  subscribe(fn: (state: ClientState) => void): () => void;
  decide(value: Decision): Promise<Attempt>;
  openPrompt(id: string): Promise<void>;
  dismissPrompt(): Promise<void>;
  decisionLog(): Promise<DecisionLogState>;
  decisionLogVisible(visible: boolean): Promise<void>;
  decisionLogFilter(filter: LogFilter): Promise<DecisionLogState>;
  decisionLogOlder(): Promise<DecisionLogState>;
  decisionLogLive(live: boolean): Promise<DecisionLogState>;
  decisionLogDetail(
    id: string,
  ): Promise<{ record?: LogRecord; note: string; unavailable?: boolean }>;
  decisionLogCopy(id: string, endpoint?: 'local' | 'remote'): Promise<void>;
}
declare global {
  interface Window {
    flowgate: Bridge;
  }
}

const object = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const string = (v: unknown): string => (typeof v === 'string' ? v : '');
const number = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const metric = (v: unknown): number | undefined =>
  typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER
    ? v
    : undefined;
const array = (v: unknown, max: number): unknown[] => {
  if (v == null) return [];
  if (!Array.isArray(v) || v.length > max) throw Error('Invalid API array');
  return v;
};
function application(v: unknown): Application {
  const a = object(v);
  return {
    key: string(a.key),
    revision: string(a.revision),
    name: string(a.name),
    executable: string(a.executable),
  };
}
function process(v: unknown): Process {
  const p = object(v);
  return {
    id: string(p.id),
    pid: number(p.pid),
    thread_group_pid: number(p.thread_group_pid) > 0 ? number(p.thread_group_pid) : undefined,
    start_ticks: string(p.start_ticks),
    uid: number(p.uid),
    executable: string(p.executable),
    application: application(p.application),
  };
}
function event(v: unknown): RequestEvent {
  const e = object(v),
    f = object(e.flow),
    a = object(e.attribution),
    scopes = object(e.scope_previews);
  const previews: RequestEvent['scope_previews'] = {};
  for (const key of ['once', 'application', 'persistent'] as Scope[])
    if (typeof scopes[key] === 'string' && scopes[key]) previews[key] = scopes[key] as string;
  if (!string(e.id) || !Number.isFinite(Date.parse(string(e.deadline))))
    throw Error('Invalid request identity/deadline');
  return {
    id: string(e.id),
    state: string(e.state),
    reason: string(e.reason),
    deadline: string(e.deadline),
    first_seen: string(e.first_seen),
    permission: string(e.permission),
    flow: {
      direction: string(f.direction),
      protocol: string(f.protocol),
      local: string(f.local),
      remote: string(f.remote),
    },
    attribution: {
      status: string(a.status),
      reason: string(a.reason),
      visibility_complete: a.visibility_complete === true,
      application: a.application ? application(a.application) : undefined,
      owners: array(a.owners, 2048).map(process),
    },
    scope_previews: previews,
    remembered_filter: e.remembered_filter ? ruleFilter(e.remembered_filter) : undefined,
  };
}
export function parseReply(raw: unknown): Reply {
  const r = object(raw);
  if (
    r.version !== 1 ||
    !string(r.generation) ||
    typeof r.read_only !== 'boolean' ||
    !Number.isFinite(Date.parse(string(r.server_time)))
  )
    throw Error('Invalid v1 backend response');
  const result: Reply = {
    version: 1,
    generation: string(r.generation),
    read_only: r.read_only,
    mode: string(r.mode),
    server_time: string(r.server_time),
    error: string(r.error),
    error_code: string(r.error_code),
    capabilities: array(r.capabilities, 64).map(string),
    deleted_rule: r.deleted_rule
      ? {
          id: string(object(r.deleted_rule).id),
          version: ruleVersion(object(r.deleted_rule).version ?? null),
        }
      : undefined,
    events: array(r.events, 256).map(event),
    rules: array(r.rules, 8192).map(parseRule),
    rule_states: r.rule_states
      ? Object.fromEntries(
          Object.entries(object(r.rule_states))
            .slice(0, 8192)
            .map(([id, value]) => {
              const v = object(value);
              if (
                !['application', 'process'].includes(string(v.target_scope)) ||
                !['active', 'inactive'].includes(string(v.state))
              )
                throw Error('Invalid rule target state');
              return [
                id,
                {
                  target_scope: v.target_scope as 'application' | 'process',
                  state: v.state as 'active' | 'inactive',
                  reason: string(v.reason),
                },
              ];
            }),
        )
      : undefined,
    saved_rule: r.saved_rule ? parseRule(r.saved_rule) : undefined,
    scope_preview: string(r.scope_preview),
    // Validated by decision-log.ts, which owns the decision-log-v1 schema.
    decision_log: r.decision_log,
    decision_record: r.decision_record,
    evaluation: parseEvaluation(r.evaluation),
  };
  if (r.permissions !== undefined || result.capabilities.includes('explicit-administrator-v1')) {
    const p = object(r.permissions);
    if (
      !['user', 'administrator'].includes(string(p.role)) ||
      !['self', 'machine', 'user-visible'].includes(string(p.observation_scope)) ||
      !['self', 'machine'].includes(string(p.policy_scope)) ||
      typeof p.can_manage_rules !== 'boolean' ||
      typeof p.can_decide !== 'boolean'
    )
      throw Error('Invalid explicit permission metadata');
    result.permissions = {
      role: p.role,
      observation_scope: p.observation_scope,
      policy_scope: p.policy_scope,
      can_manage_rules: p.can_manage_rules,
      can_decide: p.can_decide,
      can_view_measurements: p.can_view_measurements === true,
      can_control_traffic: p.can_control_traffic === true,
      can_control_evaluation: p.can_control_evaluation === true,
    } as Permissions;
  }
  if (result.capabilities.includes('daemon-udp-monitor-v1')) {
    try {
      const m = object(r.traffic_monitor),
        p = object(r.permissions);
      if (
        !['disabled', 'starting', 'active', 'stopping', 'failed'].includes(string(m.state)) ||
        !['machine', 'self'].includes(string(m.scope)) ||
        typeof m.available !== 'boolean' ||
        typeof m.partial !== 'boolean' ||
        typeof p.can_control_traffic !== 'boolean' ||
        typeof p.can_view_measurements !== 'boolean'
      )
        throw Error('Invalid daemon collector metadata');
      result.traffic_monitor = {
        state: m.state as TrafficMonitor['state'],
        available: m.available,
        reason_code: string(m.reason_code),
        reason: string(m.reason),
        generation: string(m.generation),
        netns: string(m.netns),
        scope: m.scope as TrafficMonitor['scope'],
        partial: m.partial,
        missed_operations: number(m.missed_operations),
        collected: string(m.collected),
      };
    } catch {
      // Fail closed for this optional lifecycle feature without dropping TCP/rules.
      result.traffic_monitor = undefined;
    }
  }
  result.backend_mode = string(r.backend_mode);
  if (r.policy_view) result.policy_view = parsePolicyView(r.policy_view);
  if (r.observed_preview) {
    const p = object(r.observed_preview),
      e = object(p.enforcement);
    if (
      !string(p.token) ||
      !string(p.process_id) ||
      !string(p.scope_preview) ||
      !Number.isFinite(Date.parse(string(p.expires_at))) ||
      typeof e.covered !== 'boolean'
    )
      throw Error('Invalid observed preview');
    result.observed_preview = {
      token: string(p.token),
      expires_at: string(p.expires_at),
      rule: parseRule(p.rule),
      application: application(p.application),
      process_id: string(p.process_id),
      pid: number(p.pid),
      principal_uid: number(p.principal_uid),
      scope_preview: string(p.scope_preview),
      enforcement: { state: string(e.state), covered: e.covered, reason: string(e.reason) },
    };
  }
  if (r.decision) result.decision = event(r.decision);
  if (r.enforcement) {
    const e = object(r.enforcement);
    result.enforcement = {
      state: string(e.state),
      detail: string(e.detail),
      profile: string(e.profile),
      stops_at: string(e.stops_at),
    };
  }
  if (r.activity) {
    const a = object(r.activity),
      processes: Record<string, Process> = Object.create(null);
    for (const [id, p] of Object.entries(object(a.processes))) {
      if (Object.keys(processes).length >= 8192) throw Error('Too many processes');
      processes[id] = process(p);
    }
    result.activity = {
      udp: a.udp
        ? {
            state: string(object(a.udp).state),
            machine_scope: object(a.udp).machine_scope === true,
            reason: string(object(a.udp).reason),
            generation: string(object(a.udp).generation),
            missed_operations: number(object(a.udp).missed_operations),
            collected: string(object(a.udp).collected),
            uid: number(object(a.udp).uid),
          }
        : undefined,
      sequence: number(a.sequence),
      collected: string(a.collected),
      complete: a.complete === true,
      error: string(a.error),
      issues: array(a.issues, 256).map(string),
      inaccessible_processes: number(a.inaccessible_processes),
      processes,
      rows: array(a.rows, 2048).map((v) => {
        const row = object(v),
          s = object(row.socket),
          t = object(row.traffic);
        if (!string(row.id)) throw Error('Invalid socket identity');
        return {
          id: string(row.id),
          ownership: string(row.ownership),
          ownership_category: string(row.ownership_category),
          display_application: row.display_application
            ? application(row.display_application)
            : undefined,
          owners: array(row.owners, 2048).map(string),
          state: string(row.state),
          direction: string(row.direction),
          initiation: row.initiation
            ? (() => {
                const i = object(row.initiation);
                const state = string(i.state);
                if (!['known', 'listening', 'unconnected', 'unknown', 'ambiguous'].includes(state))
                  throw Error('Invalid initiation state');
                const direction = string(i.direction);
                if (state === 'known' && !['incoming', 'outgoing'].includes(direction))
                  throw Error('Invalid initiation direction');
                return {
                  state: state as NonNullable<SocketRow['initiation']>['state'],
                  direction: state === 'known' ? (direction as 'incoming' | 'outgoing') : undefined,
                  source: string(i.source),
                  reason: string(i.reason),
                  observed_at: string(i.observed_at) || undefined,
                };
              })()
            : undefined,
          evidence: string(row.evidence),
          socket: {
            protocol: string(s.protocol),
            local: string(s.local),
            remote: string(s.remote),
            uid: number(s.uid),
            cookie: string(s.cookie),
            netns: string(s.netns),
            state: number(s.state),
          },
          traffic: {
            state: string(t.state),
            available: t.available === true,
            partial: t.partial === true,
            definition: string(t.definition),
            source: string(t.source),
            reason: string(t.reason),
            since: string(t.since),
            uploaded: metric(t.uploaded),
            downloaded: metric(t.downloaded),
            upload_bps: metric(t.upload_bps),
            download_bps: metric(t.download_bps),
          },
        };
      }),
    };
  }
  return result;
}
export function validateDecision(v: unknown): Decision {
  const d = object(v);
  if (
    Object.keys(d).sort().join(',') !== 'action,generation,id,scope' ||
    !string(d.id) ||
    string(d.id).length > 256 ||
    !string(d.generation) ||
    string(d.generation).length > 256 ||
    !['allow', 'block'].includes(string(d.action)) ||
    !['once', 'application', 'persistent'].includes(string(d.scope))
  )
    throw Error('Invalid decision');
  return d as unknown as Decision;
}

export interface RuleFilter {
  process?: ProcessTarget;
  application: string;
  revision: string;
  direction: string;
  protocol: string;
  remote_address?: string;
  local_port?: number;
  remote_port?: number;
  remote?: string;
  uid: number;
}
export interface RuleTargetState {
  target_scope: 'application' | 'process';
  state: 'active' | 'inactive';
  reason: string;
}
export interface Rule {
  version: number;
  executable: string;
  created: string;
  disabled: boolean;
  schema: number;
  id: string;
  priority: number;
  filter: RuleFilter;
  action: string;
  expires: string;
}
export interface RuleDraft {
  token: string;
  generation: string;
  rule: Rule;
  source: string;
  observed?: boolean;
  targetScope?: 'application' | 'process';
  processID?: string;
}
export interface ObservedSource {
  target_scope?: 'application' | 'process';
  generation: string;
  row_id: string;
  process_id: string;
  direction: 'incoming' | 'outgoing';
}
export type RuleSource = { id?: string; event?: string; observed?: ObservedSource };
export interface ObservedPreview {
  token: string;
  expires_at: string;
  rule: Rule;
  application: Application;
  process_id: string;
  pid: number;
  principal_uid: number;
  scope_preview: string;
  enforcement: { state: string; covered: boolean; reason: string };
}
export interface RulePreview {
  receipt: string;
  preview: string;
  expiresAt?: string;
  verifiedRule?: Rule;
  processID?: string;
}
export interface RuleEdit {
  token: string;
  action: Action;
  protocol: string;
  remote_address: string;
  local_port: number;
  remote_port: number;
  priority: number;
  disabled: boolean;
  expiry: 'preserve' | 'hour' | 'permanent';
  creation_scope?: 'application' | 'custom';
}
export type EvaluationAction = 'start' | 'stop' | 'status' | 'recover' | 'cancel';
export interface EvaluationState {
  mode?: 'daemon' | 'legacy';
  label?: string;
  status?: DaemonEvaluationStatus;
  remainingMs?: number;
  tokens?: EvaluationTokens;
  canCheck?: boolean;
  canStart?: boolean;
  canStop?: boolean;
  phase: string;
  message: string;
  generation: string;
  busy: boolean;
  starting: boolean;
}
export interface Preferences {
  displayUnit?: import('./display-units').DisplayUnit;
  keepInTray?: boolean;
  sidebar?: number;
  columns?: Record<string, number>;
}
function ruleFilter(v: unknown): RuleFilter {
  const f = object(v);
  return {
    process: parseProcessTarget(f.process),
    application: string(f.application),
    revision: string(f.revision),
    direction: string(f.direction),
    protocol: string(f.protocol),
    remote_address: string(f.remote_address),
    remote: string(f.remote),
    local_port: number(f.local_port),
    remote_port: number(f.remote_port),
    uid: number(f.uid),
  };
}
function ruleVersion(v: unknown): number {
  if (v === undefined) return 0;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0)
    throw Error(
      'Rule version cannot be represented losslessly in this Electron client; operation refused. Use a uint64-capable client.',
    );
  return v;
}
function parseRule(v: unknown): Rule {
  const r = object(v),
    filter = ruleFilter(r.filter);
  if ((number(r.schema) === 3) !== !!filter.process)
    throw Error('Process rule requires schema3 and a complete immutable binding');
  return {
    version: ruleVersion(r.version),
    executable: string(r.executable),
    created: string(r.created),
    disabled: r.disabled === true,
    schema: number(r.schema),
    id: string(r.id),
    priority: number(r.priority),
    filter,
    action: string(r.action),
    expires: string(r.expires),
  };
}
export function validateEdit(v: unknown): RuleEdit {
  const e = object(v);
  if (
    Object.keys(e)
      .filter((k) => k !== 'creation_scope')
      .sort()
      .join(',') !==
      'action,disabled,expiry,local_port,priority,protocol,remote_address,remote_port,token' ||
    (e.creation_scope !== undefined &&
      !['application', 'custom'].includes(String(e.creation_scope))) ||
    typeof e.token !== 'string' ||
    e.token.length > 128 ||
    !['allow', 'block'].includes(String(e.action)) ||
    !['tcp', 'udp', '*'].includes(String(e.protocol)) ||
    typeof e.remote_address !== 'string' ||
    e.remote_address.length > 256 ||
    ![e.local_port, e.remote_port].every(
      (n) => Number.isInteger(n) && Number(n) >= 0 && Number(n) <= 65535,
    ) ||
    !Number.isInteger(e.priority) ||
    Math.abs(Number(e.priority)) > 1000 ||
    typeof e.disabled !== 'boolean' ||
    !['preserve', 'hour', 'permanent'].includes(String(e.expiry))
  )
    throw Error('Invalid rule edit');
  return e as unknown as RuleEdit;
}

// Legacy control state already incorporates its enforcement/read-only restrictions.
// Explicit grants are operation-specific; writable storage never authorizes a verdict.
export function canManageRules(c: ClientState['control']) {
  return c.connected && !c.readOnly && (c.permissions?.can_manage_rules ?? true);
}
export function canDecide(c: ClientState['control']) {
  return c.connected && !c.readOnly && (c.permissions?.can_decide ?? true);
}
