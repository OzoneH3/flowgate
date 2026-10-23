import {
  parseProtection,
  type ProtectionStatus,
  type ProtectionTokens,
  type ProtectionView,
} from './protection-model';
import { parseConnectionZone } from './connection-presentation';
import { parseAttributionReasonCode } from './attribution-reason';
import { parseRuntimeChecks } from './runtime-checks';
import { parseDaemonBuild } from './build-info';
import {
  parseNetworkZones,
  type NetworkZones,
  type NetworkZone,
  type ZoneSource,
} from './network-zones';
import { parseProcessTarget, type ProcessTarget } from './process-rules';
import { parseLocalPeer, parseOwnSockets, parsePairResult, type LocalPeer, type OwnSocket, type PairChoice, type PairResult } from './local-pair';
import { parseLeaseRef, parseProcessLeases, validForAWhileSeconds } from './process-lease';
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
  // Backend-proven host backing file for a sandbox executable.
  host_executable?: string;
  display_name?: string;
  display_executable?: string;
  executable_status?: 'linked' | 'deleted' | 'unavailable';
  // native | wine | electron (verified app bundle on a shared Electron runtime) | ...
  kind?: string;
  // Electron app: the runtime binary that runs the bundle (executable = bundle).
  runtime?: string;
  // An application hosted by a shared runtime, with its verification.
  hosted?: Hosted;
}
export interface Hosted {
  state: 'verified' | 'unverified';
  runtime: string;
  bundle?: string;
  package_name?: string;
  product_name?: string;
  version?: string;
  integrity?: string;
  chain: { pid: number; start_ticks: string; type: string }[];
  reason: string;
}
// Launch provenance (display only; never a firewall target). See docs/API.md.
export interface ProvenanceAncestor {
  pid: number;
  start_ticks: string;
  uid: number;
  name: string;
  executable: string;
  revision?: string;
  marker?: string;
}
export interface Launch {
  kind: 'umu' | 'proton' | 'steam' | 'wine';
  launcher_pid: number;
  launcher_start_ticks: string;
  launcher_name: string;
  game?: {
    name: string;
    title?: string;
    executable: string;
    revision?: string;
    status: 'verified-file' | 'not-found';
    source: string;
  };
  prefix?: string;
  prefix_id?: string;
  prefix_source?: string;
  runtime?: string;
  steam_app_id?: string;
  game_id?: string;
  markers: string[];
}
export interface Provenance {
  evidence: 'verified' | 'unavailable' | 'none';
  reason: string;
  role?: 'launcher' | 'game' | 'runtime' | 'helper';
  group?: string;
  stop: string;
  ancestry: ProvenanceAncestor[];
  launch?: Launch;
  // The program that started the owner (display only; never a rule target).
  parent?: LaunchParent;
  captured_at?: string;
  invocation?: Invocation;
}
export interface LaunchParent {
  pid: number;
  start_ticks: string;
  depth: number;
  name: string;
  executable: string;
  application?: Application;
  note?: string;
  invocation?: Invocation;
}
export interface Invocation {
  mode: string;
  name: string;
  path?: string;
  host_path?: string;
  revision?: string;
  application?: Application;
}
// What each decision scope is enforced against today (backend-derived).
export interface PermissionTarget {
  kind: 'helper' | 'application' | 'interpreter' | 'unavailable' | 'runtime-unverified';
  label: string;
  once: string;
  for_a_while: string;
  remember: string;
  shared_with_note?: string;
  key_basis: string;
  prefix?: string;
}
export interface Process {
  thread_group_pid?: number;
  id: string;
  pid: number;
  start_ticks: string;
  uid: number;
  executable: string;
  application: Application;
  provenance?: Provenance;
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
export interface RuntimeApplication { application: Application; uid: number; evidence: RuntimeTable; }
export interface RuntimeTable { runtime: string; prefix: string; broker_pid: number; broker_start_ticks: string; socket_cookie: string; uid: number; method: string; windows_handle_holders: {pid:number; creation_time:string; image:string}[]; }
export interface SocketRow {
 runtime_application?: RuntimeApplication;
  network_scope?: {
    state: 'known' | 'unavailable';
    zone?: NetworkZone;
    revision: string;
    source: string;
    reason: string;
    // automatic-peer-v1 only: custom = explicit configured prefix override.
    basis?: 'automatic' | 'custom';
    legacy_state?: string; legacy_zone?: string; legacy_revision?: string;
  };
  ownership_category?: string;
  display_application?: Application;
  id: string;
  ownership: string;
  owners: string[];
  state: string;
  direction: string;
  initiation?: {
    generation?: string;
    state: 'known' | 'listening' | 'unconnected' | 'unknown' | 'ambiguous';
    direction?: 'incoming' | 'outgoing';
    source: string;
    reason: string;
    observed_at?: string;
  };
  evidence: string;
  socket: {
    protocol: string;
    // Optional on older responses. Missing/invalid evidence must not become zero.
    inode?: number;
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
  tcp_initiation?: {
    state: 'disabled' | 'starting' | 'active' | 'failed' | 'unavailable';
    generation: string;
    netns: string;
    reason: string;
    partial: boolean;
    lost_events: number;
    collected: string;
  };
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
  revalidation?: {
    code: string; reason: string; checked_at: string;
    changes: { field: string; before: string; after: string }[];
  };
  id: string;
  state: string;
  reason: string;
  deadline: string;
  first_seen: string;
  permission: string;
  flow: {
    direction: string;
    protocol: string;
    local: string;
    remote: string;
    netns?: string;
    network_scope?: SocketRow['network_scope'];
  };
  attribution: {
    runtime_table?: RuntimeTable;
    status: string;
    reason: string;
    reason_code?: string;
    visibility_complete: boolean;
    application?: Application;
    owners: Process[];
    provenance?: Provenance;
    permission_target?: PermissionTarget;
    // local-pair-v1: the request's own socket(s) (cookie/inode evidence).
    sockets?: OwnSocket[];
  };
  // local-pair-v1: other endpoint of a same-host connection (exact reversed tuple).
  local_peer?: LocalPeer;
  remembered_filter?: RuleFilter;
  scope_previews: Partial<Record<Scope, string>>;
  // Equivalent repeated requests share a group (backend `request_group`).
  request_group?: string;
  // stored-ask-v1: the stored Ask rule that caused this prompt (absent = default Ask).
  ask_rule?: { id: string; version: number };
  // request-application-rule-v1: retained verified identity for a future rule.
  // process_lease_available (request-for-a-while-v1): undecided request whose
  // exact verified process instance still runs; For a while may create a lease.
  request_rule?: {
    available: boolean; process_state: 'running' | 'ended' | 'unknown'; until: string;
    process_lease_available?: boolean; pid?: number;
  };
  // decision-for-a-while-v1: the lease a For a while decision created.
  lease?: { id: string; until: string };
  // queue-reconcile-v1: enabled rules for an EARLIER revision of this
  // application (e.g. updated executable). Display only; never applied.
  previous_revision_rules?: { id: string; action: string; revision: string }[];
}
export type Scope = 'once' | 'application' | 'persistent';
export type Action = 'allow' | 'block';
// Stored Blocker actions; 'ask' requires stored-ask-v1 (decisions stay allow/block).
export type RuleAction = Action | 'ask';
export const STORED_ASK_CAPABILITY = 'stored-ask-v1';
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
  can_manage_machine_rules?: boolean;
  can_control_evaluation?: boolean;
  can_control_protection?: boolean;
  can_view_measurements?: boolean;
  can_control_traffic?: boolean;
  role: 'user' | 'administrator';
  observation_scope: 'self' | 'machine' | 'user-visible';
  policy_scope: 'self' | 'machine';
  can_manage_rules: boolean;
  can_decide: boolean;
}
export interface Reply {
  observed_usage?: unknown;
  snapshot_revision?: string;
  snapshot_at?: string;
  essential_status?: unknown;
  essential_preview?: unknown;
  essential_receipt?: unknown;
  network_zones?: NetworkZones;
  zone_migration?: unknown;
  zone_preview?: {
    token: string;
    expires_at: string;
    rule: Rule;
    scope_preview: string;
    network_zones: NetworkZones;
  };
  protection?: ProtectionStatus;
  evaluation?: DaemonEvaluationStatus;
  runtime_checks?: import('./runtime-checks').RuntimeCheck[];
  build?: import('./build-info').DaemonBuild;
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
  // local-pair-v1: decide-pair result (both sides).
  pair?: PairResult;
  decision_preview?: unknown;
  decision_receipt?: unknown;
  request_rule_preview?: unknown;
  process_leases?: import('./process-lease').ProcessLease[];
  // queue-reconcile-v1: other requests the operation settled.
  settled?: { id: string; state: string; rule: string }[];
  // request-for-a-while-v1: lease from an ended request (which stays ended).
  process_lease?: import('./process-lease').ProcessLease;
  request_ended?: boolean;
  // decision-for-a-while-durations-v1: allowed For a while durations (seconds).
  for_a_while_durations?: number[];
  replayed?: boolean;
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
  // Decided scope of an acknowledged attempt (for the short result text).
  scope?: Decision['scope'];
  // For a while: the backend's authoritative lease end.
  leaseUntil?: string;
}
export interface ViewEvent extends RequestEvent {
  reviewFailure?: import('./decision-remember').DecisionReviewFailure;
  remainingMs: number;
  attempt?: Attempt;
}
export interface ClientState {
  publication?: number;
  observation: {
    connected: boolean;
    message: string;
    generation: string;
    activity?: Activity;
    capabilities?: string[];
    permissions?: Permissions;
    trafficMonitor?: TrafficMonitor;
    protection?: ProtectionStatus;
    evaluation?: DaemonEvaluationStatus;
  };
  control: {
    runtimeChecks?: import('./runtime-checks').RuntimeCheck[];
    daemonBuild?: import('./build-info').DaemonBuild;
    trafficMonitor?: TrafficMonitor;
    protection?: ProtectionStatus;
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
    networkZones?: NetworkZones;
    policy?: PolicyView;
    policyError?: string;
    processLeases?: import('./process-lease').ProcessLease[];
    forAWhileDurations?: number[];
    // A decision outcome was unknown/rejected: no new prompt is presented until
    // an authoritative list issued after it was read (queue reconciliation).
    reconciling?: boolean;
    // Outcomes of permission submissions, newest first (permission-results.ts).
    permissionResults?: import('./permission-results').PermissionResult[];
  };
}
export interface Decision {
  generation: string;
  id: string;
  action: Action;
  // 'for-a-while' (decision-for-a-while-v1): Once plus a 15 s process-instance lease; never a rule.
  scope: Scope | 'for-a-while';
  network_zone?: 'any' | NetworkZone;
  zone_revision?: string;
  preview_token?: string;
  // decision-remember-fields-v1: false = any. Absent = legacy reviewed scope.
  remember?: { address: boolean; port: boolean; protocol: boolean; process: boolean };
  duration_seconds?: number;
}
export interface Bridge {
  hostIdentity(): Promise<string>;
  guiBuild(): Promise<import('./build-info').GuiBuild>;
  zoneMigrationState(): Promise<import('./zone-migration').MigrationView>;
  zoneMigrationPreview(target: import('./zone-migration').MigrationTarget): Promise<import('./zone-migration').MigrationView>;
  zoneMigrationConfirm(token: string): Promise<import('./zone-migration').MigrationView>;
  zoneMigrationReconcile(): Promise<import('./zone-migration').MigrationView>;
  essentialState(): Promise<import('./essential-model').EssentialView>;
  essential(
    action: 'status' | 'preview' | 'apply' | 'remove-preview' | 'remove' | 'reconcile',
    value: {
      generation: string;
      options?: import('./essential-model').EssentialOptions;
      token?: string;
    },
  ): Promise<import('./essential-model').EssentialView>;
  paneSnapshot(): Promise<import('./pane-model').PaneFrame>;
  paneUpdate(value: import('./pane-model').PresentationPatch): Promise<void>;
  paneControl(
    kind: import('./pane-model').PaneKind,
    action: 'undock' | 'dock' | 'close' | 'open',
  ): Promise<void>;
  paneRule(action: import('./pane-model').PaneRuleAction): Promise<void>;
  onPaneFrame(fn: (frame: import('./pane-model').PaneFrame) => void): () => void;
  onPaneRule(fn: (action: import('./pane-model').PaneRuleAction) => void): () => void;
  applicationMetadata(
    keys: string[],
  ): Promise<
    Record<
      string,
      { icon: string | null; name?: string; fallback?: 'service' | 'terminal'; source: 'desktop-metadata' | 'steam-manifest' | 'executable-resource' | 'unavailable' }
    >
  >;
  applicationIcons(keys: string[]): Promise<Record<string, string | null>>;
  graph(value: { id: string; seconds: number }): Promise<import('./history').GraphView>;
  snapshot(): Promise<ClientState>;
  backgroundStatus(): Promise<{ trayAvailable: boolean; notifications: string }>;
  quit(): Promise<void>;
  onNavigate(fn: (value: { tab: 'requests'; message: string }) => void): () => void;
  extended(action: 'enable' | 'stop'): Promise<void>;
  extendedState(): Promise<ExtendedState>;
  ruleContext(): Promise<ClientState>;
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
  protection(action: 'status' | 'start' | 'stop', tokens: ProtectionTokens): Promise<void>;
  protectionState(): Promise<ProtectionView>;
  preferences(value?: Preferences): Promise<Preferences>;
  subscribe(fn: (state: ClientState) => void): () => void;
  onClock(
    fn: (clock: { generation: string; serverNow: number; publication?: number }) => void,
  ): () => void;
  decide(value: Decision): Promise<Attempt>;
  // local-pair-v1: one decision for both sides of a verified local pair.
  decidePair(value: PairChoice): Promise<{ message: string; text: string; result: PairResult }>;
  decisionPreview(value: Decision): Promise<import('./decision-remember').DecisionPreview>;
  decisionReconcile(value: {
    generation: string;
    id: string;
    preview_token: string;
  }): Promise<Attempt>;
  openPrompt(id: string): Promise<void>;
  requestRulePreview(value: import('./request-rule').RequestRuleChoice): Promise<import('./request-rule').RequestRulePreview>;
  requestRuleSave(value: import('./request-rule').RequestRuleChoice): Promise<{ message: string; rule: Rule; replayed: boolean }>;
  requestForAWhile(value: import('./prompt-decision').EndedLeaseChoice): Promise<{ message: string; lease: import('./process-lease').ProcessLease }>;
  openFutureApplicationRule(value: { generation: string; id: string }): Promise<void>;
  onFutureApplicationRule(fn: (source: ObservedSource) => void): () => void;
  promptLayout(value: { height: number; pointerDown: boolean; keysDown: string[]; remember: boolean }): Promise<void>;
  dismissPrompt(): Promise<void>;
  decisionLog(): Promise<DecisionLogState>;
  observedUsage(): Promise<import('./observed-usage-client').UsageState>;
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
    display_name: string(a.display_name) || undefined,
    display_executable: string(a.display_executable) || undefined,
    executable_status: ['linked', 'deleted', 'unavailable'].includes(string(a.executable_status))
      ? (a.executable_status as Application['executable_status'])
      : undefined,
    kind: string(a.kind).slice(0, 32) || undefined,
    runtime: string(a.runtime) || undefined,
    hosted: hosted(a.hosted),
  };
}
function hosted(v: unknown): Hosted | undefined {
  if (v == null || typeof v !== 'object') return;
  const h = object(v);
  if (!['verified', 'unverified'].includes(string(h.state))) return;
  const chain = Array.isArray(h.chain) ? h.chain.slice(0, 8).map(object) : [];
  return {
    state: string(h.state) as Hosted['state'],
    runtime: string(h.runtime),
    bundle: string(h.bundle) || undefined,
    package_name: string(h.package_name).slice(0, 256) || undefined,
    product_name: string(h.product_name).slice(0, 256) || undefined,
    version: string(h.version).slice(0, 64) || undefined,
    integrity: string(h.integrity).slice(0, 256) || undefined,
    chain: chain.map((c) => ({ pid: Number.isSafeInteger(c.pid) ? (c.pid as number) : 0, start_ticks: string(c.start_ticks).slice(0, 32), type: string(c.type).slice(0, 64) })),
    reason: string(h.reason).slice(0, 1024),
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
    provenance: parseProvenance(p.provenance),
  };
}
const bounded = (v: unknown, max = 1024) => string(v).slice(0, max);
export function parseProvenance(raw: unknown): Provenance | undefined {
  if (raw == null) return;
  const p = object(raw);
  if (!['verified', 'unavailable', 'none'].includes(string(p.evidence))) return;
  const parseInvocation = (raw: unknown): Invocation | undefined => {
    if (raw == null || typeof raw !== 'object') return;
    const i=object(raw), mode=bounded(i.mode,32), name=bounded(i.name,256);
    if (!mode || !name || !['file','unverified-file','inline','module','stdin'].includes(mode)) return;
    return {mode,name,path:bounded(i.path),host_path:bounded(i.host_path),revision:bounded(i.revision,256),
      application:i.application == null ? undefined : application(i.application)};
  };
  const l = p.launch == null ? undefined : object(p.launch);
  const g = l && l.game != null ? object(l.game) : undefined;
  const launch: Launch | undefined =
    l && ['umu', 'proton', 'steam', 'wine'].includes(string(l.kind))
      ? {
          kind: string(l.kind) as Launch['kind'],
          launcher_pid: number(l.launcher_pid),
          launcher_start_ticks: bounded(l.launcher_start_ticks, 32),
          launcher_name: bounded(l.launcher_name, 256),
          game:
            g && ['verified-file', 'not-found'].includes(string(g.status))
              ? {
                  name: bounded(g.name, 256),
                  title: bounded(g.title, 256) || undefined,
                  executable: bounded(g.executable),
                  revision: bounded(g.revision, 256) || undefined,
                  status: string(g.status) as 'verified-file' | 'not-found',
                  source: bounded(g.source, 128),
                }
              : undefined,
          prefix: bounded(l.prefix) || undefined,
          prefix_id: bounded(l.prefix_id, 64) || undefined,
          prefix_source: bounded(l.prefix_source, 64) || undefined,
          runtime: bounded(l.runtime, 256) || undefined,
          steam_app_id: bounded(l.steam_app_id, 64) || undefined,
          game_id: bounded(l.game_id, 256) || undefined,
          markers: array(l.markers, 16).map((m) => bounded(m, 32)),
        }
      : undefined;
  return {
    evidence: string(p.evidence) as Provenance['evidence'],
    reason: bounded(p.reason),
    role: ['launcher', 'game', 'runtime', 'helper'].includes(string(p.role))
      ? (string(p.role) as Provenance['role'])
      : undefined,
    group: bounded(p.group, 64) || undefined,
    stop: bounded(p.stop, 64),
    parent: (() => {
      if (p.parent == null || typeof p.parent !== 'object') return undefined;
      const a = object(p.parent);
      if (!number(a.pid) || !bounded(a.name, 256)) return undefined;
      return {
        pid: number(a.pid),
        start_ticks: bounded(a.start_ticks, 32),
        depth: number(a.depth),
        name: bounded(a.name, 256),
        executable: bounded(a.executable),
        application: a.application != null && typeof a.application === 'object' ? application(a.application) : undefined,
        note: bounded(a.note, 1024) || undefined,
        invocation: parseInvocation(a.invocation),
      };
    })(),
    ancestry: array(p.ancestry, 32).map((raw) => {
      const a = object(raw);
      return {
        pid: number(a.pid),
        start_ticks: bounded(a.start_ticks, 32),
        uid: number(a.uid),
        name: bounded(a.name, 256),
        executable: bounded(a.executable),
        revision: bounded(a.revision, 256) || undefined,
        marker: bounded(a.marker, 32) || undefined,
      };
    }),
    launch,
    captured_at: bounded(p.captured_at, 64) || undefined,
    invocation: parseInvocation(p.invocation),
  };
}
export function parsePermissionTarget(raw: unknown): PermissionTarget | undefined {
  if (raw == null) return;
  const t = object(raw);
  if (!['helper', 'application', 'interpreter', 'unavailable'].includes(string(t.kind))) return;
  return {
    kind: string(t.kind) as PermissionTarget['kind'],
    label: bounded(t.label),
    once: bounded(t.once),
    for_a_while: bounded(t.for_a_while),
    remember: bounded(t.remember, 2048),
    shared_with_note: bounded(t.shared_with_note, 2048) || undefined,
    key_basis: bounded(t.key_basis, 256),
    prefix: bounded(t.prefix) || undefined,
  };
}
function pendingRevalidation(raw: unknown): RequestEvent['revalidation'] {
  if (raw == null) return;
  const r = object(raw);
  if (!/^[a-z_]{1,64}$/.test(string(r.code)) || !string(r.reason) ||
      string(r.reason).length > 4096 || !Number.isFinite(Date.parse(string(r.checked_at))))
    throw Error('Invalid pending revalidation');
  return { code: string(r.code), reason: string(r.reason), checked_at: string(r.checked_at),
    changes: array(r.changes, 128).map(raw => {
      const c = object(raw);
      if (!string(c.field) || ['field','before','after'].some(k => typeof c[k] !== 'string' || string(c[k]).length > 4096))
        throw Error('Invalid pending binding change');
      return {field: string(c.field), before: string(c.before), after: string(c.after)};
    }),
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
    revalidation: pendingRevalidation(e.revalidation),
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
      netns: typeof f.netns === 'string' ? f.netns.slice(0, 128) : undefined,
      network_scope: parseConnectionZone(f.network_scope),
    },
    attribution: {
      runtime_table: parseRuntimeTable(a.runtime_table),
      status: string(a.status),
      reason: string(a.reason),
      reason_code: parseAttributionReasonCode(a.reason_code),
      visibility_complete: a.visibility_complete === true,
      application: a.application ? application(a.application) : undefined,
      owners: array(a.owners, 2048).map(process),
      provenance: parseProvenance(a.provenance),
      permission_target: parsePermissionTarget(a.permission_target),
      sockets: parseOwnSockets(a.sockets),
    },
    scope_previews: previews,
    remembered_filter: e.remembered_filter ? ruleFilter(e.remembered_filter) : undefined,
    request_group:
      string(e.request_group) && string(e.request_group).length <= 256
        ? string(e.request_group)
        : undefined,
    ask_rule: askRule(e.ask_rule),
    request_rule: requestRuleSource(e.request_rule),
    lease: parseLeaseRef(e.lease),
    previous_revision_rules: previousRevisionRules(e.previous_revision_rules),
    local_peer: parseLocalPeer(e.local_peer, parseProvenance),
  };
}
function previousRevisionRules(v: unknown): RequestEvent['previous_revision_rules'] {
  if (!Array.isArray(v)) return undefined;
  const out = v.slice(0, 8).map(object).filter((r) => string(r.id) && string(r.id).length <= 256)
    .map((r) => ({ id: string(r.id), action: string(r.action).slice(0, 16), revision: string(r.revision).slice(0, 256) }));
  return out.length ? out : undefined;
}
// Invalid entries are ignored; a settled list is advisory and never approves anything.
function settledList(v: unknown): Reply['settled'] {
  if (!Array.isArray(v)) return undefined;
  return v.slice(0, 256).map(object)
    .filter((x) => string(x.id) && string(x.id).length <= 256 && /^[a-z-]{1,32}$/.test(string(x.state)))
    .map((x) => ({ id: string(x.id), state: string(x.state), rule: string(x.rule).slice(0, 256) }));
}
function requestRuleSource(v: unknown): RequestEvent['request_rule'] {
  const r = object(v);
  return r.available === true && ['running', 'ended', 'unknown'].includes(string(r.process_state)) &&
    Number.isFinite(Date.parse(string(r.until)))
    ? {
        available: true, process_state: string(r.process_state) as 'running' | 'ended' | 'unknown', until: string(r.until),
        process_lease_available: r.process_lease_available === true,
        pid: Number.isSafeInteger(r.pid) && Number(r.pid) > 0 ? Number(r.pid) : undefined,
      }
    : undefined;
}
function askRule(v: unknown): RequestEvent['ask_rule'] {
  const r = object(v);
  return string(r.id) &&
    string(r.id).length <= 256 &&
    Number.isSafeInteger(r.version) &&
    Number(r.version) >= 1
    ? { id: string(r.id), version: Number(r.version) }
    : undefined;
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
  let snapshotRevision: string | undefined;
  if (array(r.capabilities, 64).includes('request-list-snapshot-v1') && r.snapshot_revision === undefined)
    throw Error('Invalid request snapshot metadata');
  if (r.snapshot_revision !== undefined) {
    if (typeof r.snapshot_revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(r.snapshot_revision) || BigInt(r.snapshot_revision) > 18446744073709551615n || !Number.isFinite(Date.parse(string(r.snapshot_at))))
      throw Error('Invalid request snapshot metadata');
    snapshotRevision = r.snapshot_revision;
  }
  const result: Reply = {
    snapshot_revision: snapshotRevision,
    snapshot_at: snapshotRevision ? string(r.snapshot_at) : undefined,
    essential_status: r.essential_status,
    essential_preview: r.essential_preview,
    essential_receipt: r.essential_receipt,
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
    rules: array(r.rules, 8192)
      .map(parseRule)
      .sort((a, b) => a.id.localeCompare(b.id)),
    rule_states: r.rule_states
      ? Object.fromEntries(
          Object.entries(object(r.rule_states))
            .slice(0, 8192)
            .map(([id, value]) => {
              const v = object(value);
              if (
                !['application', 'process', 'zone', 'system'].includes(string(v.target_scope)) ||
                !['active', 'inactive'].includes(string(v.state))
              )
                throw Error('Invalid rule target state');
              return [
                id,
                {
                  target_scope: v.target_scope as RuleTargetState['target_scope'],
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
    observed_usage: r.observed_usage,
    decision_preview: r.decision_preview,
    decision_receipt: r.decision_receipt,
    request_rule_preview: r.request_rule_preview,
    process_leases: parseProcessLeases(r.process_leases),
    settled: settledList(r.settled),
    process_lease: r.process_lease ? parseProcessLeases([r.process_lease])?.[0] : undefined,
    request_ended: r.request_ended === true,
    for_a_while_durations: Array.isArray(r.for_a_while_durations)
      ? r.for_a_while_durations.slice(0, 16).filter((d): d is number => Number.isSafeInteger(d) && (d as number) > 0)
      : undefined,
    replayed: r.replayed === true,
    pair: parsePairResult(r.pair, event),
    decision_record: r.decision_record,
    network_zones: parseNetworkZones(r.network_zones),
    zone_migration: r.zone_migration,
    evaluation: parseEvaluation(r.evaluation),
    protection: parseProtection(r.protection),
    runtime_checks: parseRuntimeChecks(r.runtime_checks),
    build: parseDaemonBuild(r.build),
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
      can_manage_machine_rules: p.can_manage_machine_rules === true,
      role: p.role,
      observation_scope: p.observation_scope,
      policy_scope: p.policy_scope,
      can_manage_rules: p.can_manage_rules,
      can_decide: p.can_decide,
      can_view_measurements: p.can_view_measurements === true,
      can_control_traffic: p.can_control_traffic === true,
      can_control_evaluation: p.can_control_evaluation === true,
      can_control_protection: p.can_control_protection === true,
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
  if (r.zone_preview) {
    const p = object(r.zone_preview),
      network_zones = parseNetworkZones(p.network_zones);
    if (!network_zones || !string(p.token) || !Number.isFinite(Date.parse(string(p.expires_at))))
      throw Error('Invalid zone preview');
    result.zone_preview = {
      token: string(p.token),
      expires_at: string(p.expires_at),
      rule: parseRule(p.rule),
      scope_preview: string(p.scope_preview),
      network_zones,
    };
  }
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
      replaces:
        p.replaces === undefined || p.replaces === null
          ? null
          : (() => {
              const x = object(p.replaces);
              if (!string(x.id) || !Number.isSafeInteger(x.version) || Number(x.version) < 1)
                throw Error('Invalid observed preview replacement');
              return { id: string(x.id), version: Number(x.version) };
            })(),
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
    const tcp = a.tcp_initiation === undefined ? undefined : object(a.tcp_initiation);
    if (
      tcp &&
      !['disabled', 'starting', 'active', 'failed', 'unavailable'].includes(string(tcp.state))
    )
      throw Error('Invalid TCP initiation evidence state');
    result.activity = {
      tcp_initiation: tcp
        ? {
            state: tcp.state as NonNullable<Activity['tcp_initiation']>['state'],
            generation: string(tcp.generation),
            netns: string(tcp.netns),
            reason: string(tcp.reason),
            partial: tcp.partial === true,
            lost_events: number(tcp.lost_events),
            collected: string(tcp.collected),
          }
        : undefined,
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
          runtime_application: row.runtime_application ? (()=> {const r=object(row.runtime_application), evidence=parseRuntimeTable(r.evidence); if(!evidence)throw Error("Invalid runtime evidence");return {application:application(r.application),uid:number(r.uid),evidence};})() : undefined,
          ownership: string(row.ownership),
          ownership_category: string(row.ownership_category),
          display_application: row.display_application
            ? application(row.display_application)
            : undefined,
          owners: array(row.owners, 2048).map(string),
          state: string(row.state),
          direction: string(row.direction),
          network_scope: row.network_scope
            ? (() => {
                const n = object(row.network_scope),
                  state = string(n.state);
                if (
                  !['known', 'unavailable'].includes(state) ||
                  (state === 'known' && !['local', 'internet'].includes(string(n.zone)))
                )
                  throw Error('Invalid network scope');
                return {
                  state: state as 'known' | 'unavailable',
                  zone: state === 'known' ? (n.zone as NetworkZone) : undefined,
                  revision: string(n.revision),
                  source: string(n.source),
                  reason: string(n.reason),
                  basis: n.basis === 'custom' || n.basis === 'automatic' ? n.basis : undefined,
                };
              })()
            : undefined,
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
                  generation: string(i.generation) || undefined,
                  source: string(i.source),
                  reason: string(i.reason),
                  observed_at: string(i.observed_at) || undefined,
                };
              })()
            : undefined,
          evidence: string(row.evidence),
          socket: {
            inode: typeof s.inode === 'number' && Number.isInteger(s.inode) && s.inode >= 0 && s.inode <= 0xffffffff ? s.inode : undefined,
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
    Object.keys(d).some(
      (k) =>
        ![
          'action',
          'generation',
          'id',
          'scope',
          'network_zone',
          'zone_revision',
          'preview_token',
          'remember',
          'duration_seconds',
        ].includes(k),
    ) ||
    !string(d.id) ||
    string(d.id).length > 256 ||
    !string(d.generation) ||
    string(d.generation).length > 256 ||
    !['allow', 'block'].includes(string(d.action)) ||
    !['once', 'application', 'persistent', 'for-a-while'].includes(string(d.scope))
  )
    throw Error('Invalid decision');
  if (
    d.scope === 'for-a-while' &&
    (['network_zone', 'zone_revision', 'preview_token', 'remember'].some((k) => d[k] !== undefined) ||
      (d.duration_seconds !== undefined && !validForAWhileSeconds(d.duration_seconds)))
  )
    throw Error('Invalid For a while decision');
  if (d.scope === 'for-a-while') return d as unknown as Decision;
  const zoned =
    d.network_zone !== undefined || d.zone_revision !== undefined || d.preview_token !== undefined;
  if (
    zoned &&
    (d.scope === 'once' ||
      !['any', 'local', 'internet'].includes(string(d.network_zone)) ||
      !string(d.zone_revision) ||
      string(d.zone_revision).length > 256 ||
      (d.preview_token !== undefined &&
        (!string(d.preview_token) || string(d.preview_token).length > 256)))
  )
    throw Error('Invalid decision network scope');
  if (d.remember !== undefined || d.duration_seconds !== undefined) {
    const r = object(d.remember),
      fields = ['address', 'port', 'protocol', 'process'];
    if (
      !zoned ||
      Object.keys(r).sort().join(',') !== [...fields].sort().join(',') ||
      fields.some((k) => typeof r[k] !== 'boolean') ||
      (d.scope === 'persistent'
        ? d.duration_seconds !== undefined
        : !Number.isSafeInteger(d.duration_seconds) ||
          Number(d.duration_seconds) < 60 ||
          Number(d.duration_seconds) > 31536000)
    )
      throw Error('Invalid remembered decision fields');
  }
  return d as unknown as Decision;
}

export interface RuleFilter {
  interface_index?: number;
  interface_name?: string;
  local_address?: string;
  peer_service?: { application: string; revision: string; uid: number };
  network_zone?: NetworkZone;
  zone_model?: 'automatic-peer-v1';
  all_programs?: boolean;
  all_uids?: boolean;
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
  target_scope: 'application' | 'process' | 'zone' | 'system';
  state: 'active' | 'inactive';
  reason: string;
}
export interface Rule {
  share_with_root?: boolean;
  // Daemon-derived, read-only (never persisted or sent back): this saved
  // application rule also covers updated revisions of the same verified program.
  follows_updates?: boolean;
  root_application?: string;
  invocation?: Invocation;
  preset?: {
    name: 'essential-system-networking';
    component: string;
    entry_id: string;
    revision: string;
    digest: string;
  };
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
export type RuleSource = {
  id?: string;
  event?: string;
  // rule-from-basis-v1: new rule for the identity of an existing stored rule.
  basis?: { rule: string; direction: 'incoming' | 'outgoing'; networkZone?: 'local' | 'internet' };
  observed?: ObservedSource;
  zone?: ZoneSource;
};
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
  // application-policy-v1: the exact canonical rule this preview updates in place, or null.
  replaces?: { id: string; version: number } | null;
}
export interface RulePreview {
  receipt: string;
  preview: string;
  expiresAt?: string;
  verifiedRule?: Rule;
  processID?: string;
  replaces?: { id: string; version: number } | null;
}
export interface RuleEdit {
  share_with_root?: boolean;
  token: string;
  action: RuleAction;
  protocol: string;
  remote_address: string;
  local_port: number;
  remote_port: number;
  priority: number;
  disabled: boolean;
  expiry: 'preserve' | 'hour' | 'permanent';
  network_zone?: NetworkZone | '';
  // 'policy': the canonical whole-target application/process rule (application-policy-v1).
  creation_scope?: 'application' | 'custom' | 'policy';
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
  // Last chosen For a while duration (seconds), validated against the backend set.
  forAWhileSeconds?: number;
}
function ruleFilter(v: unknown): RuleFilter {
  const f = object(v);
  if (f.zone_model !== undefined && f.zone_model !== 'automatic-peer-v1') throw Error('Unsupported immutable zone model');
  const peer = f.peer_service === undefined ? undefined : object(f.peer_service);
  if (
    peer &&
    (!string(peer.application) ||
      !string(peer.revision) ||
      !Number.isSafeInteger(peer.uid) ||
      Number(peer.uid) < 0)
  )
    throw Error('Invalid local service binding');
  if (
    f.interface_index !== undefined &&
    (!Number.isSafeInteger(f.interface_index) || Number(f.interface_index) < 0)
  )
    throw Error('Invalid interface binding');
  return {
    interface_index: f.interface_index === undefined ? undefined : Number(f.interface_index),
    interface_name: f.interface_name === undefined ? undefined : string(f.interface_name),
    local_address: f.local_address === undefined ? undefined : string(f.local_address),
    peer_service: peer
      ? {
          application: string(peer.application),
          revision: string(peer.revision),
          uid: Number(peer.uid),
        }
      : undefined,
    ...(f.zone_model === 'automatic-peer-v1' ? {zone_model: 'automatic-peer-v1' as const} : {}),
    network_zone: ['local', 'internet'].includes(string(f.network_zone))
      ? (f.network_zone as NetworkZone)
      : undefined,
    all_programs: f.all_programs === true || undefined,
    all_uids: f.all_uids === true || undefined,
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
/** Whether a stored rule applies to this revision of its application, per the daemon. */
export const ruleCoversRevision = (rule: Rule, revision: string) =>
  rule.filter.revision === revision || (rule.follows_updates === true && !rule.filter.process);
export function parseRule(v: unknown): Rule {
  const r = object(v),
    filter = ruleFilter(r.filter);
  let preset: Rule['preset'];
  if (number(r.schema) === 5) {
    const rawFilter = object(r.filter);
    if (
      !Number.isSafeInteger(rawFilter.uid) ||
      Number(rawFilter.uid) < 0 ||
      Number(rawFilter.uid) > 4294967295 ||
      !['incoming', 'outgoing'].includes(filter.direction) ||
      !['tcp', 'udp', '*'].includes(filter.protocol) ||
      !['allow', 'block'].includes(string(r.action))
    )
      throw Error('Invalid Essential rule identity or action');
    const p = object(r.preset);
    if (
      p.name !== 'essential-system-networking' ||
      ['component', 'entry_id', 'revision', 'digest'].some(
        (k) => !string(p[k]) || string(p[k]).length > 4096,
      )
    )
      throw Error('Invalid Essential rule metadata');
    const allowed = [
      'application',
      'revision',
      'uid',
      'direction',
      'protocol',
      'remote_address',
      'remote',
      'local_port',
      'remote_port',
      'network_zone',
      'all_programs',
      'all_uids',
      'process',
      'interface_index',
      'interface_name',
      'local_address',
      'peer_service',
    ];
    if (Object.keys(object(r.filter)).some((k) => !allowed.includes(k)) || filter.process)
      throw Error('Unsupported Essential rule scope');
    preset = {
      name: 'essential-system-networking',
      component: string(p.component),
      entry_id: string(p.entry_id),
      revision: string(p.revision),
      digest: string(p.digest),
    };
  } else {
    if (
      (number(r.schema) > 4 && number(r.schema) !== 6) ||
      r.preset !== undefined ||
      filter.peer_service ||
      filter.interface_index !== undefined ||
      filter.interface_name !== undefined ||
      filter.local_address !== undefined ||
      (filter.network_zone && ![4, 6].includes(number(r.schema))) ||
      (number(r.schema) === 6 && (!filter.network_zone || filter.zone_model !== 'automatic-peer-v1')) ||
      (number(r.schema) !== 6 && filter.zone_model !== undefined) ||
      (filter.all_programs && (!filter.network_zone || filter.application || filter.process))
    )
      throw Error('Unsupported zone rule schema');
    if (![4, 6].includes(number(r.schema)) && (number(r.schema) === 3) !== !!filter.process)
      throw Error('Process rule requires schema3 and a complete immutable binding');
  }
  return {
    ...(preset ? { preset } : {}),
    version: ruleVersion(r.version),
    invocation: (() => {
      const i = object(r.invocation);
      return i.mode === 'file' && string(i.name) && string(i.path) && string(i.revision)
        ? { mode: 'file', name: string(i.name).slice(0, 256), path: string(i.path).slice(0, 4096), revision: string(i.revision) } : undefined;
    })(),
    executable: string(r.executable),
    root_application: string(r.root_application) || undefined,
    ...(r.share_with_root === true ? { share_with_root: true } : {}),
    ...(r.follows_updates === true && !preset && !filter.process ? { follows_updates: true } : {}),
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
      .filter((k) => !['creation_scope', 'network_zone', 'share_with_root'].includes(k))
      .sort()
      .join(',') !==
      'action,disabled,expiry,local_port,priority,protocol,remote_address,remote_port,token' ||
    (e.creation_scope !== undefined &&
      !['application', 'custom', 'policy'].includes(String(e.creation_scope))) ||
    (e.network_zone !== undefined && !['', 'local', 'internet'].includes(String(e.network_zone))) ||
    (e.share_with_root !== undefined && typeof e.share_with_root !== 'boolean') ||
    typeof e.token !== 'string' ||
    e.token.length > 128 ||
    !['allow', 'block', 'ask'].includes(String(e.action)) ||
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

function parseRuntimeTable(value: unknown): RuntimeTable | undefined {
 if(value===undefined || value===null)return;
 const r=object(value);
 const holders=array(r.windows_handle_holders,32).map((v)=>{const h=object(v);return {pid:number(h.pid),creation_time:string(h.creation_time).slice(0,32),image:string(h.image).slice(0,4096)};});
 return {runtime:string(r.runtime),prefix:string(r.prefix).slice(0,4096),broker_pid:number(r.broker_pid),broker_start_ticks:string(r.broker_start_ticks),socket_cookie:string(r.socket_cookie),uid:number(r.uid),method:string(r.method).slice(0,1024),windows_handle_holders:holders};
}

// Display/edit witness for a backend-verified Windows socket association.
// The broker generation binds the observation, never the application permission.
export function runtimeWitness(row: SocketRow, processes: Record<string, Process>): string | undefined {
  const r = row.runtime_application;
  if (!r || !row.socket.cookie || r.evidence.socket_cookie !== row.socket.cookie || r.uid !== r.evidence.uid) return;
  return row.owners.find(id => {
    const p = processes[id];
    return p && p.pid === r.evidence.broker_pid && p.start_ticks === r.evidence.broker_start_ticks && p.uid === r.uid;
  });
}
