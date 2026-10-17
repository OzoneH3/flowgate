// Additive v1 API projection. Backend values are data, never renderer markup.
export interface Application {
  key: string;
  revision: string;
  name: string;
  executable: string;
}
export interface Process {
  id: string;
  pid: number;
  start_ticks: string;
  uid: number;
  executable: string;
  application: Application;
}
export interface Traffic {
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
  id: string;
  ownership: string;
  owners: string[];
  state: string;
  direction: string;
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
export interface Reply {
  version: 1;
  generation: string;
  read_only: boolean;
  mode: string;
  server_time: string;
  error: string;
  activity?: Activity;
  events: RequestEvent[];
  decision?: RequestEvent;
  rules: Rule[];
  saved_rule?: Rule;
  scope_preview: string;
  enforcement?: { state: string; detail: string; profile: string; stops_at: string };
}
export interface Attempt {
  phase: 'submitting' | 'acknowledged' | 'rejected' | 'unknown';
  message: string;
}
export interface ViewEvent extends RequestEvent {
  remainingMs: number;
  attempt?: Attempt;
}
export interface ClientState {
  observation: { connected: boolean; message: string; generation: string; activity?: Activity };
  control: {
    connected: boolean;
    message: string;
    generation: string;
    readOnly: boolean;
    mode: string;
    enforcement?: Reply['enforcement'];
    events: ViewEvent[];
    rules?: Rule[];
  };
}
export interface Decision {
  generation: string;
  id: string;
  action: Action;
  scope: Scope;
}
export interface Bridge {
  snapshot(): Promise<ClientState>;
  ruleDraft(source: { id?: string; event?: string }): Promise<RuleDraft>;
  rulePreview(value: RuleEdit): Promise<{ receipt: string; preview: string }>;
  ruleSave(receipt: string): Promise<Attempt>;
  ruleDelete(value: { id: string; generation: string; version: number }): Promise<Attempt>;
  evaluation(action: EvaluationAction, profile?: 'incoming' | 'both'): Promise<void>;
  evaluationState(): Promise<EvaluationState>;
  preferences(value?: Preferences): Promise<Preferences>;
  subscribe(fn: (state: ClientState) => void): () => void;
  decide(value: Decision): Promise<Attempt>;
  openPrompt(id: string): Promise<void>;
  dismissPrompt(): Promise<void>;
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
    events: array(r.events, 256).map(event),
    rules: array(r.rules, 8192).map(parseRule),
    saved_rule: r.saved_rule ? parseRule(r.saved_rule) : undefined,
    scope_preview: string(r.scope_preview),
  };
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
          owners: array(row.owners, 2048).map(string),
          state: string(row.state),
          direction: string(row.direction),
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
}
export type EvaluationAction = 'start' | 'stop' | 'status' | 'recover' | 'cancel';
export interface EvaluationState {
  phase: string;
  message: string;
  generation: string;
  busy: boolean;
  starting: boolean;
}
export interface Preferences {
  sidebar?: number;
  columns?: Record<string, number>;
}
function ruleFilter(v: unknown): RuleFilter {
  const f = object(v);
  return {
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
function parseRule(v: unknown): Rule {
  const r = object(v);
  return {
    version: number(r.version),
    executable: string(r.executable),
    created: string(r.created),
    disabled: r.disabled === true,
    schema: number(r.schema),
    id: string(r.id),
    priority: number(r.priority),
    filter: ruleFilter(r.filter),
    action: string(r.action),
    expires: string(r.expires),
  };
}
export function validateEdit(v: unknown): RuleEdit {
  const e = object(v);
  if (
    Object.keys(e).sort().join(',') !==
      'action,disabled,expiry,local_port,priority,protocol,remote_address,remote_port,token' ||
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
