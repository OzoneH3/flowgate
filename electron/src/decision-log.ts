// decision-log-v1 consumer: parsing, bounded paging and presentation labels.
// Pure (no Electron/Node APIs) so main, renderer and tests share it. The backend owns
// capture, persistence, authorization and historical truth; nothing here recomputes
// outcomes, infers direction or substitutes current process identity.
import { parseAttributionReasonCode } from './attribution-reason';
export const DECISION_LOG_CAPABILITY = 'decision-log-v1';

export interface LogApplication {
  key: string;
  name: string;
  kind: string;
  executable: string;
  revision: string;
}
export interface LogRuleSnapshot {
  target_scope?: string;
  id: string;
  version: string;
  action: string;
  priority: number;
  expires: string;
  disabled: boolean;
  filter: unknown;
}
export interface LogRecord {
  id: string;
  sequence: string;
  time: string;
  generation: string;
  mode: string;
  kind: 'pending' | 'final' | 'gap';
  request_id: string;
  flow?: {
    direction: string;
    protocol: string;
    family: string;
    local: string;
    remote: string;
    interface_index?: number;
  };
  application: LogApplication | null;
  principal_uid: number | null;
  attribution?: { status: string; reason: string; reason_code?: string };
  decision?: {
    action: string;
    source: string;
    scope: string | null;
    reason: string;
    rule: LogRuleSnapshot | null;
    matching_rules: string[];
    decided_by_uid: number | null;
  };
  verdict?: { state: string; detail: string };
  delivery: string;
  gap?: { dropped: number; reason: string };
}
export interface LogHealth {
  state: string;
  recording: boolean;
  buffered: number;
  dropped: number;
  write_failures: number;
  last_error: string;
  last_write: string;
  durability_window_ms: number;
  retention: {
    max_records: number;
    max_age_days: number;
    removed?: number;
    removed_through: string;
  };
  counts_withheld: boolean;
  lost_in_failures: number;
  log_id: string;
  oldest: string;
  newest: string;
}
export interface LogPage {
  records: LogRecord[];
  next_before: string;
  newest: string;
  has_more?: boolean;
  log_id: string;
  scope: string;
  health?: LogHealth;
  limitations: string[];
}

const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
const str = (v: unknown, max = 4096) => (typeof v === 'string' ? v.slice(0, max) : '');
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const uid = (v: unknown) => (typeof v === 'number' && Number.isInteger(v) && v >= 0 ? v : null);
const cursor = (v: unknown) => {
  const s = str(v, 32);
  if (s && !/^\d{1,20}$/.test(s)) throw Error('Invalid decision-log cursor');
  return s;
};
export const compareSequence = (a: string, b: string) => {
  const x = BigInt(a),
    y = BigInt(b);
  return x === y ? 0 : x > y ? 1 : -1;
};

export function parseRecord(raw: unknown): LogRecord {
  const r = obj(raw);
  const id = str(r.id, 256),
    sequence = cursor(r.sequence),
    kind = str(r.kind);
  if (!id || !sequence || !['pending', 'final', 'gap'].includes(kind))
    throw Error('Invalid decision-log record');
  const record: LogRecord = {
    id,
    sequence,
    time: str(r.time, 64),
    generation: str(r.generation, 64),
    mode: str(r.mode, 64),
    kind: kind as LogRecord['kind'],
    request_id: str(r.request_id, 256),
    application: null,
    principal_uid: uid(r.principal_uid),
    delivery: str(r.delivery, 64),
  };
  if (kind === 'gap') {
    const g = obj(r.gap);
    record.gap = { dropped: num(g.dropped), reason: str(g.reason) };
    return record;
  }
  const f = obj(r.flow);
  record.flow = {
    direction: str(f.direction, 32),
    protocol: str(f.protocol, 16),
    family: str(f.family, 16),
    local: str(f.local, 128),
    remote: str(f.remote, 128),
    interface_index: typeof f.interface_index === 'number' ? f.interface_index : undefined,
  };
  if (r.application) {
    const a = obj(r.application);
    record.application = {
      key: str(a.key, 512),
      name: str(a.name, 256),
      kind: str(a.kind, 64),
      executable: str(a.executable),
      revision: str(a.revision, 256),
    };
  }
  if (r.attribution) {
    const a = obj(r.attribution);
    record.attribution = { status: str(a.status, 64), reason: str(a.reason), reason_code: parseAttributionReasonCode(a.reason_code) };
  }
  if (r.decision) {
    const d = obj(r.decision);
    let rule: LogRuleSnapshot | null = null;
    if (d.rule) {
      const s = obj(d.rule);
      rule = {
        target_scope: typeof s.target_scope === 'string' ? s.target_scope.slice(0,64) : undefined,
        id: str(s.id, 256),
        version: str(typeof s.version === 'number' ? String(s.version) : s.version, 32),
        action: str(s.action, 32),
        priority: num(s.priority),
        // Zero time means no expiry.
        expires: str(s.expires, 64).startsWith('0001-01-01') ? '' : str(s.expires, 64),
        disabled: s.disabled === true,
        filter: s.filter ?? null,
      };
    }
    record.decision = {
      action: str(d.action, 32),
      source: str(d.source, 64),
      scope: typeof d.scope === 'string' ? d.scope.slice(0, 32) : null,
      reason: str(d.reason),
      rule,
      matching_rules: (Array.isArray(d.matching_rules) ? d.matching_rules : [])
        .slice(0, 64)
        .map((v) => str(v, 256)),
      decided_by_uid: uid(d.decided_by_uid),
    };
  }
  if (r.verdict) {
    const v = obj(r.verdict);
    record.verdict = { state: str(v.state, 64), detail: str(v.detail) };
  }
  return record;
}

export function parseHealth(raw: unknown): LogHealth | undefined {
  if (!raw) return undefined;
  const h = obj(raw),
    retention = obj(h.retention);
  return {
    state: str(h.state, 32),
    recording: h.recording === true,
    buffered: num(h.buffered),
    dropped: num(h.dropped),
    write_failures: num(h.write_failures),
    last_error: str(h.last_error),
    last_write: str(h.last_write, 64),
    durability_window_ms: num(h.durability_window_ms),
    counts_withheld: h.counts_withheld === true,
    lost_in_failures: num(h.lost_in_failures),
    log_id: str(h.log_id, 128),
    retention: {
      max_records: num(retention.max_records),
      max_age_days: num(retention.max_age_days),
      removed: typeof retention.removed === 'number' ? retention.removed : undefined,
      removed_through: cursor(retention.removed_through),
    },
    oldest: cursor(h.oldest),
    newest: cursor(h.newest),
  };
}

export function parsePage(raw: unknown): LogPage {
  const p = obj(raw);
  if (!Array.isArray(p.records) || p.records.length > 100) throw Error('Invalid decision-log page');
  if (p.scope !== 'machine' && p.scope !== 'self') throw Error('Invalid decision-log scope');
  return {
    records: p.records.map(parseRecord),
    next_before: cursor(p.next_before),
    newest: cursor(p.newest),
    has_more: typeof p.has_more === 'boolean' ? p.has_more : undefined,
    log_id: str(p.log_id ?? obj(p.health).log_id, 128),
    scope: p.scope,
    health: parseHealth(p.health),
    limitations: (Array.isArray(p.limitations) ? p.limitations : [])
      .slice(0, 16)
      .map((v) => str(v, 512)),
  };
}

// Only filters the backend implements server-side.
export interface LogFilter {
  since?: string;
  until?: string;
  direction?: 'incoming' | 'outgoing';
  action?: 'allow' | 'block' | 'pending';
  source?: string;
  application?: { key: string; name: string };
}
export const LOG_SOURCES = [
  'rule',
  'user',
  'timeout',
  'attribution',
  'capacity',
  'policy_change',
  'identity_changed',
  'default_ask',
  'rule_edit',
  'shutdown',
];
export function validateFilter(v: unknown): LogFilter {
  const f = obj(v),
    out: LogFilter = {};
  for (const k of Object.keys(f))
    if (!['since', 'until', 'direction', 'action', 'source', 'application'].includes(k))
      throw Error('Invalid decision-log filter');
  for (const k of ['since', 'until'] as const)
    if (f[k] !== undefined) {
      if (typeof f[k] !== 'string' || !Number.isFinite(Date.parse(f[k] as string)))
        throw Error('Invalid time range');
      out[k] = new Date(f[k] as string).toISOString();
    }
  if (f.direction !== undefined) {
    if (!['incoming', 'outgoing'].includes(f.direction as string)) throw Error('Invalid direction');
    out.direction = f.direction as LogFilter['direction'];
  }
  if (f.action !== undefined) {
    if (!['allow', 'block', 'pending'].includes(f.action as string)) throw Error('Invalid action');
    out.action = f.action as LogFilter['action'];
  }
  if (f.source !== undefined) {
    if (!LOG_SOURCES.includes(f.source as string)) throw Error('Invalid source');
    out.source = f.source as string;
  }
  if (f.application !== undefined) {
    const a = obj(f.application);
    if (typeof a.key !== 'string' || !a.key || a.key.length > 512)
      throw Error('Invalid application');
    out.application = { key: a.key, name: str(a.name, 256) };
  }
  return out;
}
export const filterQuery = (f: LogFilter) => ({
  ...(f.since ? { since: f.since } : {}),
  ...(f.until ? { until: f.until } : {}),
  ...(f.direction ? { direction: f.direction } : {}),
  ...(f.action ? { action: f.action } : {}),
  ...(f.source ? { source: f.source } : {}),
  ...(f.application ? { application: f.application.key } : {}),
});
export const isFiltered = (f: LogFilter) => Object.keys(filterQuery(f)).length > 0;

export type LogRequest = (query: Record<string, unknown>) => Promise<LogPage>;
export class LogError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
  }
}
export interface LogView {
  session: number;
  accessRevision: number;
  status: 'idle' | 'loading' | 'ready' | 'disconnected' | 'error';
  error?: { code: string; message: string };
  records: LogRecord[];
  health?: LogHealth;
  scope: string;
  limitations: string[];
  live: boolean;
  newAvailable: boolean;
  hasOlder: boolean;
  busy: boolean;
  retainedLimit: boolean;
  filter: LogFilter;
  filtered: boolean;
  notice: string;
}

// One query session per filter. Responses carry their session and are dropped when stale.
// Rows are deduplicated by stable ID, ordered by backend sequence and bounded.
export class DecisionLogStore {
  private session = 0;
  private accessRevision = 0;
  private records = new Map<string, LogRecord>();
  private order: LogRecord[] = [];
  private nextBefore = '';
  private newest = '';
  private logId = '';
  private filter: LogFilter = {};
  private inFlight = false;
  private runToken = 0;
  private state: Pick<LogView, 'status' | 'error' | 'health' | 'scope' | 'limitations'> = {
    status: 'idle',
    scope: '',
    limitations: [],
  };
  private live = true;
  private newAvailable = false;
  private retainedLimit = false;
  private notice = '';
  constructor(
    private request: LogRequest,
    private maxRows = 1000,
    private pageSize = 100,
    private catchUpPages = 5,
    private accessReset?: (revision: number) => void,
  ) {}
  view(): LogView {
    return {
      session: this.session,
      accessRevision: this.accessRevision,
      ...this.state,
      records: this.order,
      live: this.live,
      newAvailable: this.newAvailable,
      hasOlder: !!this.nextBefore && !this.retainedLimit,
      busy: this.inFlight,
      retainedLimit: this.retainedLimit,
      filter: this.filter,
      filtered: isFiltered(this.filter),
      notice: this.notice,
    };
  }
  get(id: string) {
    return this.records.get(id);
  }
  resetAccess(scope = '') {
    this.logId = '';
    this.reset({});
    this.state = { status: 'loading', scope, limitations: [] };
    this.inFlight = false;
    this.runToken++;
    this.accessRevision++;
    this.accessReset?.(this.accessRevision);
  }
  private reset(filter: LogFilter, notice = '') {
    this.session++;
    this.filter = filter;
    this.records.clear();
    this.order = [];
    this.nextBefore = '';
    this.newest = '';
    this.newAvailable = false;
    this.retainedLimit = false;
    this.notice = notice;
    this.state = { ...this.state, status: 'loading', error: undefined };
  }
  setFilter(filter: LogFilter) {
    this.reset(filter);
    this.inFlight = false;
    this.runToken++;
    return this.tick();
  }
  disconnected(message: string) {
    // Retain already-loaded historical rows; they remain backend-recorded history.
    this.state = {
      ...this.state,
      status: 'disconnected',
      error: { code: 'disconnected', message },
    };
  }
  private merge(records: LogRecord[]) {
    let added = 0;
    for (const r of records)
      if (!this.records.has(r.id)) {
        this.records.set(r.id, r);
        added++;
      }
    if (!added) return 0;
    this.order = [...this.records.values()].sort((a, b) => compareSequence(b.sequence, a.sequence));
    if (this.order.length > this.maxRows) {
      for (const r of this.order.slice(this.maxRows)) this.records.delete(r.id);
      this.order = this.order.slice(0, this.maxRows);
      this.nextBefore = this.order.at(-1)!.sequence;
    }
    const top = this.order[0]?.sequence;
    if (top && (!this.newest || compareSequence(top, this.newest) > 0)) this.newest = top;
    return added;
  }
  private apply(page: LogPage) {
    if (this.state.scope && page.scope !== this.state.scope) {
      // The page may use a cursor from a different visibility scope.
      this.resetAccess(page.scope);
      return false;
    }
    if (page.log_id && this.logId && page.log_id !== this.logId) {
      // A different/recreated log: cursors are meaningless; restart without mixing sequences.
      this.logId = page.log_id;
      this.reset(this.filter, 'The decision log was replaced; the view restarted.');
      return false;
    }
    if (page.log_id) this.logId = page.log_id;
    this.state = {
      status: 'ready',
      health: page.health,
      scope: page.scope,
      limitations: page.limitations,
    };
    return true;
  }
  private async run(fn: (session: number) => Promise<void>) {
    if (this.inFlight) return;
    this.inFlight = true;
    // Internal restarts change the session but not the run; setFilter abandons the run.
    const token = ++this.runToken,
      session = this.session;
    try {
      await fn(session);
    } catch (e) {
      if (session !== this.session) return;
      const code = e instanceof LogError ? e.code : 'disconnected';
      if (code === 'invalid_cursor') {
        this.reset(this.filter, 'Saved position is no longer valid; the view restarted.');
        return;
      }
      if (code === 'disconnected') this.disconnected((e as Error).message);
      else
        this.state = {
          ...this.state,
          status: 'error',
          error: { code, message: (e as Error).message },
        };
    } finally {
      if (token === this.runToken) this.inFlight = false;
    }
  }
  private query(extra: Record<string, unknown>) {
    // Cursor requests carry log_id so the backend rejects cursors from a replaced log.
    const scoped = (extra.before || extra.after) && this.logId ? { log_id: this.logId } : {};
    return this.request({ limit: this.pageSize, ...filterQuery(this.filter), ...scoped, ...extra });
  }
  // Periodic refresh: initial page, live catch-up, or (paused) new-record detection only.
  tick() {
    return this.run(async (session) => {
      if (!this.order.length && this.state.status !== 'ready') {
        const page = await this.query({});
        if (session !== this.session || !this.apply(page)) return;
        this.merge(page.records);
        this.nextBefore = page.next_before;
        return;
      }
      if (!this.live) {
        const page = await this.query({ limit: 1 });
        if (session !== this.session || !this.apply(page)) return;
        const top = page.records[0]?.sequence;
        this.newAvailable = !!top && (!this.newest || compareSequence(top, this.newest) > 0);
        return;
      }
      await this.catchUp(session);
    });
  }
  private async catchUp(session: number) {
    if (!this.newest) {
      const page = await this.query({});
      if (session !== this.session || !this.apply(page)) return;
      this.merge(page.records);
      this.nextBefore ||= page.next_before;
      return;
    }
    for (let i = 0; i < this.catchUpPages; i++) {
      const page = await this.query({ after: this.newest });
      if (session !== this.session || !this.apply(page)) return;
      this.merge(page.records);
      const more = page.has_more ?? page.records.length === this.pageSize;
      if (!more) {
        this.newAvailable = false;
        return;
      }
    }
    // Too far behind to follow page by page: restart at the newest page instead of
    // pretending the intervening records were displayed.
    this.reset(
      this.filter,
      'Many new records arrived; showing the newest. Older ones remain available below.',
    );
    const restartedSession = this.session;
    const page = await this.query({});
    if (restartedSession !== this.session || !this.apply(page)) return;
    this.merge(page.records);
    this.nextBefore = page.next_before;
  }
  loadOlder() {
    return this.run(async (session) => {
      if (!this.nextBefore || this.retainedLimit) return;
      if (this.order.length >= this.maxRows) {
        this.retainedLimit = true;
        return;
      }
      const page = await this.query({ before: this.nextBefore });
      if (session !== this.session || !this.apply(page)) return;
      this.merge(page.records);
      this.nextBefore = page.next_before;
      if (this.order.length >= this.maxRows && this.nextBefore) this.retainedLimit = true;
    });
  }
  setLive(live: boolean) {
    this.live = live;
    if (live) return this.tick();
  }
}

// Presentation labels. Allow is a policy decision plus a kernel verdict submission, never
// proof of delivery.
const SOURCE_LABELS: Record<string, string> = {
  rule: 'Rule',
  user: 'User decision',
  timeout: 'No answer (timeout)',
  attribution: 'Attribution failure',
  capacity: 'Capacity limit',
  policy_change: 'Policy change',
  identity_changed: 'Identity changed',
  default_ask: 'Default: ask',
  rule_edit: 'Rule saved while pending',
  shutdown: 'Daemon stopped while pending',
};
export const sourceLabel = (s: string) => SOURCE_LABELS[s] || s || '—';
export function outcomeLabel(r: LogRecord) {
  if (r.kind === 'gap') return 'Records lost';
  if (r.kind === 'pending') return 'Pending record';
  const a = r.decision?.action;
  return a === 'allow' ? 'Allowed' : a === 'block' ? 'Blocked' : a || 'Unknown';
}
export function scopeLabel(s: string | null | undefined) {
  if (!s) return '';
  return (
    {
      once: 'Once',
      application: 'Remembered for application',
      persistent: 'Remembered (saved rule)',
    }[s] || s
  );
}
const VERDICTS: Record<string, string> = {
  accept_submitted: 'Accept verdict submitted to kernel',
  drop_submitted: 'Drop verdict submitted to kernel',
  submission_failed: 'Verdict submission failed',
  held: 'Packets held awaiting an answer',
  deferred: 'Verdict deferred',
  none: 'No kernel verdict',
};
export const verdictLabel = (s: string | undefined) => (s ? VERDICTS[s] || s : '—');
export const directionLabel = (d: string | undefined) =>
  d === 'incoming' ? 'Incoming' : d === 'outgoing' ? 'Outgoing' : d || '—';
export function reasonSummary(r: LogRecord) {
  if (r.kind === 'gap') return r.gap?.reason || 'Records were not recorded';
  const d = r.decision;
  if (!d) return '—';
  const parts = [sourceLabel(d.source)];
  if (d.scope) parts.push(scopeLabel(d.scope));
  if (d.rule) parts.push(`rule v${d.rule.version}`);
  if (r.verdict?.state === 'submission_failed') parts.push('verdict failed');
  return parts.join(' · ');
}
export function healthSummary(h: LogHealth | undefined) {
  if (!h) return { level: 'unknown', text: 'Logging health not reported' };
  const notes: string[] = [];
  if (h.counts_withheld) notes.push('loss counters withheld on this connection');
  if (h.dropped) notes.push(`${h.dropped} records dropped`);
  if (h.lost_in_failures) notes.push(`${h.lost_in_failures} lost in write failures`);
  if (h.write_failures) notes.push(`${h.write_failures} write failures`);
  if (h.last_error) notes.push(h.last_error);
  const level =
    h.state === 'ok' && h.recording && !h.dropped && !h.write_failures && !h.lost_in_failures
      ? 'ok'
      : h.state === 'unavailable'
        ? 'error'
        : 'warning';
  const head =
    h.state === 'ok'
      ? h.recording
        ? 'Recording'
        : 'Not recording'
      : h.state === 'read_only'
        ? 'History read-only (not recording)'
        : h.state === 'degraded'
          ? 'Logging degraded'
          : h.state === 'unavailable'
            ? 'Log unavailable'
            : h.state;
  const retention = h.retention.max_records
    ? `retention ${h.retention.max_records.toLocaleString('en-US')} records / ${h.retention.max_age_days} days`
    : '';
  const removed = h.retention.removed
    ? `${h.retention.removed} older records removed by retention`
    : '';
  return { level, text: [head, ...notes, removed, retention].filter(Boolean).join(' · ') };
}

export function logCopyRequest(value: unknown): { id: string; endpoint?: 'local' | 'remote'; outcomeOf?: string } {
  const v = typeof value === 'string' ? { id: value } : obj(value);
  if (
    typeof v.id !== 'string' ||
    !v.id ||
    v.id.length > 256 ||
    Object.keys(v).some((k) => !['id', 'endpoint', 'outcomeOf'].includes(k)) ||
    (v.outcomeOf !== undefined && (typeof v.outcomeOf !== 'string' || !v.outcomeOf || v.outcomeOf.length > 64)) ||
    (v.endpoint !== undefined && v.endpoint !== 'local' && v.endpoint !== 'remote')
  )
    throw Error('Invalid log copy request');
  return { id: v.id, endpoint: v.endpoint as 'local' | 'remote' | undefined, ...(v.outcomeOf ? { outcomeOf: v.outcomeOf as string } : {}) };
}
