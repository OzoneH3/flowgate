import { call, type Backend } from './backend';
import type { ClientState, Reply } from './protocol';
import {
  DECISION_LOG_CAPABILITY,
  DecisionLogStore,
  LogError,
  logCopyRequest,
  parsePage,
  parseRecord,
  validateFilter,
  type LogRecord,
  type LogView,
} from './decision-log';
// Main-process owner of decision-log queries. Uses the existing daemon connection:
// the primary controller when it advertises the capability, otherwise the read-only
// companion. Polls only while the Decision Log tab is visible; one request in flight.
export interface DecisionLogState extends LogView {
  supported: boolean;
  outcomeLookup: boolean;
  connected: boolean;
  activityPreview: boolean;
  endpointKind: 'controller' | 'companion' | '';
  generation: string;
  enforcement: string;
}
type LogTarget = {
  path: string;
  kind: 'controller' | 'companion';
  generation: string;
  scope: 'machine' | 'self' | '';
  outcomeLookup: boolean;
};

function logScope(permissions: Reply['permissions']): LogTarget['scope'] {
  return permissions ? (permissions.role === 'administrator' ? 'machine' : 'self') : '';
}

export class DecisionLogClient {
  private store: DecisionLogStore;
  private context = '';
  private visible = false;
  private timer?: NodeJS.Timeout;
  constructor(
    private backend: Backend,
    accessReset?: (revision: number) => void,
    private interval = 2000,
  ) {
    this.store = new DecisionLogStore(
      (q) => this.request(q),
      undefined,
      undefined,
      undefined,
      accessReset,
    );
  }
  private target({ control, observation }: ClientState): LogTarget | undefined {
    const target = (
      path: string,
      kind: LogTarget['kind'],
      source: typeof control | typeof observation,
    ) => ({
      path,
      kind,
      generation: source.generation,
      scope: logScope(source.permissions),
      outcomeLookup: !!source.capabilities?.includes('decision-log-outcome-v1'),
    });
    if (
      this.backend.controller &&
      control.connected &&
      control.capabilities?.includes(DECISION_LOG_CAPABILITY)
    )
      return target(this.backend.controller, 'controller', control);
    if (observation.connected && observation.capabilities?.includes(DECISION_LOG_CAPABILITY))
      return target(this.backend.observer, 'companion', observation);
  }
  private sync(state = this.backend.view()) {
    const target = this.target(state);
    const context = target
      ? JSON.stringify([target.path, target.kind, target.generation, target.scope])
      : '';
    if (context !== this.context) {
      this.context = context;
      this.store.resetAccess();
    }
    return target;
  }
  observe(state: ClientState) {
    const before = this.context;
    if (this.sync(state) && this.context !== before && this.visible) void this.store.tick();
  }
  private revision() {
    this.sync();
    return this.store.view().accessRevision;
  }
  private checkReply(target: LogTarget, revision: number, reply: Reply) {
    if (revision !== this.revision() || reply.generation !== target.generation)
      throw new LogError('Decision Log access changed.', 'access_changed');
  }
  private async request(query: Record<string, unknown>) {
    const target = this.sync();
    if (!target) throw new LogError('Daemon connection unavailable', 'disconnected');
    const revision = this.store.view().accessRevision;
    const reply = await call(target.path, { operation: 'decision-log', decision_query: query });
    this.checkReply(target, revision, reply);
    this.checkScope(target, logScope(reply.permissions));
    if (reply.error || reply.error_code)
      throw new LogError(reply.error || reply.error_code, reply.error_code || 'error');
    const page = parsePage(reply.decision_log);
    this.checkScope(target, page.scope);
    return page;
  }
  private checkScope(target: LogTarget, scope: string) {
    const cachedScope = this.store.view().scope;
    // A reply can report reduced access before the next connection poll does.
    if (scope === 'self' && cachedScope === 'machine') {
      this.store.resetAccess('self');
      throw new LogError('Decision Log access changed.', 'access_changed');
    }
    if (scope === 'machine' && (cachedScope === 'self' || target.scope === 'self'))
      throw new LogError(
        'Decision Log access does not match the current connection.',
        'access_changed',
      );
  }
  state(): DecisionLogState {
    const state = this.backend.view();
    const { control: c, observation: o } = state;
    const t = this.sync(state);
    return {
      ...this.store.view(),
      supported: !!t,
      outcomeLookup: !!t?.outcomeLookup,
      connected: c.connected || o.connected,
      activityPreview: o.connected && !this.backend.controller && !o.protection && !t,
      endpointKind: t?.kind || '',
      generation: t?.generation || '',
      enforcement: c.connected ? c.enforcement?.state || c.mode || '' : '',
    };
  }
  setVisible(v: unknown) {
    this.visible = v === true;
    clearInterval(this.timer);
    if (this.visible) {
      void this.tick();
      this.timer = setInterval(() => void this.tick(), this.interval);
    }
  }
  private tick() {
    if (!this.sync()) return;
    return this.store.tick();
  }
  async setFilter(v: unknown) {
    this.sync();
    await this.store.setFilter(validateFilter(v));
    return this.state();
  }
  async older() {
    this.sync();
    await this.store.loadOlder();
    return this.state();
  }
  async setLive(v: unknown) {
    if (typeof v !== 'boolean') throw Error('Invalid live-follow value');
    this.sync();
    await this.store.setLive(v);
    return this.state();
  }
  async detail(id: unknown): Promise<{ record?: LogRecord; note: string; unavailable?: boolean }> {
    if (typeof id !== 'string' || !id || id.length > 256) throw Error('Invalid record ID');
    const target = this.sync();
    if (!target) return { note: 'Detail unavailable while disconnected.' };
    const revision = this.store.view().accessRevision;
    try {
      const reply = await call(target.path, { operation: 'decision-log-get', decision_id: id });
      this.checkReply(target, revision, reply);
      this.checkScope(target, logScope(reply.permissions));
      if (reply.error || reply.error_code)
        return {
          unavailable: reply.error_code === 'not_found',
          note:
            reply.error_code === 'not_found'
              ? 'Record unavailable.'
              : `Detail unavailable: ${reply.error || reply.error_code}`,
        };
      const raw =
        reply.decision_record ?? (reply.decision_log as { records?: unknown[] })?.records?.[0];
      return { record: raw ? parseRecord(raw) : undefined, note: '' };
    } catch (e) {
      return { note: 'Detail request failed: ' + (e as Error).message };
    }
  }
  async outcome(id: unknown): Promise<{ record?: LogRecord; note: string }> {
    if (typeof id !== 'string' || !id || id.length > 64) throw Error('Invalid record ID');
    const target = this.sync();
    if (!target) return { note: 'Outcome lookup unavailable while disconnected.' };
    if (!target.outcomeLookup) return { note: 'Linked outcomes require a newer daemon.' };
    const revision = this.store.view().accessRevision;
    try {
      const reply = await call(target.path, { operation: 'decision-log-outcome', decision_id: id });
      this.checkReply(target, revision, reply);
      this.checkScope(target, logScope(reply.permissions));
      if (!this.sync()?.outcomeLookup) throw Error('Outcome lookup unavailable');
      if (reply.error_code === 'not_found') return { note: 'No recorded outcome available.' };
      if (reply.error || reply.error_code || !reply.decision_record)
        throw Error(reply.error || reply.error_code || 'Invalid response');
      const record = parseRecord(reply.decision_record);
      if (record.kind !== 'final') throw Error('Invalid outcome record');
      return { record, note: '' };
    } catch (e) {
      return { note: 'Outcome lookup failed: ' + (e as Error).message };
    }
  }
  async copy(id: unknown, write: (text: string) => void) {
    const request = logCopyRequest(id);
    const revision = this.revision();
    const record = request.outcomeOf
      ? (await this.outcome(request.outcomeOf)).record
      : this.store.get(request.id) && (await this.detail(request.id)).record;
    if (revision !== this.revision() || !record || record.id !== request.id)
      throw Error('Record not loaded');
    if (request.endpoint) {
      const endpoint = record.flow?.[request.endpoint];
      if (!endpoint) throw Error('Endpoint not recorded');
      write(endpoint);
    } else {
      write(JSON.stringify(record, null, 2));
    }
  }
  stop() {
    clearInterval(this.timer);
  }
}
