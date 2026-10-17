import { call, type Backend } from './backend';
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
  connected: boolean;
  endpointKind: 'controller' | 'companion' | '';
  generation: string;
  enforcement: string;
}
export class DecisionLogClient {
  private store: DecisionLogStore;
  private endpoint = '';
  private visible = false;
  private timer?: NodeJS.Timeout;
  constructor(
    private backend: Backend,
    private interval = 2000,
  ) {
    this.store = new DecisionLogStore((q) => this.request(q));
  }
  private target(): { path: string; kind: 'controller' | 'companion' } | undefined {
    const { control: c, observation: o } = this.backend.view();
    if (this.backend.controller && c.connected && c.capabilities?.includes(DECISION_LOG_CAPABILITY))
      return { path: this.backend.controller, kind: 'controller' };
    if (o.connected && o.capabilities?.includes(DECISION_LOG_CAPABILITY))
      return { path: this.backend.observer, kind: 'companion' };
  }
  private async request(query: Record<string, unknown>) {
    const t = this.target();
    if (!t) throw new LogError('Daemon connection unavailable', 'disconnected');
    const r = await call(t.path, { operation: 'decision-log', decision_query: query });
    if (r.error || r.error_code)
      throw new LogError(r.error || r.error_code, r.error_code || 'error');
    return parsePage(r.decision_log);
  }
  state(): DecisionLogState {
    const { control: c, observation: o } = this.backend.view();
    const t = this.target();
    if (t && t.path !== this.endpoint) {
      // New endpoint: start a fresh query session for the same filter.
      this.endpoint = t.path;
      void this.store.setFilter(this.store.view().filter);
    }
    return {
      ...this.store.view(),
      supported: !!t,
      connected: c.connected || o.connected,
      endpointKind: t?.kind || '',
      generation: (t?.kind === 'controller' ? c.generation : o.generation) || '',
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
    if (!this.target()) return;
    return this.store.tick();
  }
  async setFilter(v: unknown) {
    await this.store.setFilter(validateFilter(v));
    return this.state();
  }
  async older() {
    await this.store.loadOlder();
    return this.state();
  }
  async setLive(v: unknown) {
    if (typeof v !== 'boolean') throw Error('Invalid live-follow value');
    await this.store.setLive(v);
    return this.state();
  }
  // Fresh authoritative copy of one record; falls back to the retained row if the
  // backend no longer has it (e.g. removed by retention) and says so.
  async detail(id: unknown): Promise<{ record?: LogRecord; note: string; unavailable?: boolean }> {
    if (typeof id !== 'string' || !id || id.length > 256) throw Error('Invalid record ID');
    const retained = this.store.get(id);
    const t = this.target();
    if (!t)
      return {
        record: retained,
        note: retained ? 'Shown from loaded page; daemon unavailable.' : '',
      };
    try {
      const r = await call(t.path, { operation: 'decision-log-get', decision_id: id });
      if (r.error || r.error_code)
        return {
          record: retained,
          unavailable: r.error_code === 'not_found',
          note:
            r.error_code === 'not_found'
              ? 'Record unavailable from the daemon; retention or authorization may explain absence. Shown from the loaded page.'
              : `Detail unavailable: ${r.error || r.error_code}`,
        };
      const raw = r.decision_record ?? (r.decision_log as { records?: unknown[] })?.records?.[0];
      return { record: raw ? parseRecord(raw) : retained, note: '' };
    } catch (e) {
      return { record: retained, note: 'Detail request failed: ' + (e as Error).message };
    }
  }
  copyText(id: unknown) {
    const request = logCopyRequest(id);
    const r = this.store.get(request.id);
    if (!r) throw Error('Record not loaded');
    if (request.endpoint) {
      const endpoint = r.flow?.[request.endpoint];
      if (!endpoint) throw Error('Endpoint not recorded');
      return endpoint;
    }
    return JSON.stringify(r, null, 2);
  }
  stop() {
    clearInterval(this.timer);
  }
}
