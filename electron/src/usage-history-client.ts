import { call, type Backend } from './backend';
import {
  HISTORY_CAPABILITY,
  parseHistory,
  parseHistoryQuery,
  parseHistorySettings,
  type HistoryQuery,
  type HistorySnapshot,
} from './usage-history';
export interface HistoryState {
  supported: boolean;
  message: string;
  snapshot?: HistorySnapshot;
  canConfigure: boolean;
  pending: boolean;
}
export class UsageHistoryClient {
  private pending?: { context: string; revision: string; enabled: boolean; days: number };
  constructor(private backend: Backend) {}
  private target() {
    const { control: c, observation: o } = this.backend.view();
    if (this.backend.controller && c.connected && c.capabilities?.includes(HISTORY_CAPABILITY))
      return {
        path: this.backend.controller,
        generation: c.generation,
        role: c.permissions?.role,
        scope: c.permissions?.observation_scope,
        write:
          c.permissions?.role === 'administrator' &&
          !c.readOnly &&
          c.permissions?.can_manage_machine_rules === true,
      };
    if (o.connected && o.capabilities?.includes(HISTORY_CAPABILITY))
      return {
        path: this.backend.observer,
        generation: o.generation,
        role: o.permissions?.role,
        scope: o.permissions?.observation_scope,
        write: false,
      };
  }
  private context() {
    return JSON.stringify(this.target());
  }
  async read(raw: unknown): Promise<HistoryState> {
    const t = this.target(),
      context = this.context();
    if (!t)
      return {
        supported: false,
        message: 'Durable history is unavailable from this daemon.',
        canConfigure: false,
        pending: false,
      };
    try {
      const query = parseHistoryQuery(raw);
      const r = await call(t.path, {
        operation: 'usage-history',
        generation: t.generation,
        history_query: query,
      });
      if (this.context() !== context || r.generation !== t.generation)
        throw Error('History connection or permissions changed; refresh.');
      if (r.error || r.error_code) throw Error(r.error || r.error_code);
      const snapshot = parseHistory(r.usage_history);
      if (
        snapshot.source !== query.source ||
        (snapshot.scope === 'machine' && t.role !== 'administrator')
      )
        throw Error('History scope/source mismatch');
      let message = '';
      if (this.pending?.context === context) {
        const p = this.pending;
        if (
          snapshot.settings.revision === p.revision &&
          snapshot.settings.enabled === p.enabled &&
          snapshot.settings.retention_days === p.days
        ) {
          this.pending = undefined;
          message = 'Settings confirmed by a fresh read.';
        } else if (BigInt(snapshot.settings.revision) >= BigInt(p.revision)) {
          // This CAS can no longer commit against its old revision. The current
          // document is authoritative, but it does not prove our write succeeded.
          this.pending = undefined;
          message =
            'Current settings read; the earlier save was not confirmed. Review before making another change.';
        } else
          message = 'Settings outcome unknown. Refresh to check; the request will not be resent.';
      }
      return {
        supported: true,
        message,
        snapshot,
        canConfigure: t.write && snapshot.state !== 'unavailable',
        pending: this.pending?.context === context,
      };
    } catch (e) {
      return {
        supported: true,
        message: String(e instanceof Error ? e.message : e),
        canConfigure: false,
        pending: this.pending?.context === context,
      };
    }
  }
  async configure(raw: unknown): Promise<HistoryState> {
    const t = this.target(),
      context = this.context();
    if (!t?.write)
      return {
        supported: true,
        message: 'History settings require administrator on the primary endpoint.',
        canConfigure: false,
        pending: false,
      };
    if (this.pending?.context === context)
      return {
        supported: true,
        message: 'Settings outcome unknown; check with Refresh.',
        canConfigure: false,
        pending: true,
      };
    let enabled: boolean, days: number, revision: string;
    try {
      const o = raw as Record<string, unknown>;
      const settings = parseHistorySettings({
        enabled: o.enabled,
        retention_days: o.retention_days,
        revision: o.expected_revision,
      });
      enabled = settings.enabled;
      days = settings.retention_days;
      revision = settings.revision;
    } catch (e) {
      return { supported: true, message: String(e), canConfigure: true, pending: false };
    }
    const expected = (BigInt(revision) + 1n).toString();
    try {
      const r = await call(t.path, {
        operation: 'usage-history-configure',
        generation: t.generation,
        history_options: { enabled, retention_days: days, expected_revision: revision },
      });
      if (this.context() !== context || r.generation !== t.generation)
        throw Error('History connection changed after save');
      if (r.error || r.error_code)
        return {
          supported: true,
          message: r.error || r.error_code || 'History settings refused.',
          canConfigure: this.context() === context,
          pending: false,
        };
      const s = parseHistorySettings(r.history_settings);
      if (s.revision !== expected || s.enabled !== enabled || s.retention_days !== days)
        throw Error('History settings acknowledgement mismatch');
      return {
        supported: true,
        message: 'History settings saved. Refreshing recorded observations…',
        canConfigure: true,
        pending: false,
      };
    } catch (e) {
      this.pending = { context, revision: expected, enabled, days };
      return {
        supported: true,
        message: 'Settings outcome unknown. Refresh to check; no automatic retry.',
        canConfigure: false,
        pending: true,
      };
    }
  }
}
