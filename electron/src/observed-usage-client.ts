import { call, type Backend } from './backend';
import { USAGE_CAPABILITY, parseUsageSnapshot, type UsageSnapshot } from './observed-usage';

export interface UsageState {
  supported: boolean;
  message: string;
  snapshot?: UsageSnapshot;
}

/** Read-only query owner. Observation collection never depends on these UI reads. */
export class ObservedUsageClient {
  private flight?: Promise<UsageState>;
  private last?: { context: string; sequence: bigint };
  constructor(private backend: Backend) {}

  private target() {
    const { control: c, observation: o } = this.backend.view();
    if (this.backend.controller && c.connected && c.capabilities?.includes(USAGE_CAPABILITY))
      return { path: this.backend.controller, generation: c.generation, scope: c.permissions?.observation_scope, role: c.permissions?.role };
    if (o.connected && o.capabilities?.includes(USAGE_CAPABILITY))
      return { path: this.backend.observer, generation: o.generation, scope: o.permissions?.observation_scope, role: o.permissions?.role };
  }

  read(): Promise<UsageState> {
    // Overlapping refreshes share a single bounded backend read.
    if (this.flight) return this.flight;
    this.flight = this.query().finally(() => { this.flight = undefined; });
    return this.flight;
  }

  private async query(): Promise<UsageState> {
    const target = this.target();
    if (!target) return { supported: false, message: 'Observed usage is unavailable from the connected daemon.' };
    try {
      const reply = await call(target.path, { operation: 'observed-usage', generation: target.generation });
      const current = this.target();
      if (!current || current.path !== target.path || current.generation !== target.generation ||
          current.scope !== target.scope || current.role !== target.role || reply.generation !== target.generation)
        throw Error('Daemon connection changed; refresh to read its current observation interval.');
      if (reply.error || reply.error_code) throw Error(reply.error || reply.error_code);
      const snapshot = parseUsageSnapshot(reply.observed_usage);
      if (snapshot.scope === 'machine' && target.role !== 'administrator')
        throw Error('Machine observations require an authenticated administrator view.');
      const context = JSON.stringify([target, snapshot.epoch, snapshot.scope]);
      const sequence = BigInt(snapshot.sequence);
      if (this.last?.context === context && sequence < this.last.sequence)
        throw Error('An older observation was returned; refresh to read current usage.');
      this.last = { context, sequence };
      return { supported: true, message: '', snapshot };
    } catch (error) {
      // Never carry a former principal/epoch's rows into unavailable state.
      return { supported: true, message: error instanceof Error ? error.message : 'Observed usage query failed.' };
    }
  }
}
