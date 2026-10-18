import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { call, type Backend } from './backend';
import {
  PROTECTION_CAPABILITY,
  protectionLabel,
  protectionTokens,
  type ProtectionView,
} from './protection-model';
// Continuous protection is independent of bounded evaluation. No subprocess, timer or auto replay.
export class Protection {
  private endpoint = '';
  private recognized = false;
  private inFlight = false;
  private message = '';
  private pending?: { generation: string; after: number; requestId: string; uncertain: boolean };
  constructor(private backend: Backend) {}
  view(): ProtectionView {
    const endpoint = this.backend.controller || this.backend.observer;
    if (endpoint !== this.endpoint) {
      this.endpoint = endpoint;
      this.recognized = false;
      this.pending = undefined;
      this.message = '';
    }
    const { control: c, observation: o } = this.backend.view();
    if (
      c.capabilities?.includes(PROTECTION_CAPABILITY) ||
      o.capabilities?.includes(PROTECTION_CAPABILITY)
    )
      this.recognized = true;
    const source = this.backend.controller ? c : o,
      p = source.connected ? source.protection : undefined;
    if (this.pending && !this.inFlight && c.connected) {
      if (this.pending.generation !== c.generation) {
        this.pending = undefined;
        this.message =
          'Daemon changed; previous action cannot be replayed. Review current protection.';
      } else if ((c.snapshotStarted || 0) > this.pending.after) {
        if (this.pending.uncertain)
          this.message =
            p?.request_id === this.pending.requestId && this.pending.requestId
              ? 'Start reconciled with daemon status; nothing replayed.'
              : 'Status refreshed after uncertain response. No operation replayed; review actual state.';
        this.pending = undefined;
      }
    }
    const busy = this.inFlight || !!this.pending;
    const allowed =
      !!this.backend.controller &&
      c.connected &&
      !c.readOnly &&
      c.permissions?.can_control_protection === true &&
      !!c.capabilities?.includes(PROTECTION_CAPABILITY);
    const evaluationBusy =
      !!c.evaluation?.id &&
      ['starting', 'active', 'stopping', 'degraded'].includes(c.evaluation.state);
    const stopped =
      !!p &&
      ['stopped', 'failed'].includes(p.state) &&
      ['not_needed', 'confirmed'].includes(p.cleanup);
    return {
      supported: this.recognized,
      connected: source.connected,
      status: p,
      busy,
      label: protectionLabel(p, source.connected),
      tokens: p
        ? { generation: source.generation, protectionId: p.id, profile: p.profile }
        : undefined,
      message: [
        !source.connected
          ? 'UI disconnected; daemon protection may still be running.'
          : !p
            ? 'Protection metadata unavailable; no evaluation fallback.'
            : `${p.reason_code}: ${p.reason}`,
        this.message,
        !allowed ? 'Protection control not permitted on this connection.' : '',
      ]
        .filter(Boolean)
        .join(' '),
      canCheck: allowed && !busy && !!p && p.readiness.state !== 'checking',
      canStart: allowed && !busy && !evaluationBusy && stopped && p?.readiness.state === 'ready',
      canStop:
        allowed &&
        !busy &&
        !!p?.id &&
        ['starting', 'active', 'failed', 'degraded'].includes(p.state),
    };
  }
  async action(action: unknown, raw: unknown) {
    if (!['status', 'start', 'stop'].includes(String(action)))
      throw Error('Unknown protection operation');
    const tokens = protectionTokens(raw),
      v = this.view();
    if (
      !v.supported ||
      !v.tokens ||
      tokens.generation !== v.tokens.generation ||
      tokens.protectionId !== v.tokens.protectionId
    )
      throw Error('Protection session changed; review before acting.');
    if (!(action === 'status' ? v.canCheck : action === 'start' ? v.canStart : v.canStop))
      throw Error('Protection operation unavailable, unauthorized or pending.');
    const endpoint = this.backend.controller!;
    const requestId = action === 'start' ? randomBytes(16).toString('hex') : '';
    this.inFlight = true;
    this.message = 'Pending; only daemon status confirms protection.';
    let uncertain = false;
    try {
      const r = await call(endpoint, {
        operation:
          action === 'status'
            ? 'protection-readiness'
            : action === 'start'
              ? 'protection-start'
              : 'protection-stop',
        generation: tokens.generation,
        ...(action !== 'status' ? { protection_id: tokens.protectionId } : {}),
        ...(action !== 'stop' ? { profile: tokens.profile } : {}),
        ...(action === 'start' ? { request_id: requestId } : {}),
      });
      if (
        endpoint !== this.backend.controller ||
        r.generation !== tokens.generation ||
        this.backend.view().control.generation !== tokens.generation
      )
        throw Error('Stale protection response discarded');
      if (r.error || r.error_code)
        this.message = `${r.error_code}: ${r.error}. Review current status.`;
      else if (
        !r.protection ||
        (action === 'start' && r.protection.request_id !== requestId) ||
        (action === 'stop' && r.protection.id !== tokens.protectionId)
      )
        throw Error('Invalid protection acknowledgement');
      else
        this.message = `Backend responded ${r.protection.state}; waiting for actual status. Closing Electron does not stop protection.`;
    } catch (error) {
      uncertain = true;
      this.message = `Outcome uncertain: ${String(error)}. Refresh status; never automatically retry.`;
    } finally {
      this.inFlight = false;
      if (endpoint === this.backend.controller)
        this.pending = {
          generation: tokens.generation,
          after: performance.now(),
          requestId,
          uncertain,
        };
      await this.backend.pollControl();
    }
  }
}
