import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { call, type Backend } from './backend';
import { EVALUATION_CAPABILITY, evaluationTokens, evaluationLabel } from './evaluation-model';
import type { EvaluationState } from './protocol';
// No subprocess or timer. Reads existing backend polling and sends fixed operations.
export class DaemonEvaluation {
  private endpoint = '';
  private recognized = false;
  private inFlight = false;
  private pending?: { generation: string; after: number; requestId: string; uncertain: boolean };
  private message = '';
  constructor(private backend: Backend) {}
  supported() {
    const endpoint = this.backend.controller || this.backend.observer;
    if (endpoint !== this.endpoint) {
      this.endpoint = endpoint;
      this.recognized = false;
      this.pending = undefined;
      this.message = '';
    }
    const { control: c, observation: o } = this.backend.view();
    if (
      c.capabilities?.includes(EVALUATION_CAPABILITY) ||
      o.capabilities?.includes(EVALUATION_CAPABILITY)
    )
      this.recognized = true;
    return this.recognized;
  }
  view(): EvaluationState {
    this.supported();
    const { control: c, observation: o } = this.backend.view();
    const primary = !!this.backend.controller;
    const source = primary ? c : o;
    const e = source.connected ? source.evaluation : undefined;
    if (this.pending && !this.inFlight && c.connected) {
      if (this.pending.generation !== c.generation) {
        this.message =
          'Daemon generation changed. Previous operation outcome discarded; review this session again.';
        this.pending = undefined;
      } else if ((c.snapshotStarted || 0) > this.pending.after) {
        if (this.pending.uncertain)
          this.message =
            e?.request_id === this.pending.requestId && this.pending.requestId
              ? 'Uncertain Start reconciled with the daemon session. No request was replayed.'
              : 'Status refreshed after uncertain response. No operation was replayed; review current state before another action.';
        this.pending = undefined;
      }
    }
    const busy = this.inFlight || !!this.pending;
    const canControl =
      primary &&
      c.connected &&
      !c.readOnly &&
      c.permissions?.can_control_evaluation === true &&
      !!c.capabilities?.includes(EVALUATION_CAPABILITY);
    const remainingMs = e ? Date.parse(e.stops_at) - this.backend.now() : NaN;
    const continuousBusy =
      !!c.protection &&
      (c.protection.desired_mode !== 'monitoring' ||
        ['starting', 'active', 'stopping', 'degraded'].includes(c.protection.state));
    const safeStopped =
      e &&
      ['stopped', 'failed'].includes(e.state) &&
      ['confirmed', 'not_needed'].includes(e.cleanup);
    return {
      mode: 'daemon',
      phase: source.connected ? e?.state || 'unknown' : 'unknown',
      generation: source.generation,
      busy,
      starting: e?.state === 'starting',
      message: [
        !source.connected
          ? 'Daemon disconnected; enforcement state unknown.'
          : !e
            ? 'Evaluation metadata unavailable; no legacy fallback.'
            : `${e.reason_code}: ${e.reason}`,
        this.message,
        source.connected && e && !e.review ? 'Backend review unavailable; Start disabled.' : '',
        !canControl
          ? 'This connection cannot control evaluation; rule and collector permissions are separate.'
          : '',
        'Closing FlowGate leaves the bounded daemon evaluation running.',
      ]
        .filter(Boolean)
        .join(' '),
      label: source.connected
        ? evaluationLabel(e, remainingMs)
        : 'Firewall · disconnected / unknown',
      status: e,
      remainingMs: Number.isFinite(remainingMs) ? remainingMs : undefined,
      tokens: e ? { generation: source.generation, evaluationId: e.id } : undefined,
      canCheck:
        source.connected &&
        !!source.capabilities?.includes(EVALUATION_CAPABILITY) &&
        !busy &&
        e?.readiness.state !== 'checking',
      canStart: !!(
        canControl &&
        !busy &&
        safeStopped &&
        !continuousBusy &&
        e?.readiness.state === 'ready' &&
        e.review.trim()
      ),
      canStop: !!(
        canControl &&
        !busy &&
        e &&
        e.id &&
        ['starting', 'active', 'failed', 'degraded'].includes(e.state)
      ),
    };
  }
  async action(action: unknown, rawTokens: unknown) {
    try {
      return await this.perform(action, rawTokens);
    } catch (error) {
      this.message = String(error);
      throw error;
    }
  }
  private async perform(action: unknown, rawTokens: unknown) {
    if (!['status', 'start', 'stop'].includes(String(action)))
      throw Error('Unsupported daemon evaluation operation');
    const tokens = evaluationTokens(rawTokens),
      v = this.view();
    if (
      !v.tokens ||
      tokens.generation !== v.tokens.generation ||
      tokens.evaluationId !== v.tokens.evaluationId
    )
      throw Error('Evaluation session changed. Refresh and review before submitting.');
    if (!(action === 'status' ? v.canCheck : action === 'start' ? v.canStart : v.canStop))
      throw Error('Evaluation operation unavailable, unauthorized or pending. Refresh status.');
    const endpoint = this.backend.controller || this.backend.observer;
    const requestId = action === 'start' ? randomBytes(16).toString('hex') : '';
    this.inFlight = true;
    this.message = 'Request pending; only daemon status confirms readiness, activation or cleanup.';
    let uncertain = false;
    try {
      const r = await call(endpoint, {
        operation:
          action === 'status'
            ? 'evaluation-readiness'
            : action === 'start'
              ? 'evaluation-start'
              : 'evaluation-stop',
        generation: tokens.generation,
        ...(action === 'status' ? { profile: 'incoming' } : { evaluation_id: tokens.evaluationId }),
        ...(action === 'start' ? { profile: 'incoming', request_id: requestId } : {}),
      });
      const current = this.backend.view();
      const generation = this.backend.controller
        ? current.control.generation
        : current.observation.generation;
      if (
        endpoint !== (this.backend.controller || this.backend.observer) ||
        generation !== tokens.generation ||
        r.generation !== tokens.generation
      )
        throw Error('Stale lifecycle response discarded');
      if (r.error || r.error_code)
        this.message = `${r.error_code}: ${r.error}. Refresh and review before another action.`;
      else if (
        !r.evaluation ||
        (action === 'start' && r.evaluation.request_id !== requestId) ||
        (action === 'stop' && r.evaluation.id !== tokens.evaluationId)
      )
        throw Error('Invalid evaluation acknowledgement');
      else
        this.message = `Backend responded ${r.evaluation.state}; awaiting authoritative status. No deadline renewal.`;
    } catch (e) {
      uncertain = true;
      this.message = `Outcome uncertain: ${String(e)}. Refreshing status; never automatically retrying.`;
    } finally {
      this.inFlight = false;
      if (endpoint === (this.backend.controller || this.backend.observer))
        this.pending = {
          generation: tokens.generation,
          after: performance.now(),
          requestId,
          uncertain,
        };
      if (this.backend.controller) await this.backend.pollControl();
      else {
        await this.backend.pollObserver();
        this.pending = undefined;
      }
    }
  }
}
