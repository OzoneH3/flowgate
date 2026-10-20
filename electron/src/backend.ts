import { eventLabel, pushResult, type PermissionResult } from './permission-results';
import { inventoryStamp } from './inventory-coherence';
import {
  REMEMBER_ZONE_CAPABILITY,
  REMEMBER_FIELDS_CAPABILITY,
  parseDecisionPreview,
  agreesWithDecision,
  sameRememberedRule,
  terminalReviewFailure,
  freshApplicationRuleSource,
  reviewFailureOf,
  type DecisionReviewFailure,
  type DecisionPreview,
} from './decision-remember';
import { POLICY_CAPABILITY } from './policy';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import {
  parseReply,
  canDecide,
  validateDecision,
  type Reply,
  type ClientState,
  type Decision,
  type Attempt,
  type RequestEvent,
  type Rule,
  canManageRules,
} from './protocol';
import {
  parseRequestRulePreview,
  requestRuleAvailable,
  requestRuleKey,
  validateRequestRule,
  type RequestRuleChoice,
  type RequestRulePreview,
} from './request-rule';
import { forAWhileDurations, forAWhileSupported, type ProcessLease } from './process-lease';
import { endedLeaseAvailable, validateEndedLease, type EndedLeaseChoice } from './prompt-decision';
import { LOCAL_PAIR_CAPABILITY, pairResultText, validatePairChoice, type PairChoice, type PairResult } from './local-pair';
export function call(path: string, request: object, timeoutMs = 3500): Promise<Reply> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 20000)
    throw Error('Invalid backend timeout');
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path });
    let chunks: Buffer[] = [];
    let size = 0;
    let finished = false;
    const done = (error?: Error, value?: Reply) => {
      if (finished) return;
      finished = true;
      if (deadline) clearTimeout(deadline);
      socket.destroy();
      error ? reject(error) : resolve(value!);
    };
    // Longer discovery requests also have an absolute bound, not just idle timeout.
    const deadline =
      timeoutMs === 3500
        ? undefined
        : setTimeout(() => done(Error('Backend timed out')), timeoutMs);
    socket.setTimeout(timeoutMs, () => done(Error('Backend timed out')));
    socket.on('error', (e) => done(e));
    socket.on('end', () => done(Error('Backend closed without acknowledgement')));
    socket.on('connect', () => socket.write(JSON.stringify({ version: 1, ...request }) + '\n'));
    socket.on('data', (dataChunk) => {
      const chunk = Buffer.isBuffer(dataChunk) ? dataChunk : Buffer.from(dataChunk);
      size += chunk.length;
      if (size > 4 * 1024 * 1024) return done(Error('Backend response exceeds 4 MiB'));
      chunks.push(chunk);
      if (chunk.includes(10)) {
        try {
          const data = Buffer.concat(chunks);
          done(
            undefined,
            parseReply(JSON.parse(data.subarray(0, data.indexOf(10)).toString('utf8'))),
          );
        } catch (e) {
          done(e as Error);
        }
      }
    });
  });
}
// A backend refusal that decided nothing (the request stays answerable).
class DecisionRefused extends Error {}

// Queue reconciliation (queue-reconcile-v1). A request acknowledged as decided,
// or reported settled by an acknowledged operation, is remembered per
// (generation, id) with the sequence number of the last list request issued
// before that acknowledgement arrived. A list issued at or before that number
// (a stale poll or reconnect read already in flight) can never reopen it. Only
// a list issued AFTER the acknowledgement whose server_time is not earlier
// than the acknowledgement's, and which still shows the request awaiting, is
// a newer authoritative observation: then the backend wins and it reopens.
// Other requests are never removed by guessing (application, endpoint): only
// non-awaiting list states or explicit `settled` ids remove them.
export interface Settlement {
  issued: number;
  serverTime: number;
  state: string;
  event?: RequestEvent;
  until: number;
}
export const settlementKey = (generation: string, id: string) => generation + '\0' + id;
export function reconcileListed(
  events: RequestEvent[],
  generation: string,
  issued: number,
  serverTime: number,
  settled: Map<string, Settlement>,
): RequestEvent[] {
  return events.map((e) => {
    const key = settlementKey(generation, e.id),
      t = settled.get(key);
    if (!t || e.state !== 'awaiting-decision') return e;
    if (issued > t.issued && serverTime >= t.serverTime) {
      settled.delete(key); // newer authoritative observation: the backend wins
      return e;
    }
    return t.event ?? { ...e, state: t.state, reason: `Settled (${t.state}) by an acknowledged operation; awaiting the next list` };
  });
}
export class Backend {
  state: ClientState = {
    observation: { connected: false, message: 'Activity connecting · read-only', generation: '' },
    control: {
      connected: false,
      message: 'No controller attached · enforcement state unknown',
      generation: '',
      readOnly: true,
      mode: '',
      events: [],
    },
  };
  private reply?: Reply;
  private received = 0;
  private attempts = new Map<string, Attempt>();
  private reviewFailures = new Map<string, {
    generation: string; event: RequestEvent; failure: DecisionReviewFailure; until: number;
  }>();
  // Queue reconciliation state (see reconcileListed).
  private settlements = new Map<string, Settlement>();
  private listIssued = 0;
  private reconcileAfter?: number;
  private endedLeases = new Map<string, { message: string; lease: ProcessLease }>();
  // Ended requests whose future rule was saved: they leave Pending requests.
  private closedEnded = new Set<string>();
  private results: PermissionResult[] = [];
  private resultSeq = 0;
  private endedLeaseFlight = new Set<string>();
  private busy = { observer: false, control: false };
  private timers: NodeJS.Timeout[] = [];
  private stopped = false;
  private publication = 0;
  private policyBusy = false;
  private policyEpoch = 0;
  private policySequence = -1n;
  private policyStamp = '';
  private policyEndpoint = '';
  private policyLast = -Infinity;
  constructor(
    readonly observer: string,
    public controller: string | undefined,
    private changed: (state: ClientState, clockOnly?: boolean) => void,
  ) {}
  start() {
    void this.pollObserver();
    void this.pollControl();
    this.timers.push(
      setInterval(() => void this.pollObserver(), 1000),
      setInterval(() => void this.pollControl(), 750),
      setInterval(() => this.emit(true), 250),
    );
  }
  stop() {
    this.stopped = true;
    for (const t of this.timers) clearInterval(t);
  }
  now() {
    return this.reply
      ? Date.parse(this.reply.server_time) + (performance.now() - this.received)
      : Date.now();
  }
  view(): ClientState {
    for (const [id, failure] of this.reviewFailures)
      if (failure.generation !== this.state.control.generation || this.now() >= failure.until)
        this.reviewFailures.delete(id);
    const generation = this.state.control.generation;
    const events = (this.reply?.events ?? []).filter(
      (e) => e.state === 'awaiting-decision' && !this.reviewFailures.has(e.id) ? true : !this.closedEnded.has(settlementKey(generation, e.id)),
    );
    for (const [id, failure] of this.reviewFailures)
      if (!events.some(e => e.id === id) && !this.closedEnded.has(settlementKey(generation, id))) events.push(failure.event);
    return {
      ...this.state,
      publication: this.publication,
      control: {
        ...this.state.control,
        serverNow: this.now(),
        policy:
          this.state.control.policy?.snapshot.valid_until &&
          Date.parse(this.state.control.policy.snapshot.valid_until) <= this.now()
            ? undefined
            : this.state.control.policy,
        reconciling: this.reconcileAfter !== undefined,
        permissionResults: [...this.results],
        events: events.map((e) => ({
          ...e,
          remainingMs: Math.max(0, Date.parse(e.deadline) - this.now()),
          attempt: this.attempts.get(e.id),
          reviewFailure: this.reviewFailures.get(e.id)?.failure,
        })),
      },
    };
  }
  private emit(clockOnly = false) {
    if (!this.stopped) {
      this.publication++;
      this.changed(this.view(), clockOnly);
    }
  }
  private mutationEpoch = 0;
  private controlFlight?: Promise<void>;
  private controlEpoch = -1;
  private pendingInventory?: Reply;
  private pendingPair?: {
    reply: Reply;
    policy: NonNullable<Reply['policy_view']>;
    epoch: number;
    stamp: string;
  };
  async ruleMutation<T>(run: () => Promise<T>): Promise<T> {
    this.mutationEpoch++;
    this.pendingPair = undefined;
    this.policyLast = -Infinity;
    try {
      return await run();
    } finally {
      this.mutationEpoch++;
      this.pendingPair = undefined;
      this.policyLast = -Infinity;
      await this.refreshRuleContext();
    }
  }
  private publishPair() {
    const pair = this.pendingPair,
      o = this.state.observation;
    if (
      !pair ||
      this.stopped ||
      pair.epoch !== this.mutationEpoch ||
      !this.state.control.connected ||
      this.state.control.generation !== pair.reply.generation ||
      !this.pendingInventory ||
      inventoryStamp(this.pendingInventory) !== pair.stamp
    )
      return;
    if (
      pair.policy.activity_available &&
      o.connected &&
      (o.generation !== pair.reply.generation ||
        !o.activity ||
        BigInt(pair.policy.activity_sequence) > BigInt(o.activity.sequence) ||
        Date.parse(pair.policy.activity_collected) > Date.parse(o.activity.collected))
    )
      return;
    this.state.control = {
      ...this.state.control,
      rules: pair.reply.rules,
      rule_states: pair.reply.rule_states,
      policy: pair.policy,
      policyError: '',
    };
    this.pendingPair = undefined;
  }
  private observerFlight?: Promise<void>;
  private policyFlight?: Promise<void>;
  private policyFlightEpoch = -1;
  private contextFlightEpoch = -1;
  pollObserver(): Promise<void> {
    if (this.observerFlight) return this.observerFlight;
    const request = this.readObserver().finally(() => {
      if (this.observerFlight === request) this.observerFlight = undefined;
    });
    this.observerFlight = request;
    return request;
  }
  private contextFlight?: Promise<ClientState>;
  refreshRuleContext(): Promise<ClientState> {
    if (this.contextFlight) {
      if (this.contextFlightEpoch === this.mutationEpoch) return this.contextFlight;
      return this.contextFlight.then(() => this.refreshRuleContext());
    }
    this.contextFlightEpoch = this.mutationEpoch;
    const request = this.readRuleContext().finally(() => {
      if (this.contextFlight === request) this.contextFlight = undefined;
    });
    this.contextFlight = request;
    return request;
  }
  private async readRuleContext() {
    await this.pollControl();
    await this.pollPolicy(true);
    await this.observerFlight;
    await this.pollObserver();
    this.publishPair();
    this.emit();
    return this.view();
  }
  private async readObserver() {
    if (this.busy.observer || this.stopped) return;
    this.busy.observer = true;
    try {
      const r = await call(this.observer, { operation: 'list' });
      if (r.error || r.mode !== 'host-monitor' || !r.read_only || !r.activity || r.activity.error)
        throw Error(r.error || r.activity?.error || 'Not a read-only observer');
      if (
        !Number.isFinite(Date.parse(r.activity.collected)) ||
        Date.parse(r.server_time) - Date.parse(r.activity.collected) > 45000
      )
        throw Error('Observer snapshot is stale');
      this.state.observation = {
        connected: true,
        message: `Activity · ${r.permissions?.observation_scope || 'user-visible'}${r.activity.complete ? '' : ' · partial'} · read-only`,
        generation: r.generation,
        activity: r.activity,
        trafficMonitor: r.traffic_monitor,
        evaluation: r.evaluation,
        protection: r.protection,
        permissions: r.permissions,
        capabilities: r.capabilities,
      };
    } catch (e) {
      this.state.observation = {
        connected: false,
        message: 'Activity unavailable · ' + (e as Error).message,
        capabilities: this.state.observation.capabilities,
        generation: this.state.observation.generation,
      };
    } finally {
      this.busy.observer = false;
      this.publishPair();
      this.emit();
    }
  }
  pollControl(): Promise<void> {
    if (this.controlFlight) {
      if (this.controlEpoch === this.mutationEpoch) return this.controlFlight;
      return this.controlFlight.then(() => this.pollControl());
    }
    this.controlEpoch = this.mutationEpoch;
    const flight = this.readControl().finally(() => {
      if (this.controlFlight === flight) this.controlFlight = undefined;
    });
    this.controlFlight = flight;
    return flight;
  }
  private async readControl() {
    if (!this.controller || this.stopped) return;
    const readEpoch = this.mutationEpoch,
      endpoint = this.controller,
      issued = ++this.listIssued;
    this.busy.control = true;
    const snapshotStarted = performance.now();
    try {
      const r = await call(endpoint, { operation: 'list' });
      if (readEpoch !== this.mutationEpoch || this.controller !== endpoint || this.stopped) return;
      for (const [token, v] of this.decisionPreviews)
        if (Date.parse(v.preview.expires_at) + 300000 < this.now())
          this.decisionPreviews.delete(token);
      if (
        r.error ||
        !(
          ['isolated-lab', 'host-enforcement'].includes(r.mode) ||
          (r.permissions &&
            r.capabilities.includes('explicit-administrator-v1') &&
            (r.mode === 'daemon-monitor' ||
              (r.mode === 'host-monitor' &&
                r.read_only &&
                ['daemon-monitor', 'host-enforcement'].includes(r.backend_mode || ''))))
        )
      )
        throw Error(r.error || 'Not a firewall controller');
      if (this.reply?.generation !== r.generation) {
        this.attempts.clear();
        this.reviewFailures.clear();
        this.decisionPreviews.clear();
        this.policySequence = -1n;
        this.settlements.clear();
        this.endedLeases.clear();
        this.reconcileAfter = undefined;
      }
      for (const [key, t] of this.settlements) if (t.until <= performance.now()) this.settlements.delete(key);
      r.events = reconcileListed(r.events, r.generation, issued, Date.parse(r.server_time), this.settlements);
      // Lost/rejected outcome: this list was issued after it, so it is authoritative.
      if (this.reconcileAfter !== undefined && issued > this.reconcileAfter) this.reconcileAfter = undefined;
      const stamp = inventoryStamp(r);
      const sameGeneration = this.state.control.generation === r.generation;
      const previousPolicy = this.state.control.policy;
      const authorityChanged =
        JSON.stringify([
          this.state.control.permissions,
          this.state.control.enforcement,
          this.state.control.capabilities,
          this.state.control.mode,
          this.state.control.readOnly,
        ]) !== JSON.stringify([r.permissions, r.enforcement, r.capabilities, r.mode, r.read_only]);
      if (stamp !== this.policyStamp) {
        this.policyStamp = stamp;
        this.policyLast = -Infinity;
      }
      this.pendingInventory = r;
      const retainedPolicy = sameGeneration && !authorityChanged ? previousPolicy : undefined;
      this.reply = r;
      this.received = performance.now();
      for (const event of r.events) {
        // A timed-out request with a retained verified identity stays visible
        // (non-actionable) so a future application rule can still be saved.
        const failure = reviewFailureOf(event) ??
          (event.state === 'expired' && event.request_rule?.available
            ? terminalReviewFailure('stale_decision', event.reason) : undefined);
        const held = this.reviewFailures.get(event.id);
        if (held && held.generation === r.generation) held.event = { ...event, revalidation: event.revalidation ?? held.event.revalidation };
        if (failure && !this.reviewFailures.has(event.id)) {
          if (this.reviewFailures.size >= 64)
            this.reviewFailures.delete(this.reviewFailures.keys().next().value!);
          this.reviewFailures.set(event.id, {generation: r.generation, event, failure, until: this.now()+300000});
        }
      }
      for (const id of this.attempts.keys())
        if (!r.events.some((e) => e.id === id)) this.attempts.delete(id);
      this.state.control = {
        snapshotStarted,
        trafficMonitor: r.traffic_monitor,
        evaluation: r.evaluation,
        protection: r.protection,
        connected: true,
        message:
          r.mode === 'isolated-lab'
            ? 'Isolated lab controller'
            : `Enforcement ${r.enforcement?.state === 'active' ? (r.enforcement.profile === 'incoming' ? 'incoming active · outgoing not covered' : r.enforcement.profile === 'both' ? 'both directions active' : 'active · profile unknown') : (r.enforcement?.state ?? 'unknown')} · ${!r.read_only && (r.permissions?.can_manage_rules ?? (r.mode !== 'host-enforcement' || r.enforcement?.state === 'active')) ? 'stored rules editable' : 'policy read-only'}`,
        networkZones: r.network_zones,
        policy: retainedPolicy,
        policyError: this.state.control.policyError,
        permissions: r.permissions,
        backendMode: r.backend_mode,
        generation: r.generation,
        readOnly:
          r.read_only ||
          (!r.permissions && r.mode === 'host-enforcement' && r.enforcement?.state !== 'active'),
        mode: r.mode,
        enforcement: r.enforcement,
        rules:
          r.capabilities.includes(POLICY_CAPABILITY) && sameGeneration && !authorityChanged
            ? this.state.control.rules
            : r.rules,
        rule_states:
          r.capabilities.includes(POLICY_CAPABILITY) && sameGeneration && !authorityChanged
            ? this.state.control.rule_states
            : r.rule_states,
        capabilities: r.capabilities,
        processLeases: forAWhileSupported(r.capabilities) ? (r.process_leases ?? []) : undefined,
        forAWhileDurations: r.for_a_while_durations,
        events: [],
      };
    } catch (e) {
      if (readEpoch !== this.mutationEpoch || this.controller !== endpoint || this.stopped) return;
      this.state.control = {
        ...this.state.control,
        connected: false,
        readOnly: true,
        message: 'Controller disconnected · enforcement state unknown · ' + (e as Error).message,
        policy: undefined,
        policyError: 'Controller disconnected; authoritative policy cleared.',
        trafficMonitor: undefined,
        evaluation: undefined,
      };
    } finally {
      this.busy.control = false;
      if (readEpoch !== this.mutationEpoch || this.controller !== endpoint || this.stopped) return;
      this.emit();
      if (!this.state.control.connected) this.policyEpoch++;
      else void this.pollPolicy();
    }
  }
  // One bounded batch, driven by the existing control loop. Pending requests do not
  // wait for metadata; no per-row sockets, timers, or renderer polling are added.
  pollPolicy(force = false): Promise<void> {
    if (this.policyFlight) {
      if (this.policyFlightEpoch === this.mutationEpoch) return this.policyFlight;
      return this.policyFlight.then(() => this.pollPolicy(force));
    }
    this.policyFlightEpoch = this.mutationEpoch;
    const request = this.readPolicy(force).finally(() => {
      if (this.policyFlight === request) this.policyFlight = undefined;
    });
    this.policyFlight = request;
    return request;
  }
  private async readPolicy(force = false) {
    const c = this.state.control,
      endpoint = this.controller;
    if (!endpoint || this.stopped || !c.connected || !c.capabilities?.includes(POLICY_CAPABILITY))
      return;
    if (this.policyBusy || (!force && performance.now() - this.policyLast < 1000)) return;
    this.policyBusy = true;
    this.policyLast = performance.now();
    const epoch = this.policyEpoch,
      mutationEpoch = this.mutationEpoch,
      baseline = this.pendingInventory,
      generation = c.generation;
    if (!baseline) {
      this.policyBusy = false;
      return;
    }
    const baselineStamp = inventoryStamp(baseline);
    if (this.policyEndpoint !== endpoint) {
      this.policySequence = -1n;
      this.policyEndpoint = endpoint;
    }
    const current = () =>
      !this.stopped &&
      this.controller === endpoint &&
      this.state.control.connected &&
      this.state.control.generation === generation &&
      this.policyEpoch === epoch &&
      this.mutationEpoch === mutationEpoch &&
      !!this.pendingInventory &&
      inventoryStamp(this.pendingInventory) === baselineStamp;
    try {
      const r = await call(endpoint, { operation: 'policy-view', generation });
      if (!current()) return;
      if (
        r.error ||
        r.generation !== generation ||
        !r.policy_view ||
        r.policy_view.snapshot.generation !== generation
      )
        throw Error(r.error || 'Policy generation or response mismatch');
      const v = r.policy_view;
      if (BigInt(v.snapshot.sequence) <= this.policySequence) return;
      if (
        Date.parse(v.snapshot.evaluated_at) > this.now() + 5000 ||
        this.now() - Date.parse(v.snapshot.evaluated_at) > 45000 ||
        (v.snapshot.valid_until && Date.parse(v.snapshot.valid_until) <= this.now())
      )
        throw Error('Policy snapshot expired; refreshing');
      const confirmation = await call(endpoint, { operation: 'list' });
      if (!current()) return;
      if (
        confirmation.error ||
        confirmation.generation !== generation ||
        inventoryStamp(confirmation) !== baselineStamp
      ) {
        this.policyLast = -Infinity;
        return;
      }
      this.policySequence = BigInt(v.snapshot.sequence);
      this.pendingPair = { reply: baseline, policy: v, epoch: mutationEpoch, stamp: baselineStamp };
      this.publishPair();
    } catch (e) {
      if (current()) {
        this.state.control.policyError = String(e);
        if (this.pendingInventory) {
          this.state.control.rules = this.pendingInventory.rules;
          this.state.control.rule_states = this.pendingInventory.rule_states;
        }
        this.state.control.policy = undefined;
      }
    } finally {
      this.policyBusy = false;
      this.emit();
    }
  }
  private decisionPreviews = new Map<
    string,
    { choice: Decision; preview: DecisionPreview; sent: boolean }
  >();
  private decisionEvent(d: Decision) {
    const c = this.state.control,
      e = this.reply?.events.find((e) => e.id === d.id);
    if (
      !this.controller ||
      !canDecide(c) ||
      c.generation !== d.generation ||
      !e ||
      this.reviewFailures.has(d.id) ||
      e.state !== 'awaiting-decision' ||
      Date.parse(e.deadline) <= this.now() ||
      !e.scope_previews[d.scope === 'for-a-while' ? 'once' : d.scope]
    )
      throw Error('Request is no longer actionable');
    return e;
  }
  async previewDecision(raw: Decision): Promise<DecisionPreview> {
    const d = validateDecision(raw),
      c = this.state.control,
      e = this.decisionEvent(d);
    if (
      d.scope === 'once' ||
      !!d.preview_token ||
      !c.capabilities?.includes(
        d.remember ? REMEMBER_FIELDS_CAPABILITY : REMEMBER_ZONE_CAPABILITY,
      ) ||
      !d.network_zone ||
      d.zone_revision !== c.networkZones?.revision
    )
      throw Error('Remembered network scope unavailable');
    if (
      d.network_zone !== 'any' &&
      (e.flow.network_scope?.state !== 'known' ||
        e.flow.network_scope.zone !== d.network_zone ||
        e.flow.network_scope.revision !== d.zone_revision)
    )
      throw Error('Network zone does not match this connection');
    const key = JSON.stringify(d);
    for (const [token, v] of this.decisionPreviews) {
      if (Date.parse(v.preview.expires_at) <= this.now() && !v.sent)
        this.decisionPreviews.delete(token);
      else if (!v.sent && JSON.stringify(v.choice) === key) return v.preview;
    }
    const r = await call(this.controller!, { operation: 'decision-preview', ...d });
    if (r.error) {
      const reported = r.events.find(event => event.id === d.id);
      const failure = reviewFailureOf(reported) ?? terminalReviewFailure(r.error_code, r.error);
      if (failure && r.generation === d.generation && this.state.control.generation === d.generation) {
        // Retain the original details for a bounded, explicitly non-actionable
        // future-rule workflow; never bind this refusal to a newer connection.
        if (this.reviewFailures.size >= 64 && !this.reviewFailures.has(d.id))
          this.reviewFailures.delete(this.reviewFailures.keys().next().value!);
        const previous = this.reviewFailures.get(d.id);
        // Paired Allow/Deny previews may race: a later generic stale reply must
        // not erase the first precise socket/identity failure (or its details).
        if (!previous || previous.failure.code === 'stale_decision' && failure.code !== 'stale_decision')
          this.reviewFailures.set(d.id, { generation: d.generation, event: reported?.revalidation ? reported : e, failure, until: this.now() + 300000 });
        for (const [token, held] of this.decisionPreviews)
          if (!held.sent && held.choice.generation === d.generation && held.choice.id === d.id)
            this.decisionPreviews.delete(token);
        this.emit();
      }
      throw Error(r.error);
    }
    if (r.generation !== d.generation) throw Error('Daemon generation changed');
    const p = agreesWithDecision(
      parseDecisionPreview(r.decision_preview),
      d,
      this.decisionEvent(d),
      this.now(),
    );
    if (this.decisionPreviews.size >= 64) throw Error('Too many retained decision reviews');
    this.decisionPreviews.set(p.token, { choice: d, preview: p, sent: false });
    return p;
  }
  private requestRules = new Map<string, {
    choice: RequestRuleChoice; preview: RequestRulePreview;
    phase: 'reviewed' | 'submitting' | 'unknown' | 'saved'; saved?: Rule;
  }>();
  private requestRuleEvent(c: RequestRuleChoice) {
    const state = this.view(), e = state.control.events.find((x) => x.id === c.id);
    if (!this.controller || !state.control.connected || !canManageRules(state.control) ||
        state.control.generation !== c.generation || !requestRuleAvailable(e, state.control.capabilities))
      throw Error('An application rule cannot be saved from this request');
    return e!;
  }
  // Never decides or releases the request; the backend validates the
  // executable it captured from the verified requester.
  async previewRequestRule(raw: unknown): Promise<RequestRulePreview> {
    const c = validateRequestRule(raw);
    this.requestRuleEvent(c);
    if (c.zone_revision !== (this.state.control.networkZones?.revision || '')) throw Error('Network definition changed; review again');
    const key = requestRuleKey(c);
    for (const [token, v] of this.requestRules) {
      if (v.phase === 'reviewed' && Date.parse(v.preview.expires_at) <= this.now()) this.requestRules.delete(token);
      else if (v.phase === 'reviewed' && requestRuleKey(v.choice) === key) return v.preview;
    }
    const r = await call(this.controller!, { operation: 'request-rule-preview', ...c });
    // Keep the backend's code (e.g. identity_unverifiable) so the card can classify it.
    if (r.error) throw Error((r.error_code ? r.error_code + ': ' : '') + r.error);
    if (r.generation !== c.generation) throw Error('Daemon generation changed');
    const preview = parseRequestRulePreview(r.request_rule_preview, c);
    if (this.requestRules.size >= 64) this.requestRules.delete(this.requestRules.keys().next().value!);
    this.requestRules.set(preview.token, { choice: c, preview, phase: 'reviewed' });
    return preview;
  }
  // Same token only: a repeated click or an unknown acknowledgement re-asks the
  // backend for this receipt and can never create a second rule.
  async saveRequestRule(raw: unknown): Promise<{ message: string; rule: Rule; replayed: boolean }> {
    const c = validateRequestRule(raw, true), held = this.requestRules.get(c.preview_token!);
    if (!held || requestRuleKey(held.choice) !== requestRuleKey(c)) throw Error('Reviewed rule unavailable; review again');
    if (held.phase === 'saved' && held.saved)
      return { message: `Already saved: ${held.preview.summary}. Applies to future connections; the ended request was not allowed.`, rule: held.saved, replayed: true };
    if (held.phase === 'submitting') throw Error('Saving · waiting for backend acknowledgement');
    this.requestRuleEvent(c);
    return this.ruleMutation(async () => {
      held.phase = 'submitting';
      let r: Reply;
      try {
        r = await call(this.controller!, { operation: 'request-rule-save', ...c });
      } catch (error) {
        held.phase = 'unknown';
        this.reconcileAfter = this.listIssued;
        throw Error('Save acknowledgement lost; use Check result (same review, never a new rule). ' + String((error as Error)?.message ?? error));
      }
      if (r.error) {
        held.phase = 'reviewed';
        throw Error((r.error_code ? r.error_code + ': ' : '') + r.error);
      }
      const rule = r.saved_rule;
      if (!rule || rule.id !== held.preview.rule.id || rule.version !== held.preview.rule.version) {
        held.phase = 'unknown';
        throw Error('Unexpected save acknowledgement; inspect Rules');
      }
      held.phase = 'saved';
      held.saved = rule;
      this.settle(c.generation, r.settled ?? [], r.server_time);
      // The ended request is answered by its saved rule: it leaves the queue.
      if (this.closedEnded.size >= 1024) this.closedEnded.delete(this.closedEnded.values().next().value!);
      this.closedEnded.add(settlementKey(c.generation, c.id));
      this.reviewFailures.delete(c.id);
      this.emit();
      return { message: `Saved: ${held.preview.summary}. Applies to future connections; the ended request was not allowed.`, rule, replayed: !!r.replayed };
    });
  }
  // This opens a separate rule editor; it never sends Decide for the old flow.
  futureApplicationSource(value: { generation: string; id: string }) {
    if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',') !== 'generation,id' ||
        ![value.generation, value.id].every(v => typeof v === 'string' && v.length > 0 && v.length <= 256))
      throw Error('Invalid original request');
    const state = this.view(), event = state.control.events.find(e => e.id === value.id);
    if (!event || value.generation !== state.control.generation ||
        event.attempt?.phase === 'unknown' || event.attempt?.phase === 'submitting' ||
        (!this.reviewFailures.has(event.id) && event.state === 'awaiting-decision' && event.remainingMs > 0))
      throw Error('Resolve the original request or its uncertain result first; no rule opened');
    const source = freshApplicationRuleSource(state, event);
    if (!source) throw Error('No fresh independently verified application identity is visible. Open the application in Activity after it reconnects; the ended connection cannot be approved.');
    return source;
  }
  async reconcileDecision(value: {
    generation: string;
    id: string;
    preview_token: string;
  }): Promise<Attempt> {
    const held = this.decisionPreviews.get(value.preview_token);
    if (
      !held?.sent ||
      held.choice.generation !== value.generation ||
      held.choice.id !== value.id ||
      !this.controller ||
      !this.state.control.connected ||
      this.state.control.readOnly ||
      this.state.control.generation !== value.generation
    )
      throw Error('Original decision receipt unavailable; no decision resent');
    const r = await call(this.controller, {
      operation: 'decision-status',
      generation: value.generation,
      preview_token: value.preview_token,
    });
    if (r.error || r.generation !== value.generation)
      throw Error(r.error || 'Daemon generation changed');
    const receipt = r.decision_receipt as
      { state?: string; preview?: unknown; decision?: unknown; saved_rule?: unknown } | undefined;
    const expected = held.preview,
      p = parseDecisionPreview(receipt?.preview);
    if (JSON.stringify(p) !== JSON.stringify(expected)) throw Error('Receipt preview changed');
    let result: Attempt = {
      phase: 'unknown',
      message: 'Outcome still uncertain; no decision resent.',
      reconcile: value.preview_token,
    };
    if (receipt?.state === 'committed') {
      const parsed = parseReply({
        ...r,
        decision: receipt.decision,
        saved_rule: receipt.saved_rule,
      });
      if (
        parsed.decision?.id !== value.id ||
        parsed.decision.state !== (held.choice.action === 'allow' ? 'allowed' : 'blocked') ||
        !parsed.saved_rule ||
        !sameRememberedRule(parsed.saved_rule, expected.rule)
      )
        throw Error('Invalid committed decision receipt');
      result = {
        phase: 'acknowledged',
        message: `Backend confirmed ${parsed.decision.state} · ${parsed.decision.reason}`,
        rule: parsed.saved_rule,
      };
    } else if (receipt?.state !== 'pending') throw Error('Invalid decision receipt');
    if (this.state.control.generation === value.generation) this.attempts.set(value.id, result);
    this.emit();
    return result;
  }
  async decide(raw: Decision): Promise<Attempt> {
    const d = validateDecision(raw);
    // For a while creates an in-memory lease, not a rule: no rule mutation lock.
    return d.scope === 'once' || d.scope === 'for-a-while'
      ? this.decideInner(d)
      : this.ruleMutation(() => this.decideInner(d));
  }
  private async decideInner(raw: Decision): Promise<Attempt> {
    const d = validateDecision(raw);
    const c = this.state.control;
    const e = this.reply?.events.find((e) => e.id === d.id);
    const temporary = d.scope === 'for-a-while';
    if (temporary && !forAWhileSupported(c.capabilities))
      throw Error('For a while unsupported by this backend');
    if (temporary && d.duration_seconds !== undefined && !forAWhileDurations(c).includes(d.duration_seconds))
      throw Error('This For a while duration is not offered by the backend');
    if (
      !this.controller ||
      !c.connected ||
      !canDecide(c) ||
      c.generation !== d.generation ||
      !e ||
      this.reviewFailures.has(d.id) ||
      e.state !== 'awaiting-decision' ||
      Date.parse(e.deadline) <= this.now() ||
      // For a while decides like Once (plus a backend lease); same admission.
      !e.scope_previews[d.scope === 'for-a-while' ? 'once' : d.scope] ||
      this.attempts.has(d.id) ||
      [...this.attempts.values()].filter((a) => a.phase === 'submitting').length >= 8
    )
      throw Error('Request is no longer actionable; refresh authoritative state');
    const zoned =
      d.scope !== 'once' &&
      !temporary &&
      (c.capabilities?.includes(REMEMBER_ZONE_CAPABILITY) ||
        c.capabilities?.includes(REMEMBER_FIELDS_CAPABILITY));
    if (d.remember && (!zoned || !c.capabilities?.includes(REMEMBER_FIELDS_CAPABILITY)))
      throw Error('Remember fields unsupported by this backend');
    const held = d.preview_token ? this.decisionPreviews.get(d.preview_token) : undefined;
    if (zoned) {
      if (!held || held.sent || !d.preview_token) throw Error('Fresh decision preview required');
      agreesWithDecision(held.preview, d, e, this.now());
      held.sent = true;
    } else if (d.network_zone || d.zone_revision || d.preview_token)
      throw Error('Decision network scope unsupported');
    this.attempts.set(d.id, {
      phase: 'submitting',
      message: 'Submitting · waiting for backend acknowledgement',
    });
    this.emit();
    let result: Attempt;
    try {
      const r = await call(this.controller, {
        operation: 'decide',
        generation: d.generation,
        ...(zoned
          ? {
              generation: d.generation,
              network_zone: d.network_zone,
              zone_revision: d.zone_revision,
              preview_token: d.preview_token,
              ...(d.remember ? { remember: d.remember } : {}),
              ...(d.duration_seconds !== undefined ? { duration_seconds: d.duration_seconds } : {}),
            }
          : {}),
        ...(temporary && d.duration_seconds !== undefined ? { duration_seconds: d.duration_seconds } : {}),
        id: d.id,
        action: d.action,
        scope: d.scope,
      });
      if (r.generation !== d.generation) throw Error('Backend generation changed');
      if (r.error && temporary && r.error_code === 'process_scope_unavailable') {
        // Nothing was decided: the request stays answerable (Once/Remember).
        this.attempts.delete(d.id);
        this.emit();
        throw new DecisionRefused('process_scope_unavailable: ' + r.error);
      }
      if (r.error) {
        result = {
          phase: 'rejected',
          message: 'Backend rejected: ' + (r.error_code ? r.error_code + ': ' : '') + r.error,
        };
        // The refusal may itself have ended the request: read the list first.
        this.reconcileAfter = this.listIssued;
      } else if (
        r.decision?.id !== d.id ||
        r.decision.state !== (d.action === 'allow' ? 'allowed' : 'blocked') ||
        (zoned && (!r.saved_rule || !sameRememberedRule(r.saved_rule, held!.preview.rule)))
      )
        throw Error('Invalid decision acknowledgement');
      else {
        result = {
          phase: 'acknowledged',
          message: `Backend acknowledged ${r.decision.state} · ${r.decision.reason}`,
          rule: r.saved_rule,
          scope: d.scope,
          leaseUntil: temporary ? r.decision.lease?.until : undefined,
        };
        this.settle(d.generation, [{ id: d.id, state: r.decision.state, event: r.decision }, ...(r.settled ?? [])], r.server_time);
      }
    } catch (e) {
      if (e instanceof DecisionRefused) throw Error(e.message);
      result = {
        phase: 'unknown',
        message:
          'Acknowledgement unavailable; outcome unknown. No automatic retry. ' +
          (e as Error).message,
        reconcile: zoned ? d.preview_token : undefined,
      };
      // No further prompt until a list issued after this point was read.
      this.reconcileAfter = this.listIssued;
    }
    // A reply from an old connection must never mutate a new session.
    if (this.state.control.generation === d.generation) this.attempts.set(d.id, result);
    this.emit();
    this.reconcileSoon();
    return result;
  }
  // local-pair-v1: both sides of one verified local connection. The backend
  // confirms the exact pair (events referencing each other) and returns BOTH
  // verdicts; nothing is inferred here and no retry is sent.
  async decidePair(raw: PairChoice): Promise<{ message: string; text: string; result: PairResult }> {
    const d = validatePairChoice(raw),
      c = this.state.control;
    const listed = d.ids.map((id) => this.reply?.events.find((e) => e.id === id));
    if (
      !this.controller ||
      !c.connected ||
      !canDecide(c) ||
      c.generation !== d.generation ||
      !c.capabilities?.includes(LOCAL_PAIR_CAPABILITY) ||
      listed.some((e) => !e) ||
      !listed.some((e) => e!.state === 'awaiting-decision' && Date.parse(e!.deadline) > this.now() && !this.attempts.has(e!.id))
    )
      throw Error('Pair is no longer actionable; refresh authoritative state');
    // Both sides are in flight: never presented again while submitting.
    const pending = listed.filter((e) => e!.state === 'awaiting-decision').map((e) => e!.id);
    const mark = (a: Attempt) => {
      if (this.state.control.generation === d.generation) for (const id of pending) this.attempts.set(id, a);
      this.emit();
    };
    mark({ phase: 'submitting', message: 'Submitting · waiting for backend acknowledgement' });
    let r: Reply;
    try {
      r = await call(this.controller, { operation: 'decide-pair', generation: d.generation, event_ids: d.ids, action: d.action, scope: d.scope });
    } catch (error) {
      const message = 'Acknowledgement lost; outcome unknown. No automatic retry. ' + String((error as Error)?.message ?? error);
      mark({ phase: 'unknown', message });
      this.reconcileAfter = this.listIssued;
      this.reconcileSoon();
      throw Error(message);
    }
    if (r.generation !== d.generation) {
      mark({ phase: 'unknown', message: 'Backend generation changed' });
      throw Error('Backend generation changed');
    }
    if (r.error) {
      // Refused before any change (validation runs first): nothing was decided.
      if (this.state.control.generation === d.generation) for (const id of pending) this.attempts.delete(id);
      this.emit();
      this.reconcileSoon();
      throw Error((r.error_code ? r.error_code + ': ' : '') + r.error);
    }
    const p = r.pair;
    if (!p || p.events.some((e) => !d.ids.includes(e.id)) || p.events.length !== d.ids.length) {
      mark({ phase: 'unknown', message: 'Invalid pair acknowledgement; outcome unknown' });
      this.reconcileAfter = this.listIssued;
      this.reconcileSoon();
      throw Error('Invalid pair acknowledgement; outcome unknown');
    }
    const text = pairResultText(p);
    for (const e of p.events)
      if (e.state === 'allowed' || e.state === 'blocked')
        this.attempts.set(e.id, { phase: 'acknowledged', message: `Backend acknowledged ${e.state} · ${e.reason}`, scope: 'once' });
    this.settle(d.generation, [...p.events.map((e) => ({ id: e.id, state: e.state, event: e })), ...(r.settled ?? [])], r.server_time);
    this.emit();
    this.reconcileSoon();
    return { message: r.scope_preview || p.sentence, text, result: p };
  }
  /** Keeps a submission outcome for review (newest first, bounded). */
  noteResult(generation: string, eventId: string, outcome: Pick<PermissionResult, 'severity' | 'text' | 'detail'>) {
    const e = this.reply?.events.find((x) => x.id === eventId) ?? this.reviewFailures.get(eventId)?.event;
    pushResult(this.results, {
      id: String(++this.resultSeq),
      at: this.now(),
      generation,
      eventId,
      ...eventLabel(e),
      ...outcome,
    });
    this.emit();
  }
  // Records acknowledged/settled requests and removes them from the visible
  // queue at once (only those ids; nothing is inferred).
  settle(generation: string, entries: { id: string; state: string; event?: RequestEvent }[], serverTime: string) {
    if (this.reply?.generation !== generation) return;
    const t = Date.parse(serverTime),
      until = performance.now() + 600000;
    for (const x of entries) {
      if (x.state === 'awaiting-decision') continue;
      if (this.settlements.size >= 1024) this.settlements.delete(this.settlements.keys().next().value!);
      this.settlements.set(settlementKey(generation, x.id), {
        issued: this.listIssued, serverTime: Number.isFinite(t) ? t : 0, state: x.state, event: x.event, until,
      });
    }
    this.reply.events = reconcileListed(this.reply.events, generation, -1, 0, this.settlements);
  }
  // Reads an authoritative list issued after now (joins nothing stale).
  private reconcileSoon() {
    void this.pollControl().then(() => {
      if (this.reconcileAfter !== undefined) return this.pollControl();
    });
  }
  // request-for-a-while-v1: a process lease from an ended request; the request
  // itself stays ended and is never decided or delivered.
  async requestForAWhile(raw: EndedLeaseChoice): Promise<{ message: string; lease: ProcessLease }> {
    const c = validateEndedLease(raw),
      state = this.view(),
      control = state.control,
      key = settlementKey(c.generation, c.id),
      e = control.events.find((x) => x.id === c.id);
    const done = this.endedLeases.get(key);
    if (done) return done;
    if (this.endedLeaseFlight.has(key)) throw Error('Submitting · waiting for backend acknowledgement');
    if (!this.controller || !control.connected || !canDecide(control) || control.generation !== c.generation ||
        !endedLeaseAvailable(e, control.capabilities))
      throw Error('For a while is unavailable for this request');
    if (c.duration_seconds !== undefined && !forAWhileDurations(control).includes(c.duration_seconds))
      throw Error('This For a while duration is not offered by the backend');
    this.endedLeaseFlight.add(key);
    try {
      let r: Reply;
      try {
        r = await call(this.controller, { operation: 'request-for-a-while', ...c });
      } catch (error) {
        this.reconcileAfter = this.listIssued;
        this.reconcileSoon();
        throw Error('Acknowledgement lost; outcome unknown. Checking the backend list first. ' + String((error as Error)?.message ?? error));
      }
      if (r.generation !== c.generation) throw Error('Daemon generation changed');
      if (r.error) {
        this.reconcileSoon();
        throw Error((r.error_code ? r.error_code + ': ' : '') + r.error);
      }
      const lease = r.process_lease;
      if (!lease || !r.request_ended || lease.event_id !== c.id || (c.duration_seconds ?? 15) !== lease.seconds)
        throw Error('Invalid For a while acknowledgement');
      this.settle(c.generation, r.settled ?? [], r.server_time);
      if (this.state.control.generation === c.generation && this.state.control.processLeases)
        this.state.control.processLeases = [
          ...this.state.control.processLeases.filter(
            (l) => !(l.pid === lease.pid && l.start === lease.start && l.direction === lease.direction),
          ),
          lease,
        ];
      const out = { message: r.scope_preview || 'For a while lease created; this ended request was not delivered.', lease };
      this.endedLeases.set(key, out);
      this.emit();
      this.reconcileSoon();
      return out;
    } finally {
      this.endedLeaseFlight.delete(key);
    }
  }
}
