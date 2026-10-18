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
} from './protocol';
export function call(path: string, request: object): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path });
    let chunks: Buffer[] = [];
    let size = 0;
    let finished = false;
    const done = (error?: Error, value?: Reply) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      error ? reject(error) : resolve(value!);
    };
    socket.setTimeout(3500, () => done(Error('Backend timed out')));
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
  private busy = { observer: false, control: false };
  private timers: NodeJS.Timeout[] = [];
  private stopped = false;
  private policyBusy = false;
  private policyEpoch = 0;
  private policySequence = -1n;
  private policyStamp = '';
  private policyEndpoint = '';
  private policyLast = -Infinity;
  constructor(
    readonly observer: string,
    public controller: string | undefined,
    private changed: (state: ClientState) => void,
  ) {}
  start() {
    void this.pollObserver();
    void this.pollControl();
    this.timers.push(
      setInterval(() => void this.pollObserver(), 1000),
      setInterval(() => void this.pollControl(), 750),
      setInterval(() => this.emit(), 250),
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
    return {
      ...this.state,
      control: {
        ...this.state.control,
        serverNow: this.now(),
        policy:
          this.state.control.policy?.snapshot.valid_until &&
          Date.parse(this.state.control.policy.snapshot.valid_until) <= this.now()
            ? undefined
            : this.state.control.policy,
        events: (this.reply?.events ?? []).map((e) => ({
          ...e,
          remainingMs: Math.max(0, Date.parse(e.deadline) - this.now()),
          attempt: this.attempts.get(e.id),
        })),
      },
    };
  }
  private emit() {
    if (!this.stopped) this.changed(this.view());
  }
  async pollObserver() {
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
      this.emit();
    }
  }
  async pollControl() {
    if (!this.controller || this.busy.control || this.stopped) return;
    this.busy.control = true;
    const snapshotStarted = performance.now();
    try {
      const r = await call(this.controller, { operation: 'list' });
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
        this.policySequence = -1n;
      }
      const stamp = JSON.stringify([
        this.controller,
        r.generation,
        r.rules,
        r.permissions,
        r.enforcement,
        r.capabilities,
      ]);
      if (stamp !== this.policyStamp) {
        this.policyStamp = stamp;
        this.policyEpoch++;
        this.state.control.policy = undefined;
        this.policyLast = -Infinity;
      }
      this.reply = r;
      this.received = performance.now();
      for (const id of this.attempts.keys())
        if (!r.events.some((e) => e.id === id)) this.attempts.delete(id);
      this.state.control = {
        snapshotStarted,
        trafficMonitor: r.traffic_monitor,
        evaluation: r.evaluation,
        connected: true,
        message:
          r.mode === 'isolated-lab'
            ? 'Isolated lab controller'
            : `Enforcement ${r.enforcement?.state === 'active' ? (r.enforcement.profile === 'incoming' ? 'incoming active · outgoing not covered' : r.enforcement.profile === 'both' ? 'both directions active' : 'active · profile unknown') : (r.enforcement?.state ?? 'unknown')} · ${!r.read_only && (r.permissions?.can_manage_rules ?? (r.mode !== 'host-enforcement' || r.enforcement?.state === 'active')) ? 'stored rules editable' : 'policy read-only'}`,
        policy: this.state.control.policy,
        policyError: this.state.control.policyError,
        permissions: r.permissions,
        backendMode: r.backend_mode,
        generation: r.generation,
        readOnly:
          r.read_only ||
          (!r.permissions && r.mode === 'host-enforcement' && r.enforcement?.state !== 'active'),
        mode: r.mode,
        enforcement: r.enforcement,
        rules: r.rules,
        rule_states: r.rule_states,
        capabilities: r.capabilities,
        events: [],
      };
    } catch (e) {
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
      this.emit();
      if (!this.state.control.connected) this.policyEpoch++;
      else void this.pollPolicy();
    }
  }
  // One bounded batch, driven by the existing control loop. Pending requests do not
  // wait for metadata; no per-row sockets, timers, or renderer polling are added.
  async pollPolicy() {
    const c = this.state.control,
      endpoint = this.controller;
    if (!endpoint || this.stopped || !c.connected || !c.capabilities?.includes(POLICY_CAPABILITY))
      return;
    if (this.policyBusy || performance.now() - this.policyLast < 1000) return;
    this.policyBusy = true;
    this.policyLast = performance.now();
    const epoch = this.policyEpoch,
      generation = c.generation;
    if (this.policyEndpoint !== endpoint) {
      this.policySequence = -1n;
      this.policyEndpoint = endpoint;
    }
    const current = () =>
      !this.stopped &&
      this.controller === endpoint &&
      this.state.control.connected &&
      this.state.control.generation === generation &&
      this.policyEpoch === epoch;
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
      if (BigInt(v.snapshot.sequence) <= this.policySequence)
        throw Error('Out-of-order policy response discarded');
      if (
        Date.parse(v.snapshot.evaluated_at) > this.now() + 5000 ||
        this.now() - Date.parse(v.snapshot.evaluated_at) > 45000 ||
        (v.snapshot.valid_until && Date.parse(v.snapshot.valid_until) <= this.now())
      )
        throw Error('Policy snapshot expired; refreshing');
      this.policySequence = BigInt(v.snapshot.sequence);
      this.state.control.policy = v;
      this.state.control.policyError = '';
    } catch (e) {
      if (current()) {
        this.state.control.policy = undefined;
        this.state.control.policyError = String(e);
      }
    } finally {
      this.policyBusy = false;
      this.emit();
    }
  }
  async decide(raw: Decision): Promise<Attempt> {
    const d = validateDecision(raw);
    const c = this.state.control;
    const e = this.reply?.events.find((e) => e.id === d.id);
    if (
      !this.controller ||
      !c.connected ||
      !canDecide(c) ||
      c.generation !== d.generation ||
      !e ||
      e.state !== 'awaiting-decision' ||
      Date.parse(e.deadline) <= this.now() ||
      !e.scope_previews[d.scope] ||
      this.attempts.has(d.id) ||
      [...this.attempts.values()].filter((a) => a.phase === 'submitting').length >= 8
    )
      throw Error('Request is no longer actionable; refresh authoritative state');
    this.attempts.set(d.id, {
      phase: 'submitting',
      message: 'Submitting · waiting for backend acknowledgement',
    });
    this.emit();
    let result: Attempt;
    try {
      const r = await call(this.controller, {
        operation: 'decide',
        id: d.id,
        action: d.action,
        scope: d.scope,
      });
      if (r.generation !== d.generation) throw Error('Backend generation changed');
      if (r.error) {
        result = { phase: 'rejected', message: 'Backend rejected: ' + r.error };
      } else if (
        r.decision?.id !== d.id ||
        r.decision.state !== (d.action === 'allow' ? 'allowed' : 'blocked')
      )
        throw Error('Invalid decision acknowledgement');
      else {
        result = {
          phase: 'acknowledged',
          message: `Backend acknowledged ${r.decision.state} · ${r.decision.reason}`,
        };
        if (this.reply?.generation === d.generation)
          this.reply.events = this.reply.events.map((e) => (e.id === d.id ? r.decision! : e));
      }
    } catch (e) {
      result = {
        phase: 'unknown',
        message:
          'Acknowledgement unavailable; outcome unknown. No automatic retry. ' +
          (e as Error).message,
      };
    }
    // A reply from an old connection must never mutate a new session.
    if (this.state.control.generation === d.generation) this.attempts.set(d.id, result);
    this.emit();
    void this.pollControl();
    return result;
  }
}
