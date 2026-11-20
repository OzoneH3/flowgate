// Queue reconciliation (queue-reconcile-v1), For a while from an ended request
// whose process is alive (request-for-a-while-v1) and For a while durations
// (decision-for-a-while-durations-v1). Synthetic sockets and a minimal DOM; no
// daemon, no window.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend, reconcileListed, settlementKey } = require('../dist/test/backend.cjs');
const { AutomaticPrompts, inputSettled, requestGroups } = require('../dist/test/automatic-prompts.cjs');
const { validateDecision, parseReply } = require('../dist/test/protocol.cjs');
const lease = require('../dist/test/process-lease.cjs');
const pd = require('../dist/test/prompt-decision.cjs');
const { REMEMBER_FIELDS_CAPABILITY, DEFAULT_REMEMBER } = require('../dist/test/decision-remember.cjs');
const { REQUEST_RULE_CAPABILITY } = require('../dist/test/request-rule.cjs');

const CAPS = [
  'explicit-administrator-v1',
  REMEMBER_FIELDS_CAPABILITY,
  REQUEST_RULE_CAPABILITY,
  lease.FOR_A_WHILE_CAPABILITY,
  lease.FOR_A_WHILE_DURATIONS_CAPABILITY,
  pd.REQUEST_FOR_A_WHILE_CAPABILITY,
  'queue-reconcile-v1',
];
const DURATIONS = [15, 60, 300, 600, 1800, 3600];
const ev = (id, over = {}) => ({
  id,
  state: 'awaiting-decision',
  reason: 'waiting',
  deadline: new Date(Date.now() + 60000).toISOString(),
  first_seen: new Date(Date.now() - 1000).toISOString(),
  permission: '',
  flow: { direction: 'outgoing', protocol: 'tcp', local: '10.1.0.1:40000', remote: '10.1.0.2:443' },
  attribution: {
    application: { key: 'k', revision: 'r', name: 'curl', executable: '/usr/bin/curl' },
    owners: [{ pid: 4242, start_ticks: '9', uid: 1000 }],
    status: 'directly-associated',
    reason: 'one holder',
    visibility_complete: true,
  },
  scope_previews: { once: 'Once', 'for-a-while': 'For a while' },
  remembered_filter: { application: 'k', revision: 'r', uid: 1000, direction: 'outgoing', protocol: 'tcp', remote_address: '10.1.0.2', local_port: 0, remote_port: 443 },
  ...over,
});
const endedLive = (over = {}) =>
  ev('ended', {
    state: 'expired',
    reason: 'Connection ended: original socket is no longer present; process/executable change is not established',
    revalidation: {
      code: 'connection_ended',
      reason: 'Connection ended: original socket is no longer present; process/executable change is not established',
      checked_at: new Date().toISOString(),
      changes: [{ field: 'socket_inode_cookie', before: 'a', after: '' }],
    },
    request_rule: { available: true, process_state: 'running', until: new Date(Date.now() + 600000).toISOString(), process_lease_available: true, pid: 4242 },
    ...over,
  });

// One fake control endpoint. `hold` delays list responses until released;
// every response's events are produced from `world` at RESPONSE time unless
// the list was held, in which case they are the snapshot at request time.
async function fixture(t, { caps = CAPS, handle } = {}) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/qr-')),
    endpoint = path.join(dir, 's'),
    sent = [],
    world = { events: [], leases: [], hold: false, held: [], serverTime: () => new Date().toISOString() };
  const base = (events = world.events) => ({
    version: 1, generation: world.generation || 'g', read_only: false, mode: 'daemon-monitor', server_time: world.serverTime(),
    ...(world.snapshotRevision ? { snapshot_revision: world.snapshotRevision, snapshot_at: world.serverTime() } : {}),
    capabilities: caps, for_a_while_durations: DURATIONS,
    permissions: { role: 'administrator', observation_scope: 'machine', policy_scope: 'machine', can_manage_rules: true, can_decide: true },
    events: JSON.parse(JSON.stringify(events)), process_leases: world.leases,
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw);
      sent.push(q);
      if (q.operation === 'list' && world.hold) {
        const snapshot = base();
        world.held.push(() => s.end(JSON.stringify(snapshot) + '\n'));
        return;
      }
      if (q.operation !== 'list' && handle) {
        const r = handle(q, world);
        if (r === 'drop') return s.end();
        return s.end(JSON.stringify({ ...base(), ...r }) + '\n');
      }
      s.end(JSON.stringify(base()) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, () => {});
  t.after(() => {
    b.stop();
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const release = () => {
    world.hold = false;
    for (const f of world.held.splice(0)) f();
  };
  return { b, sent, world, release };
}
const visible = (b) => requestGroups(b.view().control.events).flatMap((g) => g.events.map((e) => e.id));
const until = (fn) =>
  new Promise((resolve, reject) => {
    const end = Date.now() + 2000;
    const tick = () => (fn() ? resolve() : Date.now() > end ? reject(Error('timeout')) : setTimeout(tick, 5));
    tick();
  });

test('reconcileListed: a stale list never reopens; only a newer observation may', () => {
  const settled = new Map([[settlementKey('g', 'a'), { issued: 5, serverTime: 1000, state: 'allowed', until: Infinity }]]);
  const listed = [ev('a'), ev('b')];
  // Issued before (or at) the acknowledgement: replaced, never awaiting.
  for (const [issued, time] of [[3, 2000], [5, 2000]]) {
    const out = reconcileListed(listed, 'g', issued, time, settled);
    assert.equal(out[0].state, 'allowed');
    assert.equal(out[1].state, 'awaiting-decision', 'unrelated request untouched');
  }
  // Issued after but with an older server clock: still stale.
  assert.equal(reconcileListed(listed, 'g', 6, 999, settled)[0].state, 'allowed');
  // Another generation is a different request.
  assert.equal(reconcileListed(listed, 'h', 3, 0, settled)[0].state, 'awaiting-decision');
  // A non-awaiting authoritative state passes through unchanged.
  assert.equal(reconcileListed([ev('a', { state: 'blocked' })], 'g', 3, 0, settled)[0].state, 'blocked');
  // Newer authoritative observation (issued after the ack, server time not earlier) wins.
  assert.equal(reconcileListed(listed, 'g', 6, 1000, settled)[0].state, 'awaiting-decision');
  assert.equal(settled.size, 0, 'the backend reopened it; the local record is dropped');
});

test('acknowledged Allow removes the request at once; settled ids are removed; a stale poll cannot reopen', async (t) => {
  const { b, world, release, sent } = await fixture(t, {
    handle: (q, w) => {
      if (q.operation !== 'decide') return {};
      const decided = { ...w.events.find((e) => e.id === q.id), state: 'allowed', reason: 'explicit' };
      w.events = w.events.map((e) => (e.id === q.id ? decided : e.id === 'covered' ? { ...e, state: 'allowed' } : e));
      return { decision: decided, settled: [{ id: 'covered', state: 'allowed', rule: 'user:x' }] };
    },
  });
  world.events = [ev('first'), ev('covered', { request_group: 'G' }), ev('other', { flow: { ...ev('x').flow, local: '10.1.0.1:40009' } })];
  await b.pollControl();
  assert.deepEqual(visible(b).sort(), ['covered', 'first', 'other']);
  // A poll issued BEFORE the acknowledgement, answered after it (stale).
  world.hold = true;
  const stale = b.pollControl();
  await until(() => world.held.length === 1);
  const once = await b.decide({ generation: 'g', id: 'first', action: 'allow', scope: 'once' });
  assert.equal(once.phase, 'acknowledged');
  assert.deepEqual(visible(b), ['other'], 'decided and settled ids removed immediately; nothing guessed');
  release();
  await stale;
  assert.deepEqual(visible(b), ['other'], 'stale list did not reopen decided/settled requests');
  // Reconnect-style list issued after the ack: authoritative non-awaiting states.
  await b.pollControl();
  assert.deepEqual(visible(b), ['other']);
  assert.equal(b.view().control.events.find((e) => e.id === 'first').state, 'allowed');
  assert.equal(sent.filter((q) => q.operation === 'decide').length, 1);
});

test('other requests stay until the backend reports them non-awaiting (no guessing by name/endpoint)', async (t) => {
  const { b, world } = await fixture(t, {
    handle: (q, w) => {
      const decided = { ...w.events.find((e) => e.id === q.id), state: 'allowed' };
      w.events = w.events.map((e) => (e.id === q.id ? decided : e));
      return { decision: decided };
    },
  });
  // Same application, same endpoint, same group: still a separate request.
  world.events = [ev('a', { request_group: 'G' }), ev('b', { request_group: 'G' })];
  await b.pollControl();
  await b.decide({ generation: 'g', id: 'a', action: 'allow', scope: 'once' });
  assert.deepEqual(visible(b), ['b']);
  world.events = world.events.map((e) => (e.id === 'b' ? { ...e, state: 'blocked' } : e));
  await b.pollControl();
  assert.deepEqual(visible(b), []);
});

test('lost acknowledgement: no new prompt until an authoritative list issued afterwards was read', async (t) => {
  const { b, world, release } = await fixture(t, { handle: () => 'drop' });
  world.events = [ev('a'), ev('b', { flow: { ...ev('x').flow, local: '10.1.0.1:40002' } })];
  await b.pollControl();
  const prompts = new AutomaticPrompts();
  assert.equal(prompts.next(b.view(), false).id, 'a');
  // A list already in flight before the failure must not end reconciliation.
  world.hold = true;
  const inflight = b.pollControl();
  await until(() => world.held.length === 1);
  const result = await b.decide({ generation: 'g', id: 'a', action: 'allow', scope: 'once' });
  assert.equal(result.phase, 'unknown');
  assert.equal(b.view().control.reconciling, true);
  assert.equal(prompts.next(b.view(), false), undefined, 'no popup while reconciling');
  assert.deepEqual(prompts.follow(b.view(), { generation: 'g', id: 'a' }), { generation: 'g', id: 'a' }, 'card stays');
  // The backend did decide it (the ack was lost).
  world.events = world.events.map((e) => (e.id === 'a' ? { ...e, state: 'allowed', reason: 'explicit' } : e));
  release();
  await inflight;
  // The chained authoritative read completes reconciliation.
  await until(() => !b.view().control.reconciling);
  assert.equal(b.view().control.events.find((e) => e.id === 'a').state, 'allowed');
  assert.equal(prompts.next(b.view(), false).id, 'b', 'next request only after reconciliation');
});

test('rejected decision also reconciles before the next prompt', async (t) => {
  const { b, world } = await fixture(t, {
    handle: (q, w) => {
      w.events = w.events.map((e) => (e.id === q.id ? { ...e, state: 'expired', revalidation: endedLive().revalidation } : e));
      return { error: 'Connection ended: original socket is no longer present', error_code: 'connection_ended' };
    },
  });
  world.events = [ev('a'), ev('b', { flow: { ...ev('x').flow, local: '10.1.0.1:40002' } })];
  await b.pollControl();
  const r = await b.decide({ generation: 'g', id: 'a', action: 'allow', scope: 'once' });
  assert.equal(r.phase, 'rejected');
  assert.match(pd.shortError(r.message.replace(/^Backend rejected: /, '')), /^This connection has ended\.$/);
  await until(() => !b.view().control.reconciling);
  assert.equal(new AutomaticPrompts().next(b.view(), false).id, 'b');
});

test('no automatic advance under the same click or keypress (input-release + pacing guard)', () => {
  const g = { now: 1000, transitionUntil: 0, keys: 0, rendererKeys: 0, pointerDown: false };
  assert.equal(inputSettled(g), true);
  assert.equal(inputSettled({ ...g, pointerDown: true }), false, 'pointer still down after the click');
  assert.equal(inputSettled({ ...g, keys: 1 }), false, 'Enter/Space still held');
  assert.equal(inputSettled({ ...g, rendererKeys: 1 }), false);
  assert.equal(inputSettled({ ...g, transitionUntil: 1650 }), false, '650 ms pacing after release');
  assert.equal(inputSettled({ ...g, now: 1650, transitionUntil: 1650 }), true);
  const main = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  assert.equal((main.match(/promptInputSettled\(\)/g) || []).length, 2, 'both presentation paths use the guard');
  assert.match(main, /TRANSITION_MS = 650/);
});

test('ended request whose process runs: For a while creates the lease only, settles queued ids', async (t) => {
  const leaseUntil = new Date(Date.now() + 60000).toISOString();
  const { b, world, sent } = await fixture(t, {
    handle: (q, w) => {
      assert.equal(q.operation, 'request-for-a-while');
      const l = { id: 'L1', action: q.action, direction: 'outgoing', application: 'k', application_name: 'curl', executable: '/usr/bin/curl', uid: 1000, pid: 4242, start: '9', until: leaseUntil, remaining_ms: 60000, seconds: q.duration_seconds ?? 15, event_id: q.id };
      w.leases = [l];
      w.events = w.events.map((e) => (e.id === 'queued' ? { ...e, state: 'blocked', rule: 'while:L1' } : e));
      return { process_lease: l, request_ended: true, settled: [{ id: 'queued', state: 'blocked', rule: 'while:L1' }], scope_preview: 'For a while: Deny for process 4242 (1 minute), outgoing connections only. This ended request was not delivered.' };
    },
  });
  world.events = [endedLive(), ev('queued', { flow: { ...ev('x').flow, local: '10.1.0.1:40002' } }), ev('sibling', { attribution: { ...ev('x').attribution, owners: [{ pid: 5, start_ticks: '1', uid: 1000 }] }, flow: { ...ev('x').flow, local: '10.1.0.1:40003' } })];
  await b.pollControl();
  const ended = b.view().control.events.find((e) => e.id === 'ended');
  assert.ok(pd.endedRequest(ended));
  assert.ok(pd.endedLeaseAvailable(ended, CAPS));
  assert.equal(pd.endedLeaseReason(ended, CAPS), '');
  const plan = pd.promptPlan(ended, 'block', { generation: 'g', zoneRevision: '', capabilities: CAPS, forAWhile: true, forAWhileSeconds: 60, remember: false, fields: { ...DEFAULT_REMEMBER }, duration: 0 });
  assert.deepEqual(plan, { kind: 'ended-lease', choice: { generation: 'g', id: 'ended', action: 'block', duration_seconds: 60 } });
  const r = await b.requestForAWhile(plan.choice);
  assert.equal(r.lease.pid, 4242);
  assert.equal(pd.endedLeaseResult(r.lease), 'For a while: Deny for process 4242 (1 min). This ended request was not delivered.');
  assert.deepEqual(visible(b), ['sibling'], 'queued same-process request removed by the settled id; sibling stays');
  assert.equal(b.view().control.processLeases[0].id, 'L1');
  // No decision or rule operation; a repeated click returns the same result without a second call.
  await b.requestForAWhile(plan.choice);
  assert.equal(sent.filter((q) => q.operation === 'request-for-a-while').length, 1);
  assert.ok(!sent.some((q) => q.operation === 'decide' || /rule/.test(q.operation)));
  assert.deepEqual(sent.find((q) => q.operation === 'request-for-a-while'), { version: 1, operation: 'request-for-a-while', generation: 'g', id: 'ended', action: 'block', duration_seconds: 60 });
  assert.throws(() => pd.validateEndedLease({ ...plan.choice, duration_seconds: 20 }));
  assert.throws(() => pd.validateEndedLease({ ...plan.choice, scope: 'once' }));
});

test('ended request whose process exited: For a while unavailable with one short reason; Remember stays', async (t) => {
  const exited = endedLive({ request_rule: { available: true, process_state: 'ended', until: new Date(Date.now() + 600000).toISOString(), process_lease_available: false } });
  const { b, world, sent } = await fixture(t, { handle: () => ({ error: 'The process has exited (PID 4242); For a while has nothing to cover', error_code: 'process_ended' }) });
  world.events = [exited];
  await b.pollControl();
  const e = b.view().control.events[0];
  assert.equal(pd.endedLeaseReason(e, CAPS), 'The process has exited; For a while has nothing to cover.');
  assert.deepEqual(pd.promptPlan(e, 'block', { generation: 'g', zoneRevision: '', capabilities: CAPS, forAWhile: true, remember: false, fields: { ...DEFAULT_REMEMBER }, duration: 0 }), { kind: 'unavailable', note: pd.ENDED_PROCESS_EXITED });
  await assert.rejects(b.requestForAWhile({ generation: 'g', id: 'ended', action: 'block' }), /unavailable/);
  assert.equal(sent.filter((q) => q.operation === 'request-for-a-while').length, 0);
  // Remember -> Allow/Deny still plans the request-rule save.
  assert.equal(pd.promptPlan(e, 'allow', { generation: 'g', zoneRevision: '', capabilities: CAPS, forAWhile: false, remember: true, fields: { ...DEFAULT_REMEMBER }, duration: 0 }).kind, 'request-rule');
  // A backend refusal is shown short.
  assert.equal(pd.shortError('process_ended: The process has exited (PID 4242); For a while has nothing to cover'), pd.ENDED_PROCESS_EXITED);
  // Live process but old backend: unavailable, plain explanation.
  assert.equal(pd.endedLeaseReason(endedLive(), CAPS.filter((c) => c !== pd.REQUEST_FOR_A_WHILE_CAPABILITY)), 'Unavailable: this request has ended.');
});

test('ended card: one short main message; raw connection_ended reasons stay in Details', () => {
  const failure = { code: 'connection_ended', message: 'Connection ended: original socket is no longer present; process/executable change is not established' };
  assert.equal(pd.endedSummary(failure), 'This connection has ended.');
  assert.equal(pd.ENDED_MESSAGE, 'This connection has ended.');
  assert.equal(pd.shortError('connection_ended: ' + failure.message), 'This connection has ended.');
  assert.equal(pd.ENDED_NEEDS_CHOICE, 'Check Remember to save a rule, or For a while for the running process.');
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  assert.ok(!src.includes('reviewFailureSummary('), 'renderer uses the short ended summary');
  assert.ok(src.includes("$('revalidationDetails').textContent = failure ? `${failure.code}: ${failure.message}` : '—'"), 'raw reason in Details');
});

test('durations: offered set, saved default, expiry preview, validated decisions, backend until', async (t) => {
  const control = { capabilities: CAPS, forAWhileDurations: [15, 60, 300, 600, 1800, 3600, 7] };
  assert.deepEqual(lease.forAWhileDurations(control), DURATIONS, 'unknown values ignored');
  assert.deepEqual(lease.forAWhileDurations({ capabilities: [lease.FOR_A_WHILE_CAPABILITY] }), [15], 'old backend: fixed 15 s');
  assert.equal(lease.defaultForAWhile(300, DURATIONS), 300);
  assert.equal(lease.defaultForAWhile(300, [15]), 15, 'saved choice not offered -> 15 s');
  assert.equal(lease.defaultForAWhile('x', DURATIONS), 3600);
  assert.equal(lease.defaultForAWhile(undefined, DURATIONS), 3600);
  assert.equal(lease.defaultForAWhile(15, DURATIONS), 15, 'explicit shorter choice is preserved');
  assert.ok(lease.validForAWhileSeconds(3600) && !lease.validForAWhileSeconds(20) && !lease.validForAWhileSeconds('60'));
  assert.deepEqual(DURATIONS.map(lease.durationLabel), ['15 s', '1 min', '5 min', '10 min', '30 min', '1 h']);
  const now = new Date(2026, 9, 19, 14, 2, 0).getTime();
  assert.match(lease.expiryPreview(1800, now), /^until 14:32$/);
  assert.match(lease.expiryPreview(15, now), /^until 14:02:15$/);
  assert.match(lease.forAWhileNote(3600), /^For 1 h · /);
  // Decision shape: 15 s omits the field (compatible); others send it.
  const base = { generation: 'g', zoneRevision: '', capabilities: CAPS, forAWhile: true, remember: false, fields: { ...DEFAULT_REMEMBER }, duration: 0 };
  assert.deepEqual(pd.promptPlan(ev('a'), 'allow', { ...base, forAWhileSeconds: 15 }).decision, { generation: 'g', id: 'a', action: 'allow', scope: 'for-a-while' });
  const hour = pd.promptPlan(ev('a'), 'block', { ...base, forAWhileSeconds: 3600 }).decision;
  assert.deepEqual(hour, { generation: 'g', id: 'a', action: 'block', scope: 'for-a-while', duration_seconds: 3600 });
  assert.deepEqual(validateDecision(hour), hour);
  const initial = lease.defaultForAWhile(undefined, lease.forAWhileDurations(control));
  assert.equal(pd.promptPlan(ev('a'), 'allow', { ...base, forAWhileSeconds: initial }).decision.duration_seconds, 3600, 'first use sends a real one-hour duration rather than the legacy omitted-field default');
  assert.throws(() => validateDecision({ ...hour, duration_seconds: 20 }));
  // Remember stays exclusive with For a while.
  assert.deepEqual(lease.toggleDecisionOption({ forAWhile: true, remember: false }, 'remember', true), { forAWhile: false, remember: true });
  // Backend: sends duration_seconds, countdown from the backend's until.
  const backendUntil = new Date(Date.now() + 3600000).toISOString();
  const { b, world, sent } = await fixture(t, {
    handle: (q, w) => {
      const decided = { ...w.events[0], state: 'blocked', reason: 'for a while', lease: { id: 'L', until: backendUntil, seconds: 3600 } };
      w.events = [decided];
      w.leases = [{ id: 'L', action: 'block', direction: 'outgoing', application: 'k', executable: '/usr/bin/curl', uid: 1000, pid: 4242, start: '9', until: backendUntil, remaining_ms: 3600000, seconds: 3600, event_id: 'a' }];
      return { decision: decided };
    },
  });
  world.events = [ev('a'), ev('b')];
  await b.pollControl();
  assert.deepEqual(b.view().control.forAWhileDurations, DURATIONS);
  const result = await b.decide(hour);
  assert.equal(result.leaseUntil, backendUntil, 'result uses the backend until');
  assert.equal(sent.find((q) => q.operation === 'decide').duration_seconds, 3600);
  await b.pollControl();
  const listed = b.view().control.processLeases[0];
  assert.equal(listed.seconds, 3600);
  const t0 = Date.parse(backendUntil) - 3600000;
  assert.equal(lease.leaseLine(listed, t0 + 1000), 'For a while: Deny · process 4242 · Out · 60 min left');
  assert.equal(lease.leaseLine(listed, Date.parse(backendUntil) - 30000), 'For a while: Deny · process 4242 · Out · 30 s left');
  // A 1-hour lease keeps the popup card only briefly (15 s), not for the hour.
  assert.ok(lease.leaseHolds({ processLeases: [listed], events: [] }, 'a', t0 + 5000));
  assert.ok(!lease.leaseHolds({ processLeases: [listed], events: [] }, 'a', t0 + 20000));
  // Not offered by the backend: refused locally, nothing sent.
  world.events = [ev('c')];
  await b.pollControl();
  await assert.rejects(b.decide({ generation: 'g', id: 'c', action: 'block', scope: 'for-a-while', duration_seconds: 20 }));
  assert.equal(sent.filter((q) => q.operation === 'decide').length, 1);
});

// ---- minimal DOM for the card ----
class El {
  constructor(tag) {
    Object.assign(this, { tagName: tag.toUpperCase(), children: [], parent: null, text: '', className: '', id: '', dataset: {}, attrs: {}, hidden: false, title: '' });
  }
  set textContent(t) {
    this.children = [];
    this.text = String(t);
  }
  get textContent() {
    return this.text + this.children.map((c) => c.textContent).join('');
  }
  append(...nodes) {
    for (let n of nodes) {
      if (typeof n === 'string') {
        const t = new El('#text');
        t.text = n;
        n = t;
      }
      n.parent = this;
      this.children.push(n);
    }
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
}
function card(e, options = {}) {
  global.document = { createElement: (t) => new El(t) };
  global.Option = class extends El {
    constructor(label, value) {
      super('option');
      this.text = label;
      this.value = value;
    }
  };
  global.window = { flowgate: { applicationMetadata: async () => ({}) } };
  const { buildRequestCard } = require('../dist/test/prompt-card.cjs');
  const root = new El('div');
  root.append(...buildRequestCard(e, { name: 'curl', rememberMode: true, forAWhile: true, rememberOptions: [], ...options }));
  const all = [...root.walk()];
  return { root, byId: (id) => all.find((n) => n.id === id) };
}

test('card: duration selector beside the decision controls, hidden until For a while is checked', () => {
  const { byId } = card(ev('a'), { forAWhileDurations: DURATIONS });
  const wrap = byId('forAWhileDurationWrap');
  assert.ok(wrap && wrap.hidden, 'hidden by default (renderer shows it only with For a while)');
  assert.equal(wrap.parent.id, 'decisionControls', 'in the sticky decision row');
  assert.deepEqual(byId('forAWhileDuration').children.map((o) => [o.text, o.value]), DURATIONS.map((d) => [lease.durationLabel(d), String(d)]));
  assert.ok(byId('forAWhileExpiry'));
  const controls = byId('decisionControls').children.map((c) => c.id || c.children.find((x) => x.tagName === 'INPUT')?.id);
  assert.deepEqual(controls, ['allow', 'block', 'rememberToggle', 'forAWhileToggle', 'forAWhileDurationWrap']);
  // Old backend (only 15 s): no selector.
  assert.equal(card(ev('a'), { forAWhileDurations: [15] }).byId('forAWhileDuration'), undefined);
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  assert.match(src, /\$\('forAWhileDurationWrap'\)\.hidden = !promptID && !showLease/);
  assert.match(src, /preferences\(\{ forAWhileSeconds: seconds \}\)/, 'choice persisted in preferences');
  assert.match(src, /scope: 'for-a-while' as const,\s*\/\/[^\n]*\n\s*\.\.\.\(forAWhileSeconds !== 15/, 'card decision carries the selected duration');
});

test('card: one short line when a rule exists for an earlier revision (display only)', () => {
  const plain = card(ev('a'));
  assert.equal(plain.byId('previousRevisionNotice'), undefined);
  const { byId } = card(ev('a', { previous_revision_rules: [{ id: 'user:old', action: 'allow', revision: '1:2:3' }] }));
  // A Details field (Rule section), not a first-view line.
  const notice = byId('previousRevisionNotice');
  assert.ok(notice.text.startsWith('A rule exists for an earlier version of this application (updated executable).'));
  assert.match(notice.text, /user:old \(Allow\) · revision 1:2:3/);
  assert.match(notice.text, /Not applied/);
  assert.ok([...byId('requestMore').walk()].includes(notice));
});


test('snapshot revisions retain full uint64 precision and reject malformed metadata', () => {
  const base = { version: 1, generation: 'g', read_only: false, server_time: new Date().toISOString(), snapshot_at: new Date().toISOString() };
  assert.equal(parseReply({ ...base, snapshot_revision: '18446744073709551615' }).snapshot_revision, '18446744073709551615');
  for (const revision of [0, '0', '01', '-1', '1.5', '18446744073709551616'])
    assert.throws(() => parseReply({ ...base, snapshot_revision: revision }), /snapshot metadata/);
  assert.throws(() => parseReply({ ...base, snapshot_revision: '1', snapshot_at: 'bad' }), /snapshot metadata/);
  assert.equal(parseReply(base).snapshot_revision, undefined, 'legacy server remains supported');
  assert.throws(() => parseReply({ ...base, capabilities: ['request-list-snapshot-v1'] }), /snapshot metadata/);
});

test('snapshot revision fences survive polling after an acknowledgement and reset on generation change', async (t) => {
  const { b, world } = await fixture(t, {
    handle: (q, w) => {
      w.snapshotRevision = '9007199254740993';
      return { decision: { ...w.events[0], state: 'allowed' } };
    },
  });
  world.snapshotRevision = '9007199254740992';
  world.events = [ev('a')];
  await b.pollControl();
  assert.deepEqual(visible(b), ['a']);
  assert.equal((await b.decide({ generation: 'g', id: 'a', action: 'allow', scope: 'once' })).phase, 'acknowledged');
  world.snapshotRevision = '9007199254740992';
  await b.pollControl();
  assert.deepEqual(visible(b), [], 'older revision issued after ack cannot reopen');
  world.snapshotRevision = '9007199254740993';
  await b.pollControl();
  assert.deepEqual(visible(b), [], 'same published revision cannot undo its acknowledgement');
  world.generation = 'new-generation';
  world.snapshotRevision = '1';
  await b.pollControl();
  assert.deepEqual(visible(b), ['a'], 'restarted daemon has its own revision sequence');
});
