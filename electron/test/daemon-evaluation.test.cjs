// SYNTHETIC Unix replies: lifecycle/IPC model evidence, not firewall acceptance.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { DaemonEvaluation } = require('../dist/test/daemon-evaluation.cjs');
const {
  evaluationLabel,
  parseEvaluation,
  evaluationTokens,
} = require('../dist/test/evaluation-model.cjs');
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/eval-model-'));
  const f = {
    generation: 'g1',
    permit: true,
    drop: false,
    delay: 0,
    cap: true,
    calls: [],
    e: {
      review: 'SYNTHETIC review: incoming only, stored rules apply, unmatched asks, five minutes.',
      unsupported_outgoing: 'SYNTHETIC incoming-only contract',
      id: '',
      request_id: '',
      state: 'stopped',
      profile: 'incoming',
      duration_seconds: 300,
      cleanup: 'not_needed',
      stops_at: '',
      reason_code: 'stopped',
      reason: 'Fixture',
      readiness: { state: 'ready', checked_at: new Date().toISOString(), checks: [] },
    },
  };
  const response = (ro) => ({
    version: 1,
    generation: f.generation,
    read_only: ro,
    mode: ro ? 'host-monitor' : 'daemon-monitor',
    backend_mode: 'daemon-monitor',
    server_time: new Date().toISOString(),
    capabilities: ['explicit-administrator-v1', ...(f.cap ? ['daemon-evaluation-v1'] : [])],
    permissions: {
      role: 'administrator',
      policy_scope: 'machine',
      observation_scope: 'machine',
      can_manage_rules: !ro,
      can_decide: false,
      can_control_evaluation: f.permit && !ro,
    },
    evaluation: f.e,
    activity: {
      sequence: 1,
      collected: new Date().toISOString(),
      complete: true,
      rows: [],
      processes: {},
    },
  });
  const servers = [];
  for (const ro of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', async (b) => {
        const q = JSON.parse(b);
        let r = response(ro);
        if (q.operation.startsWith('evaluation-')) {
          f.calls.push(q);
          if (ro && q.operation !== 'evaluation-readiness') {
            r.error = 'read only';
            r.error_code = 'forbidden';
          } else if (q.generation !== f.generation) {
            r.error = 'changed';
            r.error_code = 'generation_conflict';
          } else if (q.operation === 'evaluation-start') {
            f.e = {
              ...f.e,
              id: 'session1',
              request_id: q.request_id,
              state: 'active',
              cleanup: 'pending',
              stops_at: new Date(Date.now() + 300000).toISOString(),
            };
            r = response(ro);
          } else if (q.operation === 'evaluation-stop') {
            f.e = { ...f.e, state: 'stopped', cleanup: 'confirmed' };
            r = response(ro);
          }
          if (f.drop) {
            s.end();
            return;
          }
          if (f.delay) await new Promise((r) => setTimeout(r, f.delay));
        }
        s.end(JSON.stringify(r) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, ro ? 'm' : 'c'), r));
    servers.push(server);
  }
  const b = new Backend(path.join(dir, 'm'), path.join(dir, 'c'), () => {});
  await b.pollObserver();
  await b.pollControl();
  const d = new DaemonEvaluation(b);
  t.after(() => {
    b.stop();
    servers.forEach((s) => s.close());
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { ...f, f, b, d };
}
test('readiness/start/stop fixed operations, original deadline and fresh request nonce', async (t) => {
  const { f, b, d } = await fixture(t);
  assert(d.supported());
  await d.action('status', d.view().tokens);
  await d.action('start', d.view().tokens);
  assert.equal(f.calls[1].profile, 'incoming');
  assert.match(f.calls[1].request_id, /^[a-f0-9]{32}$/);
  assert.equal(d.view().phase, 'active');
  assert.match(d.view().label, /Incoming firewall/);
  const deadline = f.e.stops_at;
  await assert.rejects(d.action('start', d.view().tokens));
  assert.equal(f.e.stops_at, deadline);
  await d.action('stop', d.view().tokens);
  assert.equal(d.view().phase, 'stopped');
  assert.equal(f.calls.length, 3);
  assert.equal(f.e.cleanup, 'confirmed');
});
test('rules permission does not confer evaluation authority; read-only cannot mutate', async (t) => {
  const { f, b, d } = await fixture(t);
  f.permit = false;
  await b.pollControl();
  assert.equal(d.view().canStart, false);
  await assert.rejects(d.action('start', d.view().tokens));
  b.controller = b.observer;
  await b.pollControl();
  assert.equal(d.view().canStop, false);
  await assert.rejects(d.action('stop', d.view().tokens));
  assert.equal(f.calls.length, 0);
});
test('confirmation freezes generation and session; stale review is never silently refreshed', async (t) => {
  const { f, b, d } = await fixture(t);
  const old = d.view().tokens;
  f.e.id = 'other';
  await b.pollControl();
  await assert.rejects(d.action('start', old), /session changed/);
  const current = d.view().tokens;
  f.generation = 'g2';
  await b.pollControl();
  await assert.rejects(d.action('start', current), /session changed/);
  assert.equal(f.calls.length, 0);
});
test('lost Start acknowledgement reconciles and is not replayed', async (t) => {
  const { f, b, d } = await fixture(t);
  f.drop = true;
  await d.action('start', d.view().tokens);
  assert.equal(d.view().phase, 'active');
  assert.match(d.view().message, /reconciled|uncertain/i);
  await b.pollControl();
  d.view();
  assert.equal(f.calls.length, 1);
});
test('duplicate submission locked, late old-generation response discarded', async (t) => {
  const { f, b, d } = await fixture(t);
  f.delay = 40;
  const token = d.view().tokens;
  const first = d.action('start', token);
  await assert.rejects(d.action('start', token));
  await new Promise((r) => setTimeout(r, 10));
  f.generation = 'new';
  await b.pollControl();
  await first;
  assert.match(d.view().message, /generation changed|uncertain/i);
  assert.equal(f.calls.length, 1);
});
test('capability recognition sticks across disconnect/downgrade; no legacy fallback', async (t) => {
  const { f, b, d } = await fixture(t);
  assert(d.supported());
  b.state.control.connected = false;
  b.state.observation.connected = false;
  assert.equal(d.view().phase, 'unknown');
  assert.equal(d.view().canStart, false);
  f.cap = false;
  await b.pollControl();
  await b.pollObserver();
  assert(d.supported());
  assert.equal(d.view().canStart, false);
});
test('countdown never asserts cleanup; malformed metadata and generic payloads rejected', () => {
  const raw = {
    id: 'a',
    request_id: 'b',
    state: 'active',
    profile: 'incoming',
    duration_seconds: 300,
    cleanup: 'pending',
    stops_at: '',
    readiness: { state: 'ready', checks: [] },
  };
  assert.match(evaluationLabel(parseEvaluation(raw), 0), /awaiting expiry confirmation/);
  assert.equal(parseEvaluation({ ...raw, profile: 'both' }), undefined);
  for (const value of [null, {}, { generation: 'g', evaluationId: 'x', command: 'sh' }])
    assert.throws(() => evaluationTokens(value));
});

test('recognized daemon route cannot launch the legacy authentication bridge', async (t) => {
  const { Evaluation } = require('../dist/test/evaluation.cjs');
  const { b } = await fixture(t);
  const wrapper = new Evaluation(
    path.resolve(__dirname, '../../.workspace/nonexistent-eval-root'),
    b,
  );
  t.after(() => wrapper.close());
  assert.equal(wrapper.view().mode, 'daemon');
  await assert.rejects(wrapper.action('start', 'incoming'), /Invalid evaluation session tokens/);
});
