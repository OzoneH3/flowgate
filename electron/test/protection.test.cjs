// Controlled Unix replies: frontend lifecycle/fault evidence, not kernel acceptance.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { Protection } = require('../dist/test/protection.cjs');
const {
  parseProtection,
  protectionLabel,
  protectionTokens,
} = require('../dist/test/protection-model.cjs');
const status = () => ({
  id: '',
  request_id: '',
  desired_mode: 'monitoring',
  state: 'stopped',
  profile: 'both',
  cleanup: 'not_needed',
  reason_code: 'stopped',
  reason: 'fixture',
  readiness: { state: 'ready', checked_at: new Date().toISOString(), checks: [] },
  existing_connections: 'preserved',
  failure_policy: 'new flows fail closed',
  gui_required: false,
});
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/protect-')),
    endpoint = dir + '/api';
  const f = {
    generation: 'one',
    permit: true,
    cap: true,
    p: status(),
    calls: [],
    drop: false,
    hold: undefined,
  };
  const reply = () => ({
    version: 1,
    generation: f.generation,
    read_only: false,
    mode: 'daemon-monitor',
    server_time: new Date().toISOString(),
    capabilities: ['explicit-administrator-v1', ...(f.cap ? ['continuous-firewall-v1'] : [])],
    permissions: {
      role: 'administrator',
      policy_scope: 'machine',
      observation_scope: 'machine',
      can_manage_rules: true,
      can_decide: f.p.state === 'active',
      can_control_protection: f.permit,
    },
    events: [],
    rules: [],
    protection: f.p,
  });
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      f.calls.push(q);
      if (q.operation === 'protection-start') {
        f.p = {
          ...f.p,
          id: 'a'.repeat(32),
          request_id: q.request_id,
          desired_mode: q.profile,
          profile: q.profile,
          state: 'active',
        };
        if (f.drop) {
          s.end();
          return;
        }
      }
      if (q.operation === 'protection-stop')
        f.p = { ...f.p, desired_mode: 'monitoring', state: 'stopped', cleanup: 'confirmed' };
      if (f.hold && q.operation === 'protection-start') {
        f.hold(() => s.end(JSON.stringify(reply()) + '\n'));
        return;
      }
      s.end(JSON.stringify(reply()) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const backend = new Backend(endpoint, endpoint, () => {});
  await backend.pollControl();
  const p = new Protection(backend);
  t.after(() => {
    backend.stop();
    server.close();
    fs.rmSync(dir, { force: true, recursive: true });
  });
  return {
    ...f,
    get pstate() {
      return f.p;
    },
    f,
    backend,
    protection: p,
  };
}
test('strict protection metadata, phase labels and tokens never infer active from desire', () => {
  const p = status();
  assert(parseProtection(p));
  assert.equal(parseProtection({ ...p, gui_required: true }), undefined);
  assert.equal(parseProtection({ ...p, state: 'ready' }), undefined);
  assert.match(protectionLabel({ ...p, desired_mode: 'both', state: 'failed' }, true), /failed/);
  assert.match(
    protectionLabel({ ...p, state: 'active', profile: 'both' }, true),
    /Incoming \+ outgoing.*active/,
  );
  assert.match(protectionLabel({ ...p, state: 'active' }, false), /unknown/);
  assert.throws(() =>
    protectionTokens({ generation: 'one', protectionId: '', profile: 'both', operation: 'start' }),
  );
});
test('Start/Stop exact session/profile; refresh authoritative state, no evaluation fallback', async (t) => {
  const { protection: p, backend: b, f } = await fixture(t);
  let v = p.view();
  assert(v.canStart);
  await p.action('start', { ...v.tokens, profile: 'both' });
  await b.pollControl();
  v = p.view();
  assert.match(v.label, /outgoing.*active/);
  assert(!v.canStart);
  assert(v.canStop);
  const q = f.calls.find((q) => q.operation === 'protection-start');
  assert.equal(q.profile, 'both');
  assert.match(q.request_id, /^[a-f0-9]{32}$/);
  await p.action('stop', v.tokens);
  await b.pollControl();
  assert.match(p.view().label, /Monitoring only/);
  const stop = f.calls.find((q) => q.operation === 'protection-stop');
  assert.equal(stop.protection_id, 'a'.repeat(32));
  assert(!('request_id' in stop));
  assert(!f.calls.some((q) => q.operation.startsWith('evaluation')));
});
test('lost Start ACK reconciles from status with one write, restart/disconnect unknown', async (t) => {
  const { protection: p, backend: b, f } = await fixture(t);
  f.drop = true;
  await p.action('start', p.view().tokens);
  await b.pollControl();
  assert.match(p.view().label, /active/);
  assert.equal(f.calls.filter((q) => q.operation === 'protection-start').length, 1);
  b.state.control.connected = false;
  assert.match(p.view().label, /unknown/);
  assert(!p.view().canStop);
  f.generation = 'two';
  f.p = status();
  await b.pollControl();
  assert.equal(p.view().tokens.generation, 'two');
  assert.match(p.view().label, /Monitoring only/);
  assert.equal(f.calls.filter((q) => q.operation === 'protection-start').length, 1);
});
test('held Start blocks competing Stop and stale generation cannot complete as active', async (t) => {
  const { protection: p, backend: b, f } = await fixture(t);
  let release, held;
  const gate = new Promise((r) => (held = r));
  f.hold = (r) => {
    release = r;
    held();
  };
  const task = p.action('start', p.view().tokens);
  await gate;
  await assert.rejects(() => p.action('stop', p.view().tokens));
  f.generation = 'two';
  f.p = status();
  await b.pollControl();
  release();
  await task;
  await b.pollControl();
  assert.match(p.view().label, /Monitoring only/);
  assert.equal(f.calls.filter((q) => q.operation === 'protection-start').length, 1);
});
test('old capability, explicit permission denial and unknown metadata disable mutation', async (t) => {
  const { protection: p, backend: b, f } = await fixture(t);
  f.permit = false;
  await b.pollControl();
  assert(!p.view().canStart);
  await assert.rejects(() => p.action('start', p.view().tokens));
  f.cap = false;
  await b.pollControl();
  assert(!p.view().canStart);
  assert.equal(f.calls.filter((q) => q.operation.startsWith('protection-')).length, 0);
});
