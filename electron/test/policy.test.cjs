// Labelled synthetic policy contract/transport edge cases; not enforcement evidence.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'),
  path = require('node:path'),
  net = require('node:net');
const { parsePolicyView, authoritativePolicy, policyLabel } = require('../dist/test/policy.cjs');
const { Backend } = require('../dist/test/backend.cjs');
const identity = { key: 'app', revision: 'rev', uid: 1000 };
const direction = (d) => ({
  direction: d,
  configured: 'absent',
  reason: 'No explicit rule',
  rules: [],
  active_rules: 0,
  disabled_rules: 0,
  expired_rules: 0,
  potential_overlapping_actions: false,
  configured_default: { known: true, action: 'ask', reason: 'Pure evaluator default' },
  runtime_default: { known: false, reason: 'No active profile' },
  enforcement: { state: 'stopped', covered: false, reason: 'Stored only' },
});
const view = (sequence = '1', generation = 'g') => ({
  snapshot: {
    generation,
    token: 'policy-token',
    sequence,
    evaluated_at: new Date().toISOString(),
    meaning: 'Current policy, not history',
  },
  activity_sequence: '3',
  activity_collected: new Date().toISOString(),
  activity_available: true,
  complete: true,
  applications: [
    {
      ref: 'ref',
      identity,
      process_ids: ['pid:start'],
      incoming: direction('incoming'),
      outgoing: direction('outgoing'),
    },
  ],
  rows: [
    {
      row_id: 'socket',
      status: 'observed_native',
      reason: 'observed',
      application_ref: 'ref',
      decision_authority: false,
    },
  ],
});
const processIdentity = {
  id: 'pid:start',
  uid: 1000,
  application: { key: 'app', revision: 'rev' },
};
const state = (v) => ({
  control: { connected: true, generation: 'g', policy: v, serverNow: Date.now() },
  observation: {
    connected: true,
    generation: 'g',
    activity: {
      sequence: 3,
      collected: new Date().toISOString(),
      processes: { 'pid:start': processIdentity },
    },
  },
});
test('exact decimal versions and sequences remain strings; malformed/unsafe policy rejects', () => {
  const v = view('18446744073709551615');
  v.applications[0].incoming.rules.push({
    id: 'r',
    version: '18446744073709551615',
    action: 'block',
    priority: 1,
    scope: {
      application: 'app',
      revision: 'rev',
      uid: 1000,
      direction: 'incoming',
      protocol: 'tcp',
    },
    disabled: false,
    expired: false,
    active: true,
    expires: '0001-01-01T00:00:00Z',
  });
  const got = parsePolicyView(v);
  assert.equal(got.snapshot.sequence, '18446744073709551615');
  assert.equal(got.applications[0].incoming.rules[0].version, '18446744073709551615');
  v.snapshot.sequence = 9007199254740992;
  assert.throws(() => parsePolicyView(v));
  v.snapshot.sequence = '18446744073709551616';
  assert.throws(() => parsePolicyView(v));
});
test('summary uses only backend association and classification; shared/reused/expired/disconnected identities refuse', () => {
  const v = parsePolicyView(view()),
    s = state(v),
    row = {
      kind: 'socket',
      socket: { id: 'socket', owners: ['pid:start'], ownership_category: 'visible-holder' },
    };
  assert.equal(authoritativePolicy(row, s).application.ref, 'ref');
  assert.equal(
    authoritativePolicy(
      { ...row, socket: { ...row.socket, display_application: { name: 'display metadata' } } },
      s,
    ).application.ref,
    'ref',
  );
  assert.equal(
    authoritativePolicy({ ...row, socket: { ...row.socket, owners: ['pid:start', 'other'] } }, s)
      .application,
    undefined,
  );
  assert.equal(
    authoritativePolicy(
      { ...row, socket: { ...row.socket, ownership_category: 'holder-changed' } },
      s,
    ).application,
    undefined,
  );
  assert.equal(
    policyLabel({ ...v.applications[0].incoming, configured: 'mixed', rules: [{}, {}] }),
    'Mixed · 2',
  );
  assert.equal(authoritativePolicy({ ...row, displayApplication: {} }, s).application, undefined);
  assert.equal(
    authoritativePolicy({ ...row, socket: { id: 'reused', owners: ['pid:start'] } }, s).application,
    undefined,
  );
  s.observation.generation = 'other';
  assert.equal(authoritativePolicy(row, s).application, undefined);
  s.observation.generation = 'g';
  v.snapshot.valid_until = new Date(Date.now() - 1).toISOString();
  assert.equal(authoritativePolicy(row, s).application, undefined);
  delete v.snapshot.valid_until;
  s.control.connected = false;
  assert.equal(authoritativePolicy(row, s).application, undefined);
});
const pause = () => new Promise((r) => setTimeout(r, 10));
async function until(fn) {
  for (let i = 0; i < 100; i++) {
    if (fn()) return;
    await pause();
  }
  throw Error('timeout');
}
test('batch transport rejects old generation and sequence, clears disconnect, never per-row polls', async (t) => {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/policy-contract-')),
    endpoint = path.join(dir, 's');
  let generation = 'g',
    seq = '2',
    hold = false,
    held,
    fail = false,
    reads = 0;
  const reply = () => ({
    version: 1,
    generation,
    read_only: false,
    mode: 'isolated-lab',
    server_time: new Date().toISOString(),
    capabilities: ['policy-explanations-v1'],
    events: [],
    rules: [],
  });
  const server = net.createServer((s) =>
    s.once('data', (bytes) => {
      const q = JSON.parse(bytes);
      if (fail) return s.end();
      if (q.operation === 'policy-view') {
        reads++;
        const r = { ...reply(), policy_view: view(seq, generation) };
        if (hold) {
          held = () => s.end(JSON.stringify(r) + '\n');
          return;
        }
        s.end(JSON.stringify(r) + '\n');
      } else s.end(JSON.stringify(reply()) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, () => {});
  t.after(() => {
    b.stop();
    held?.();
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await b.pollControl();
  await until(() => !!b.view().control.policy);
  assert.equal(reads, 1);
  await b.pollControl();
  assert.equal(reads, 1); // throttled batch, not row count
  b.policyLast = -Infinity;
  seq = '1';
  await b.pollPolicy();
  assert.equal(b.view().control.policy, undefined);
  assert.match(b.view().control.policyError, /Out-of-order/);
  hold = true;
  b.policyLast = -Infinity;
  seq = '3';
  const pending = b.pollPolicy();
  await until(() => !!held);
  generation = 'new';
  await b.pollControl();
  held();
  await pending;
  assert.equal(b.view().control.policy, undefined);
  hold = false;
  b.policyLast = -Infinity;
  seq = '1';
  await b.pollPolicy();
  assert.equal(b.view().control.policy.snapshot.generation, 'new');
  fail = true;
  await b.pollControl();
  assert.equal(b.view().control.policy, undefined);
  assert.equal(b.view().control.connected, false);
});
