// Controlled response gates reproduce Save/list/policy ordering; no sleeps or optimistic rules.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { inventoryStamp } = require('../dist/test/inventory-coherence.cjs');
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
};
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/coherence-')),
    endpoint = path.join(dir, 's');
  let rules = [],
    generation = 'g',
    sequence = 0,
    holdList,
    holdPolicy;
  const snapshots = [];
  const rule = {
    id: 'created',
    version: 1,
    schema: 2,
    action: 'allow',
    disabled: false,
    created: new Date().toISOString(),
    expires: '0001-01-01T00:00:00Z',
    priority: 100,
    filter: {
      application: 'app',
      revision: 'r',
      uid: 1000,
      direction: 'incoming',
      protocol: 'tcp',
      remote_address: '*',
      local_port: 0,
      remote_port: 0,
    },
  };
  const base = () => ({
    version: 1,
    generation,
    read_only: false,
    mode: 'isolated-lab',
    server_time: new Date().toISOString(),
    capabilities: ['policy-explanations-v1'],
    rules: [...rules],
    events: [],
  });
  const direction = (d) => ({
    direction: d,
    configured: rules.length ? 'uniform' : 'absent',
    action: rules.length ? 'allow' : '',
    reason: 'test',
    rules: rules.map((r) => ({
      id: r.id,
      version: String(r.version),
      action: r.action,
      priority: 100,
      scope: r.filter,
      disabled: r.disabled,
      expired: false,
      active: !r.disabled,
      expires: r.expires,
    })),
    active_rules: rules.length,
    disabled_rules: 0,
    expired_rules: 0,
    potential_overlapping_actions: false,
    configured_default: { known: false, reason: 'test' },
    runtime_default: { known: false, reason: 'test' },
    enforcement: { state: 'stopped', covered: false, reason: 'test' },
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw),
        r = base();
      if (q.operation === 'policy-view')
        r.policy_view = {
          snapshot: {
            generation,
            token: 's' + ++sequence,
            sequence: String(sequence),
            evaluated_at: new Date().toISOString(),
            meaning: 'test',
          },
          activity_sequence: '1',
          activity_collected: new Date().toISOString(),
          activity_available: true,
          complete: true,
          applications: [
            {
              ref: 'a',
              identity: { key: 'app', revision: 'r', uid: 1000 },
              process_ids: ['p'],
              incoming: direction('incoming'),
              outgoing: direction('outgoing'),
            },
          ],
          rows: [],
        };
      const gate = q.operation === 'policy-view' ? holdPolicy : holdList;
      if (gate) {
        if (q.operation === 'policy-view') holdPolicy = undefined;
        else holdList = undefined;
        gate.resolve(() => s.end(JSON.stringify(r) + '\n'));
      } else s.end(JSON.stringify(r) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, (s) =>
    snapshots.push({
      generation: s.control.generation,
      list: s.control.rules?.map((r) => [r.id, r.version, r.disabled]),
      policy: s.control.policy?.applications[0].incoming.rules.map((r) => [
        r.id,
        Number(r.version),
        r.disabled,
      ]),
    }),
  );
  t.after(() => {
    b.stop();
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await b.pollControl();
  await b.pollPolicy(true);
  return {
    b,
    snapshots,
    rule,
    setRules: (r) => (rules = r),
    holdList: () => {
      holdList = deferred();
      return holdList.promise;
    },
    holdPolicy: () => {
      holdPolicy = deferred();
      return holdPolicy.promise;
    },
    restart: () => (generation = 'new'),
  };
}
test('fresh policy before fresh list publishes one coherent saved state, no blink', async (t) => {
  const x = await fixture(t);
  x.setRules([x.rule]);
  await x.b.pollPolicy(true);
  assert.deepEqual(x.b.view().control.rules, []);
  assert.deepEqual(x.b.view().control.policy.applications[0].incoming.rules, []);
  await x.b.pollControl();
  await x.b.pollPolicy(true);
  assert.equal(x.b.view().control.rules[0].id, 'created');
  for (const s of x.snapshots.filter((s) => s.policy)) assert.deepEqual(s.list, s.policy);
  x.setRules([{ ...x.rule, version: 2, disabled: true }]);
  await x.b.pollControl();
  await x.b.pollPolicy(true);
  assert.equal(x.b.view().control.rules[0].disabled, true);
  x.setRules([]);
  await x.b.pollControl();
  await x.b.pollPolicy(true);
  assert.equal(x.b.view().control.rules.length, 0);
});
test('pre-Save held list cannot overwrite post-Save refresh and callers join new read', async (t) => {
  const x = await fixture(t),
    held = x.holdList(),
    old = x.b.pollControl(),
    release = await held;
  await x.b.ruleMutation(async () => {
    x.setRules([x.rule]);
    release();
  });
  await old;
  assert.equal(x.b.view().control.rules[0].id, 'created');
  for (const s of x.snapshots.filter((s) => s.policy)) assert.deepEqual(s.list, s.policy);
});
test('late policy response from old daemon is discarded on restart', async (t) => {
  const x = await fixture(t),
    held = x.holdPolicy(),
    old = x.b.pollPolicy(true),
    release = await held;
  x.restart();
  await x.b.pollControl();
  release();
  await old;
  await x.b.pollPolicy(true);
  assert.equal(x.b.view().control.policy.snapshot.generation, 'new');
});
test('whole inventory equality ignores array ordering, never per-rule snapshot ordering', () => {
  const r = {
    generation: 'g',
    rules: [
      { id: 'b', version: 1 },
      { id: 'a', version: 4 },
    ],
    rule_states: { b: { state: 'active' }, a: { state: 'inactive' } },
    capabilities: [],
    read_only: false,
    mode: 'x',
  };
  assert.equal(
    inventoryStamp(r),
    inventoryStamp({
      ...r,
      rules: [...r.rules].reverse(),
      rule_states: { a: r.rule_states.a, b: r.rule_states.b },
    }),
  );
  assert.notEqual(
    inventoryStamp(r),
    inventoryStamp({ ...r, rules: [r.rules[0], { id: 'a', version: 5 }] }),
  );
});
test('metadata waits for corresponding Activity, then list and policy publish together', async (t) => {
  const x = await fixture(t);
  x.b.state.observation = {
    connected: true,
    generation: 'g',
    activity: {
      sequence: 0,
      collected: new Date(Date.now() - 1000).toISOString(),
      rows: [],
      processes: {},
    },
  };
  x.setRules([x.rule]);
  await x.b.pollControl();
  await x.b.pollPolicy(true);
  assert.equal(x.b.view().control.rules.length, 0);
  x.b.state.observation.activity.sequence = 1;
  x.b.state.observation.activity.collected = new Date(Date.now() + 1000).toISOString();
  x.b.publishPair();
  assert.equal(x.b.view().control.rules[0].id, 'created');
  assert.equal(x.b.view().control.policy.applications[0].incoming.rules[0].id, 'created');
});
