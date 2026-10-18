// Synthetic transport faults only. Real enforcement evidence is acceptance.mjs.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
async function fixture(t, handler) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/ipc-'));
  const endpoint = path.join(dir, 'api');
  const server = net.createServer((s) => s.once('data', (data) => handler(s, JSON.parse(data))));
  await new Promise((r) => server.listen(endpoint, r));
  t.after(() => {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return endpoint;
}
const event = () => ({
  id: 'request-1',
  state: 'awaiting-decision',
  deadline: new Date(Date.now() + 60000).toISOString(),
  flow: {},
  attribution: {},
  scope_previews: { once: 'Exact backend scope' },
});
const response = (e) => ({
  version: 1,
  generation: 'gen-1',
  read_only: false,
  mode: 'isolated-lab',
  server_time: new Date().toISOString(),
  events: [e],
});
const answer = { generation: 'gen-1', id: 'request-1', action: 'allow', scope: 'once' };
test('ambiguous acknowledgement locks request, reconnect never replays', async (t) => {
  let decisions = 0;
  const e = event();
  const endpoint = await fixture(t, (s, q) => {
    if (q.operation === 'decide') {
      assert.equal(q.generation, 'gen-1');
      decisions++;
      s.end();
    } else s.end(JSON.stringify(response(e)) + '\n');
  });
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  const result = await b.decide(answer);
  assert.equal(result.phase, 'unknown');
  await new Promise((r) => setTimeout(r, 30));
  await b.pollControl();
  await assert.rejects(() => b.decide(answer));
  assert.equal(decisions, 1);
  b.stop();
});
test('simultaneous opposing clicks send one backend operation', async (t) => {
  let decisions = 0;
  const e = event();
  const endpoint = await fixture(t, (s, q) => {
    if (q.operation === 'decide') {
      decisions++;
      setTimeout(
        () =>
          s.end(
            JSON.stringify({
              ...response(e),
              decision: { ...e, state: 'allowed', reason: 'ack' },
            }) + '\n',
          ),
        30,
      );
    } else s.end(JSON.stringify(response(e)) + '\n');
  });
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  const results = await Promise.allSettled([
    b.decide(answer),
    b.decide({ ...answer, action: 'block' }),
  ]);
  assert.equal(decisions, 1);
  assert.equal(results.filter((r) => r.status === 'rejected').length, 1);
  b.stop();
  await new Promise((r) => setTimeout(r, 30));
});
test('wrong generation acknowledgement is never reported as success', async (t) => {
  const e = event();
  const endpoint = await fixture(t, (s, q) =>
    s.end(
      JSON.stringify(
        q.operation === 'decide'
          ? { ...response(e), generation: 'new', decision: { ...e, state: 'allowed' } }
          : response(e),
      ) + '\n',
    ),
  );
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  assert.equal((await b.decide(answer)).phase, 'unknown');
  b.stop();
  await new Promise((r) => setTimeout(r, 30));
});

test('host-control response without active status cannot enable decisions', async (t) => {
  let decisions = 0;
  const e = event();
  const endpoint = await fixture(t, (s, q) => {
    if (q.operation === 'decide') decisions++;
    s.end(JSON.stringify({ ...response(e), mode: 'host-enforcement' }) + '\n');
  });
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  assert.equal(b.view().control.readOnly, true);
  await assert.rejects(() => b.decide(answer));
  assert.equal(decisions, 0);
  b.stop();
});
test('daemon stored-rule grant is independent of decisions; companion and malformed grants fail closed', async (t) => {
  let role = 'primary',
    mutations = 0;
  const endpoint = await fixture(t, (s, q) => {
    if (q.operation !== 'list') mutations++;
    const r = {
      ...response(event()),
      mode: role === 'companion' ? 'host-monitor' : 'daemon-monitor',
      backend_mode: 'daemon-monitor',
      read_only: role === 'companion',
      capabilities: ['explicit-administrator-v1'],
      permissions: {
        role: 'administrator',
        observation_scope: 'machine',
        policy_scope: 'machine',
        can_manage_rules: role !== 'companion',
        can_decide: false,
      },
      enforcement: { state: 'stopped' },
      rules: [
        {
          id: 'stored',
          version: 0,
          filter: {
            application: 'a',
            revision: 'r',
            uid: 0,
            direction: 'incoming',
            protocol: 'tcp',
          },
        },
      ],
    };
    if (role === 'invalid') r.permissions.can_decide = 'true';
    if (role === 'missing') delete r.permissions;
    s.end(JSON.stringify(r) + '\n');
  });
  const b = new Backend(endpoint, endpoint, () => {});
  const { Rules } = require('../dist/test/rules.cjs');
  const rules = new Rules(b);
  await b.pollControl();
  assert.equal(b.view().control.connected, true);
  assert.equal(b.view().control.readOnly, false);
  assert.equal((await rules.draft({ id: 'stored' })).rule.id, 'stored');
  await assert.rejects(() => b.decide(answer), /no longer actionable/);
  assert.equal(mutations, 0);
  role = 'companion';
  await b.pollControl();
  await assert.rejects(() => rules.draft({ id: 'stored' }), /read-only/);
  assert.equal(b.view().control.enforcement.state, 'stopped');
  for (role of ['invalid', 'missing']) {
    await b.pollControl();
    assert.equal(b.view().control.connected, false);
    await assert.rejects(() => b.decide(answer));
  }
  assert.equal(mutations, 0);
  b.stop();
});

test('popup refresh joins policy in flight then obtains a corresponding Activity snapshot', async () => {
  const b = Object.create(Backend.prototype),
    trace = [];
  b.readPolicy = async () => {
    trace.push('policy-start');
    await new Promise((r) => setTimeout(r, 5));
    trace.push('policy-end');
  };
  b.readObserver = async () => {
    trace.push('activity-after-policy');
  };
  b.pollControl = async () => {
    void b.pollPolicy();
  };
  b.publishPair = () => {};
  b.emit = () => {};
  b.view = () => ({ ready: true });
  const first = b.pollPolicy(),
    second = b.pollPolicy(true);
  assert.equal(first, second);
  assert.deepEqual(await b.refreshRuleContext(), { ready: true });
  assert.deepEqual(trace, ['policy-start', 'policy-end', 'activity-after-policy']);
});
