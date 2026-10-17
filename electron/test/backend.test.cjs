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
