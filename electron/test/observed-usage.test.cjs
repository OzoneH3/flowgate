const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { parseUsageSnapshot, formatUsage, usageCounter, USAGE_CAPABILITY } = require('../dist/test/observed-usage.cjs');
const { ObservedUsageClient } = require('../dist/test/observed-usage-client.cjs');

const entry = (extra = {}) => ({ id: 'entry-a', uid: 1000,
  application: { key: 'app-a', revision: 'revision-a', name: 'Synthetic application', kind: 'native' },
  source: 'tcp-transport-payload', uploaded: '9007199254740993', downloaded: '12',
  first_observed_at: '2026-10-23T10:00:00Z', last_observed_at: '2026-10-23T10:01:00Z', partial: true, ...extra });
const snapshot = (extra = {}) => ({ version: 1, epoch: 'epoch-a', sequence: '5',
  started_at: '2026-10-23T10:00:00Z', sampled_at: '2026-10-23T10:01:00Z', scope: 'user',
  partial: true, attribution: 'sampled-owner', capacity_limited: false, saturated: false,
  sources: [{ source: 'tcp-transport-payload', state: 'active', reason: 'Sampled TCP payload.' },
    { source: 'udp-api-reported', state: 'unavailable', reason: 'Collector disabled; no UDP measurements.' }],
  entries: [entry()], ...extra });

test('exact counter formatting never rounds through JavaScript Number', () => {
  assert.equal(formatUsage('9007199254740993', 'B'), '9007199254740993 B');
  assert.equal(formatUsage('18446744073709551615', 'bit'), '147573952589676412920 bit');
  assert.equal(formatUsage('1234567', 'MB'), '1.23 MB');
  assert.equal(formatUsage('1', 'MB'), '<0.01 MB');
  assert.equal(formatUsage('0'), '0 B');
  for (const bad of [1, '1e3', '-1', '+1', '01', '', '1.1', '18446744073709551616'])
    assert.throws(() => usageCounter(bad));
});

test('retained entries remain separate by server identity and source, independent of Activity', () => {
  const a = entry(), b = entry({ id: 'entry-b', uid: 1001 }), udp = entry({ id: 'entry-udp', source: 'udp-api-reported' });
  const parsed = parseUsageSnapshot(snapshot({ entries: [a, b, udp] }));
  assert.equal(parsed.entries.length, 3);
  assert.equal(parsed.entries.find((r) => r.id === a.id).uploaded, '9007199254740993');
  assert.equal(parsed.entries.filter((r) => r.source === 'udp').length, 1);
  assert.match(parsed.coverage, /UDP API bytes: unavailable/);
  assert.throws(() => parseUsageSnapshot(snapshot({ entries: [a, a] })), /identity/);
});

test('unavailable, capped and frozen states remain explicit; no missing values turn into zero', () => {
  const parsed = parseUsageSnapshot(snapshot({ capacity_limited: true, saturated: true }));
  assert.match(parsed.coverage, /accumulation is frozen/);
  assert.match(parsed.coverage, /totals are capped/);
  assert.throws(() => parseUsageSnapshot(snapshot({ entries: [entry({ uploaded: undefined })] })));
  assert.throws(() => parseUsageSnapshot(snapshot({ partial: false })));
  assert.throws(() => parseUsageSnapshot(snapshot({ attribution: 'continuous-owner' })));
  assert.throws(() => parseUsageSnapshot(snapshot({ sources: [] })));
  assert.throws(() => parseUsageSnapshot(snapshot({ entries: Array.from({ length: 1025 }, (_, i) => entry({ id: String(i) })) })));
});

test('user responses cannot contain machine gap or unattributed counters', () => {
  for (const extra of [{ gaps: '0' }, { unattributed: [] }])
    assert.throws(() => parseUsageSnapshot(snapshot(extra)), /machine accounting/);
  const parsed = parseUsageSnapshot(snapshot({ scope: 'machine', gaps: '12', unattributed: [
    { source: 'tcp-transport-payload', uploaded: '9', downloaded: '8' },
  ] }));
  assert.equal(parsed.scope, 'machine');
  assert.equal(parsed.entries.find((r) => r.application === '').uid, undefined);
  assert.match(parsed.coverage, /Coverage breaks \(including ended socket baselines\): 12/);
});

test('initial empty interval has no invented sample time', () => {
  const parsed = parseUsageSnapshot(snapshot({ sequence: '0', sampled_at: undefined, entries: [] }));
  assert.equal(parsed.observedAt, undefined);
  assert.equal(parsed.entries.length, 0);
  assert.throws(() => parseUsageSnapshot(snapshot({ started_at: 'yesterday' })));
});

async function harness(t) {
  const workspace = path.resolve(__dirname, '../../.workspace');
  fs.mkdirSync(workspace, { recursive: true });
  const dir = fs.mkdtempSync(path.join(workspace, 'usage-'));
  const socket = path.join(dir, 's');
  const calls = [];
  let responder = () => ({ observed_usage: snapshot() });
  const sockets = new Set();
  const server = net.createServer((s) => {
    sockets.add(s); s.on('close', () => sockets.delete(s));
    s.once('data', async (b) => {
      const q = JSON.parse(b); calls.push(q);
      const payload = await responder(q);
      s.end(JSON.stringify({ version: 1, generation: 'g1', read_only: true, mode: 'daemon-monitor',
        server_time: new Date().toISOString(), ...payload }) + '\n');
    });
  });
  await new Promise((resolve) => server.listen(socket, resolve));
  t.after(async () => {
    for (const s of sockets) s.destroy();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const permissions = { role: 'user', observation_scope: 'self' };
  const state = { control: { connected: true, generation: 'g1', capabilities: [USAGE_CAPABILITY], permissions },
    observation: { connected: true, generation: 'g1', capabilities: [USAGE_CAPABILITY], permissions } };
  const backend = { controller: socket, observer: socket, view: () => state };
  return { state, calls, backend, client: new ObservedUsageClient(backend), respond: (fn) => { responder = fn; } };
}

test('actual Unix API reads are read-only and overlapping refreshes share one request', async (t) => {
  const h = await harness(t);
  let release;
  h.respond(() => new Promise((resolve) => { release = resolve; }));
  const a = h.client.read(), b = h.client.read();
  assert.equal(a, b);
  while (!release) await new Promise((r) => setTimeout(r, 1));
  release({ observed_usage: snapshot() });
  assert.equal((await a).snapshot.entries.length, 1);
  assert.deepEqual(h.calls, [{ version: 1, operation: 'observed-usage', generation: 'g1' }]);
});

test('stale daemon generation, permission changes and disconnect discard in-flight data', async (t) => {
  for (const change of [
    (h) => { h.state.control.generation = 'g2'; },
    (h) => { h.state.control.permissions = { role: 'administrator', observation_scope: 'machine' }; },
    (h) => { h.state.control.connected = h.state.observation.connected = false; },
  ]) {
    const h = await harness(t);
    h.respond(() => { change(h); return { observed_usage: snapshot() }; });
    const result = await h.client.read();
    assert.equal(result.snapshot, undefined);
    assert.match(result.message, /connection changed/);
  }
});

test('machine scope needs administrator evidence and errors never retain old totals', async (t) => {
  const h = await harness(t);
  assert((await h.client.read()).snapshot);
  h.respond(() => ({ observed_usage: snapshot({ scope: 'machine', gaps: '1' }) }));
  assert.match((await h.client.read()).message, /administrator/);
  h.respond(() => ({ error: 'Accounting unavailable', error_code: 'unavailable' }));
  const result = await h.client.read();
  assert.equal(result.snapshot, undefined);
  assert.equal(result.message, 'Accounting unavailable');
});

test('sequence regression is refused within an epoch; a new epoch starts a new interval', async (t) => {
  const h = await harness(t);
  assert.equal((await h.client.read()).snapshot.sequence, '5');
  h.respond(() => ({ observed_usage: snapshot({ sequence: '4' }) }));
  assert.match((await h.client.read()).message, /older observation/);
  h.respond(() => ({ observed_usage: snapshot({ epoch: 'epoch-b', sequence: '1', entries: [] }) }));
  const next = await h.client.read();
  assert.equal(next.snapshot.epoch, 'epoch-b');
  assert.equal(next.snapshot.entries.length, 0);
});

test('old daemons are not queried; read-only companion can serve the new capability', async (t) => {
  const h = await harness(t);
  h.state.control.capabilities = [];
  h.state.observation.capabilities = [];
  assert.equal((await h.client.read()).supported, false);
  assert.equal(h.calls.length, 0);
  h.state.observation.capabilities = [USAGE_CAPABILITY];
  assert((await h.client.read()).snapshot);
  assert.equal(h.calls.length, 1);
});
