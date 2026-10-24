const { test } = require('node:test'),
  assert = require('node:assert/strict');
const {
  parseHistory,
  parseHistorySettings,
  parseHistoryQuery,
} = require('../dist/test/usage-history.cjs');
const { UsageHistoryClient } = require('../dist/test/usage-history-client.cjs');
const now = '2026-10-24T12:00:00Z',
  id = 'a'.repeat(64),
  epoch = 'b'.repeat(32);
const settings = { enabled: true, retention_days: 7, revision: '2' };
const snapshot = {
  version: 1,
  scope: 'user',
  partial: true,
  state: 'recording',
  settings,
  source: 'tcp-transport-payload',
  from: '2026-10-24T11:00:00Z',
  until: now,
  resolution_seconds: 300,
  entries: [
    {
      id,
      uid: 1000,
      application: { key: 'app-a', revision: 'rev-a', kind: 'native', name: 'Recorded alpha' },
      source: 'tcp-transport-payload',
      uploaded: '9007199254740993',
      downloaded: '0',
      partial: true,
    },
  ],
  points: [
    {
      at: '2026-10-24T11:05:00Z',
      uploaded: '9007199254740993',
      downloaded: '0',
      observed_buckets: 1,
      epoch_count: 1,
      flags: 0,
      partial: true,
    },
  ],
  epochs: [{ epoch, daemon_generation: 'old-daemon', started_at: '2026-10-24T10:00:00Z' }],
};
test('history preserves exact integers, sparse bins and distinct recorded identity', () => {
  const s = parseHistory(snapshot);
  assert.equal(s.points[0].uploaded, '9007199254740993');
  assert.equal(s.points.length, 1);
  assert.equal(s.entries[0].key, 'app-a');
  assert.equal(s.epochs[0].daemon_generation, 'old-daemon');
  assert.equal(s.source, 'tcp-transport-payload');
  assert.deepEqual(parseHistoryQuery({ range: '30d', source: 'udp-api-reported' }), {
    range: '30d',
    source: 'udp-api-reported',
  });
});
test('history rejects foreign diagnostics, malformed bounded fields and mixed sources', () => {
  for (const raw of [
    { ...snapshot, last_commit_at: now },
    { ...snapshot, error: 'machine' },
    { ...snapshot, points: Array(513).fill(snapshot.points[0]) },
    { ...snapshot, source: 'all' },
    { ...snapshot, entries: [{ ...snapshot.entries[0], source: 'udp-api-reported' }] },
    { ...snapshot, points: [{ ...snapshot.points[0], uploaded: 9007199254740993 }] },
    { ...snapshot, points: [{ ...snapshot.points[0], epoch_count: 2 }] },
    { ...snapshot, points: [...snapshot.points, ...snapshot.points] },
  ])
    assert.throws(() => parseHistory(raw));
  for (const days of [0, 2, 90, '7'])
    assert.throws(() => parseHistorySettings({ ...settings, retention_days: days }));
});
const fs = require('node:fs'),
  net = require('node:net'),
  path = require('node:path');
async function harness(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/history-ui-'));
  const socket = dir + '/s';
  const calls = [],
    sockets = new Set();
  let responder = () => ({ usage_history: snapshot });
  const server = net.createServer((s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
    s.once('data', async (b) => {
      const q = JSON.parse(b);
      calls.push(q);
      const body = await responder(q);
      if (body.drop) {
        s.destroy();
        return;
      }
      s.end(
        JSON.stringify({
          version: 1,
          generation: 'g1',
          mode: 'daemon-monitor',
          read_only: false,
          server_time: now,
          ...body,
        }) + '\n',
      );
    });
  });
  await new Promise((r) => server.listen(socket, r));
  t.after(async () => {
    for (const s of sockets) s.destroy();
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const state = {
    control: {
      connected: true,
      generation: 'g1',
      readOnly: false,
      capabilities: ['usage-history-v1'],
      permissions: {
        role: 'administrator',
        observation_scope: 'machine',
        can_manage_machine_rules: true,
      },
    },
    observation: {
      connected: true,
      generation: 'g1',
      capabilities: ['usage-history-v1'],
      permissions: { role: 'user', observation_scope: 'self' },
    },
  };
  return {
    state,
    calls,
    client: new UsageHistoryClient({ controller: socket, observer: socket, view: () => state }),
    respond: (fn) => (responder = fn),
  };
}
const query = { range: '24h', source: 'tcp-transport-payload' };
test('history transport fences read scope and permission changes', async (t) => {
  const h = await harness(t);
  let release;
  h.respond(() => new Promise((r) => (release = r)));
  const flight = h.client.read(query);
  while (!release) await new Promise((r) => setTimeout(r, 2));
  h.state.control.permissions.role = 'user';
  release({ usage_history: { ...snapshot, scope: 'machine' } });
  const r = await flight;
  assert.equal(r.snapshot, undefined);
  assert.match(r.message, /changed/);
  h.respond(() => ({ usage_history: { ...snapshot, scope: 'machine' } }));
  assert.equal((await h.client.read(query)).snapshot, undefined);
  assert.equal(h.calls.filter((q) => q.operation !== 'usage-history').length, 0);
});
test('unknown settings outcome is reconciled by reads without mutation replay', async (t) => {
  const h = await harness(t);
  h.respond((q) =>
    q.operation === 'usage-history-configure' ? { drop: true } : { usage_history: snapshot },
  );
  const unknown = await h.client.configure({
    enabled: true,
    retention_days: 7,
    expected_revision: '1',
  });
  assert.equal(unknown.pending, true);
  assert.equal(
    (await h.client.configure({ enabled: true, retention_days: 7, expected_revision: '1' }))
      .pending,
    true,
  );
  assert.equal(h.calls.filter((q) => q.operation === 'usage-history-configure').length, 1);
  const read = await h.client.read(query);
  assert.equal(read.pending, false);
  assert.match(read.message, /confirmed/);
  assert.equal(h.calls.filter((q) => q.operation === 'usage-history-configure').length, 1);
});
test('ordinary and companion-only history never send settings writes', async (t) => {
  const h = await harness(t);
  h.state.control.permissions.role = 'user';
  assert.equal(
    (await h.client.configure({ enabled: true, retention_days: 7, expected_revision: '1' }))
      .canConfigure,
    false,
  );
  assert.equal(h.calls.length, 0);
  h.state.control.connected = false;
  const own = await h.client.read(query);
  assert(own.snapshot);
  assert.equal(own.canConfigure, false);
});
test('history settings acknowledgement cannot restore authority after context change', async (t) => {
  const h = await harness(t);
  let release;
  h.respond(
    () =>
      new Promise((resolve) => {
        release = resolve;
      }),
  );
  const flight = h.client.configure({ enabled: true, retention_days: 7, expected_revision: '1' });
  while (!release) await new Promise((resolve) => setTimeout(resolve, 2));
  h.state.control.permissions.role = 'user';
  release({ history_settings: settings });
  const result = await flight;
  assert.equal(result.canConfigure, false);
  assert.equal(result.pending, true);
  h.respond(() => ({ usage_history: snapshot }));
  const own = await h.client.read(query);
  assert.equal(own.canConfigure, false);
  assert.equal(own.pending, false); // pending write remains bound to the former context
  assert.equal(h.calls.filter((q) => q.operation === 'usage-history-configure').length, 1);
});
test('a newer authoritative settings revision resolves unknown outcome without claiming success', async (t) => {
  const h = await harness(t);
  h.respond(() => ({ drop: true }));
  assert.equal(
    (await h.client.configure({ enabled: true, retention_days: 7, expected_revision: '1' }))
      .pending,
    true,
  );
  h.respond(() => ({
    usage_history: { ...snapshot, settings: { enabled: false, retention_days: 1, revision: '3' } },
  }));
  const current = await h.client.read(query);
  assert.equal(current.pending, false);
  assert.equal(current.canConfigure, true);
  assert.match(current.message, /earlier save was not confirmed/);
  assert.equal(h.calls.filter((q) => q.operation === 'usage-history-configure').length, 1);
});
