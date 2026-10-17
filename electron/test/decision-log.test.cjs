// SYNTHETIC in-memory decision-log-v1 pages (draft contract); not daemon evidence.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const L = require('../dist/test/decision-log.cjs');

const record = (seq, extra = {}) => ({
  id: 'r' + seq,
  sequence: String(seq),
  time: new Date(1792270000000 + seq * 1000).toISOString(),
  generation: 'g1',
  mode: 'isolated-lab',
  kind: 'final',
  request_id: 'q' + seq,
  flow: {
    direction: seq % 2 ? 'incoming' : 'outgoing',
    protocol: 'tcp',
    family: 'ipv4',
    local: '10.0.0.1:1',
    remote: '10.0.0.2:2',
  },
  application: { key: 'app', name: 'App', kind: 'exe', executable: '/usr/bin/app', revision: '1' },
  principal_uid: 1000,
  decision: {
    action: 'allow',
    source: 'rule',
    scope: null,
    reason: 'matched',
    rule: {
      id: 'rule1',
      version: '3',
      action: 'allow',
      priority: 0,
      expires: '',
      disabled: false,
      filter: {},
    },
    matching_rules: ['rule1'],
    decided_by_uid: null,
  },
  verdict: { state: 'accept_submitted', detail: '' },
  delivery: 'not_observed',
  ...extra,
});
// Exclusive before/after cursors, newest-first by default, oldest-first for after.
function backend(n, opts = {}) {
  const b = { all: [], calls: [], logId: opts.logId || 'log1', fail: null, delay: 0 };
  for (let i = 1; i <= n; i++) b.all.push(record(i));
  b.request = async (q) => {
    b.calls.push(q);
    if (b.delay) await new Promise((r) => setTimeout(r, b.delay));
    if (b.fail) throw b.fail;
    let rows = b.all.filter((r) => !q.direction || r.flow.direction === q.direction);
    if (q.after) rows = rows.filter((r) => BigInt(r.sequence) > BigInt(q.after));
    else {
      rows = [...rows].reverse();
      if (q.before) rows = rows.filter((r) => BigInt(r.sequence) < BigInt(q.before));
    }
    const page = rows.slice(0, q.limit);
    return L.parsePage({
      records: page,
      next_before: !q.after && rows.length > q.limit ? page.at(-1).sequence : '',
      newest: b.all.at(-1)?.sequence || '',
      has_more: rows.length > q.limit,
      log_id: b.logId,
      scope: 'machine',
      health: { state: 'ok', recording: true, retention: { max_records: 20000, max_age_days: 30 } },
    });
  };
  return b;
}
const ids = (v) => v.records.map((r) => r.sequence);

test('parse rejects malformed cursors and keeps gap records metadata-free', () => {
  assert.throws(() => L.parseRecord({ ...record(1), sequence: '1e3' }));
  assert.throws(() => L.parsePage({ records: [], next_before: '-1' }));
  const g = L.parseRecord({
    id: 'g',
    sequence: '9',
    kind: 'gap',
    gap: { dropped: 4, reason: 'buffer overflow' },
  });
  assert.equal(g.kind, 'gap');
  assert.equal(g.flow, undefined);
  assert.equal(L.outcomeLabel(g), 'Records lost');
  // Numeric rule versions from older backends normalize to the decimal-string form.
  assert.equal(
    L.parseRecord(record(2, { decision: { ...record(2).decision, rule: { id: 'x', version: 7 } } }))
      .decision.rule.version,
    '7',
  );
});

test('newest page then older pages: no duplicates or missing boundary records', async () => {
  const b = backend(250),
    s = new L.DecisionLogStore(b.request, 1000, 100);
  await s.tick();
  assert.deepEqual(ids(s.view()).slice(0, 2), ['250', '249']);
  await s.loadOlder();
  await s.loadOlder();
  const seq = ids(s.view()).map(Number);
  assert.equal(seq.length, 250);
  assert.deepEqual(
    seq,
    Array.from({ length: 250 }, (_, i) => 250 - i),
  );
  assert.equal(s.view().hasOlder, false);
});

test('live follow merges new records by stable ID; paused only signals availability', async () => {
  const b = backend(10),
    s = new L.DecisionLogStore(b.request, 1000, 100);
  await s.tick();
  b.all.push(record(11), record(12));
  await s.tick();
  assert.deepEqual(ids(s.view()).slice(0, 3), ['12', '11', '10']);
  await s.tick(); // repeated catch-up returns nothing new; no duplicates
  assert.equal(s.view().records.length, 12);
  await s.setLive(false);
  b.all.push(record(13));
  await s.tick();
  assert.equal(s.view().records[0].sequence, '12', 'paused view must not change');
  assert.equal(s.view().newAvailable, true);
  await s.setLive(true);
  assert.equal(s.view().records[0].sequence, '13');
  assert.equal(s.view().newAvailable, false);
});

test('filters are sent to the backend and a stale response from an old filter is dropped', async () => {
  const b = backend(20),
    s = new L.DecisionLogStore(b.request, 1000, 100);
  b.delay = 30;
  const first = s.tick();
  const second = s.setFilter(L.validateFilter({ direction: 'outgoing' }));
  await Promise.all([first, second]);
  assert.equal(b.calls.at(-1).direction, 'outgoing');
  assert(
    s.view().records.every((r) => r.flow.direction === 'outgoing'),
    'stale unfiltered page leaked',
  );
  assert.equal(s.view().filtered, true);
  assert.throws(() => L.validateFilter({ port: 53 }));
  assert.throws(() => L.validateFilter({ source: 'guess' }));
});

test('retained rows are bounded; older paging stops with an explicit limit', async () => {
  const b = backend(500),
    s = new L.DecisionLogStore(b.request, 150, 100);
  await s.tick();
  await s.loadOlder();
  assert.equal(s.view().records.length, 150);
  await s.loadOlder();
  assert.equal(s.view().retainedLimit, true);
  assert.equal(s.view().hasOlder, false);
});

test('reconnect continues the persistent log; a replaced log or invalid cursor restarts', async () => {
  const b = backend(5),
    s = new L.DecisionLogStore(b.request, 1000, 100);
  await s.tick();
  b.fail = new Error('socket closed');
  await s.tick();
  assert.equal(s.view().status, 'disconnected');
  assert.equal(s.view().records.length, 5, 'loaded history stays visible');
  b.fail = null;
  b.all.push(record(6));
  await s.tick();
  assert.equal(s.view().status, 'ready');
  assert.deepEqual(ids(s.view()).slice(0, 2), ['6', '5']);
  assert.equal(b.calls.at(-1).log_id, 'log1', 'cursor query must carry log_id');
  b.logId = 'log2';
  b.all = [record(1)];
  await s.tick();
  assert.match(s.view().notice, /replaced/);
  await s.tick();
  assert.deepEqual(ids(s.view()), ['1']);
  b.fail = new L.LogError('stale cursor', 'invalid_cursor');
  await s.tick();
  assert.match(s.view().notice, /no longer valid/);
});

test('permission errors are reported, not shown as an empty log', async () => {
  const b = backend(3),
    s = new L.DecisionLogStore(b.request);
  b.fail = new L.LogError('not allowed', 'forbidden');
  await s.tick();
  assert.equal(s.view().status, 'error');
  assert.equal(s.view().error.code, 'forbidden');
});

test('far-behind live follow restarts at newest instead of claiming continuity', async () => {
  const b = backend(5),
    s = new L.DecisionLogStore(b.request, 1000, 10, 2);
  await s.tick();
  for (let i = 6; i <= 60; i++) b.all.push(record(i));
  await s.tick();
  assert.match(s.view().notice, /Many new records/);
  assert.equal(s.view().records[0].sequence, '60');
});

test('labels never claim delivery and keep historical scope wording', () => {
  const r = L.parseRecord(record(1));
  assert.equal(L.outcomeLabel(r), 'Allowed');
  assert.doesNotMatch(L.verdictLabel(r.verdict.state), /deliver/i);
  assert.equal(L.scopeLabel('once'), 'Once');
  assert.match(L.reasonSummary(r), /Rule · rule v3/);
  const h = L.healthSummary({
    ...L.parseHealth({ state: 'degraded', recording: true, dropped: 3, retention: {} }),
  });
  assert.equal(h.level, 'warning');
  assert.match(h.text, /3 records dropped/);
});
