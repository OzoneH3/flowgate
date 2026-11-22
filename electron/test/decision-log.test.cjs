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

test('copy bridge permits only a loaded record id and a specific endpoint selector', () => {
  assert.deepEqual(L.logCopyRequest('r1'), { id: 'r1', endpoint: undefined });
  assert.deepEqual(L.logCopyRequest({ id: 'r1', endpoint: 'remote' }), {
    id: 'r1',
    endpoint: 'remote',
  });
  assert.deepEqual(L.logCopyRequest({ id: 'final', outcomeOf: 'pending' }), {
    id: 'final', endpoint: undefined, outcomeOf: 'pending',
  });
  for (const value of [
    null,
    {},
    { id: '' },
    { id: 'r1', endpoint: 'file' },
    { id: 'r1', text: 'arbitrary' },
    { id: 'r1', outcomeOf: {} },
  ])
    assert.throws(() => L.logCopyRequest(value));
});

test('scope change on the same log drops a delayed recovery page and clears cursors', async () => {
  const foreign = record(101, { principal_uid: 1001 });
  const own = record(13);
  const requests = [];
  const pending = [];
  const store = new L.DecisionLogStore((query) => {
    requests.push(query);
    return new Promise((resolve) => pending.push(resolve));
  }, 1000, 100, 1);
  const page = (scope, records, extra = {}) => L.parsePage({
    scope, records, log_id: 'same-log', ...extra,
  });

  const initial = store.tick();
  pending.shift()(page('machine', [foreign], { next_before: '101' }));
  await initial;
  assert.equal(store.view().hasOlder, true);
  const oldRun = store.tick();
  pending.shift()(page('machine', [record(102, { principal_uid: 1001 })], { has_more: true }));
  await new Promise((resolve) => setImmediate(resolve));
  const oldReply = pending.shift();

  store.resetAccess();
  assert.deepEqual(store.view().records, []);
  assert.equal(store.get(foreign.id), undefined);
  assert.equal(store.view().hasOlder, false);
  const fresh = store.tick();
  assert.deepEqual(requests.at(-1), { limit: 100 });
  pending.shift()(page('self', [own]));
  await fresh;
  oldReply(page('machine', [foreign], { next_before: '101' }));
  await oldRun;
  assert.equal(store.view().scope, 'self');
  assert.deepEqual(ids(store.view()), [own.sequence]);
  assert.equal(store.get(foreign.id), undefined);
  assert.equal(store.view().hasOlder, false);
});

test('a page can narrow visibility before the connection poll reports the change', async () => {
  let scope = 'machine';
  const requests = [];
  const store = new L.DecisionLogStore(async (query) => {
    requests.push(query);
    return L.parsePage({
      scope, log_id: 'same-log',
      records: scope === 'machine' ? [record(101, { principal_uid: 1001 })] : [record(13)],
      next_before: scope === 'machine' ? '101' : '',
    });
  });
  await store.tick();
  scope = 'self';
  await store.tick();
  assert.equal(requests.at(-1).after, '101');
  assert.equal(store.view().accessRevision, 1);
  assert.deepEqual(store.view().records, []);
  await store.tick();
  assert.deepEqual(requests.at(-1), { limit: 100 });
  assert.deepEqual(ids(store.view()), ['13']);
});

test('a delayed catch-up restart cannot insert incoming rows into a populated outgoing filter', async () => {
  const requests = [];
  const store = new L.DecisionLogStore((query) => new Promise((resolve) => {
    requests.push({ query, resolve });
  }), 1000, 100, 1);
  const page = (records, extra = {}) => L.parsePage({
    records, log_id: 'same-log', scope: 'machine', ...extra,
  });

  const initial = store.tick();
  requests.shift().resolve(page([record(1)]));
  await initial;
  const catchUp = store.tick();
  requests.shift().resolve(page([record(3)], { has_more: true }));
  await new Promise((resolve) => setImmediate(resolve));
  const old = requests.shift();
  assert.deepEqual(old.query, { limit: 100 });

  const switched = store.setFilter({ direction: 'outgoing' });
  const fresh = requests.shift();
  assert.deepEqual(fresh.query, { limit: 100, direction: 'outgoing' });
  const outgoing = record(2);
  fresh.resolve(page([outgoing]));
  await switched;
  assert.deepEqual(ids(store.view()), ['2']);

  old.resolve(page([record(5)], { next_before: '5' }));
  await catchUp;
  assert.deepEqual(ids(store.view()), ['2']);
  assert.equal(store.view().filter.direction, 'outgoing');
  assert.equal(store.view().hasOlder, false);
});

test('a failed catch-up restart reports its error when the filter has not changed', async () => {
  let calls = 0;
  const store = new L.DecisionLogStore(async () => {
    if (++calls === 3) throw new L.LogError('History unavailable', 'unavailable');
    return L.parsePage({
      records: [record(calls)], log_id: 'same-log', scope: 'machine', has_more: true,
    });
  }, 1000, 100, 1);
  await store.tick();
  await store.tick();
  assert.equal(store.view().status, 'error');
  assert.equal(store.view().error.code, 'unavailable');
});

test('copied evidence preserves a revalidation link, aggregation and withheld versus zero counts', () => {
  const parsedCopy = (input) => JSON.parse(JSON.stringify(L.parseRecord(input)));
  const block = parsedCopy({
    ...record(7), request_id: undefined, related_request_id: 'earlier-request',
    decision: { action: 'block', source: 'identity_changed' },
  });
  assert.equal(block.request_id, '');
  assert.equal(block.related_request_id, 'earlier-request');

  const aggregation = {
    observations: 15, first_seen: '2026-11-22T18:03:12.012Z',
    last_seen: '2026-11-22T18:03:14.123Z', window_ms: 5000,
  };
  assert.deepEqual(parsedCopy({ ...record(8), aggregation }).aggregation, aggregation);

  const gap = { id: 'gap', sequence: '9', kind: 'gap' };
  const withheld = parsedCopy({ ...gap, gap: { reason: 'History incomplete' } });
  const zero = parsedCopy({ ...gap, gap: { dropped: 0, reason: 'History incomplete' } });
  assert.equal(Object.hasOwn(withheld.gap, 'dropped'), false);
  assert.equal(zero.gap.dropped, 0);
});
