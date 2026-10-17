// Explicit synthetic graph samples, not collector/kernel evidence.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { TrafficHistory, HISTORY_LIMITS } = require('../dist/test/history.cjs');
const app = { key: 'app', revision: 'r', name: 'test', executable: '/test' };
const proc = { id: 'p', pid: 1, uid: 1000, application: app, executable: '/test' };
function row(id, protocol = 'tcp', owners = ['p'], extra = {}) {
  return {
    id,
    owners,
    socket: { protocol, local: '[::1]:10', remote: '[::1]:11', state: 1 },
    traffic: {
      state: 'measured',
      available: true,
      definition: protocol === 'tcp' ? 'tcp-transport-payload' : 'udp-api-reported',
      since: 'baseline',
      uploaded: 10,
      downloaded: 20,
      upload_bps: 4,
      download_bps: 8,
      ...extra,
    },
  };
}
function fixture(limits) {
  let now = 1000,
    seq = 0;
  const h = new TrafficHistory(() => now, limits),
    send = (rows, options = {}) => {
      now += 1000;
      const o = {
        connected: true,
        generation: 'g',
        activity: {
          sequence: ++seq,
          collected: String(seq),
          complete: true,
          rows,
          processes: { p: proc, q: { ...proc, id: 'q', pid: 2 } },
          ...options.activity,
        },
        ...options,
      };
      h.observe(o);
      return o;
    };
  return { h, send, tick: () => (now += 1000), view: (id) => h.view({ id, seconds: 300 }) };
}
test('separate sources, shared dedup, measured zero, partial and missing gaps; duplicate delivery', () => {
  const f = fixture(),
    shared = row('shared', 'tcp', ['p', 'q']);
  shared.display_application = app;
  f.send([shared, row('udp', 'udp')]);
  const o = f.send([shared, shared, row('udp', 'udp', ['p'], { partial: true })]);
  const v = f.view('app:app|r|uid:1000');
  assert.equal(v.points.filter((p) => p.source === 'tcp').at(-1).up, 4);
  assert.equal(v.points.filter((p) => p.source === 'udp').at(-1).up, 4);
  assert(v.points.at(-1).partial);
  const count = f.h.stats().points;
  f.h.observe(o);
  assert.equal(f.h.stats().points, count);
  f.send([
    row('shared', 'tcp', ['p'], { upload_bps: 0, download_bps: 0 }),
    row('udp', 'udp', ['p'], {
      available: false,
      upload_bps: undefined,
      download_bps: undefined,
      reason: 'Collector disconnected',
    }),
  ]);
  assert.equal(f.view('shared').points.at(-1).up, 0);
  assert.equal(f.view('udp').points.at(-1).up, undefined);
  assert.match(f.view('udp').points.at(-1).note, /disconnected/);
  f.send([]);
  assert.equal(f.view('shared').points.at(-1).up, undefined);
});
test('reconnect, reset, source change, new generation and stale delivery never bridge intervals', () => {
  const f = fixture();
  f.send([row('s')]);
  f.send([row('s')]);
  f.h.observe({ connected: false, generation: 'g' });
  assert.equal(f.view('s').points.at(-1).up, undefined);
  f.send([row('s')]);
  assert.equal(f.view('s').points.at(-1).up, undefined);
  f.send([row('s')]);
  f.send([row('s', 'tcp', ['p'], { since: 'reset', uploaded: 0, upload_bps: 999999 })]);
  assert.equal(f.view('s').points.at(-1).up, undefined);
  assert.match(f.view('s').points.at(-1).note, /reset/);
  f.send([row('s', 'udp')]);
  assert.equal(f.view('s').points.at(-1).up, undefined);
  const n = f.h.stats().points;
  f.h.observe({ connected: true, generation: 'g', activity: { sequence: 1, collected: 'stale' } });
  assert.equal(f.h.stats().points, n);
  f.send([row('s')], { generation: 'new' });
  assert.equal(f.view('s').points.length, 1);
  assert.equal(f.view('s').points[0].up, undefined);
});
test('membership recorded at sample time; stable socket follows reassociation without retroactive app history', () => {
  const f = fixture();
  f.send([row('s', 'tcp', [])]);
  f.send([row('s', 'tcp', [])]);
  const past = f.view('s').points[0].at;
  f.send([row('s')]);
  assert.equal(f.view('s').points[0].at, past);
  assert(f.view('app:app|r|uid:1000').points.every((p) => p.at > past));
  assert.equal(f.view('unidentified').points.at(-1).up, undefined);
});
test('bounded point/entity/closed retention, eviction and reused endpoint identity', () => {
  const f = fixture({
    ...HISTORY_LIMITS,
    entities: 5,
    points: 12,
    perEntity: 4,
    closed: 1,
    closedDuration: 2000,
  });
  for (let i = 0; i < 20; i++) {
    f.send([row('new' + i, 'tcp', [])]);
    assert(f.h.stats().points <= 12);
    assert(f.h.stats().entries <= 5);
  }
  assert.equal(f.view('new0').points.length, 0);
  assert.equal(f.view('new19').points.length, 1);
  f.send([row('new0', 'tcp', [])]);
  assert.equal(f.view('new0').points.length, 1);
  assert.throws(() => f.h.view({ id: 's', seconds: 999 }), /Invalid/);
});
test('collection timestamps anchor to monotonic frontend time; wall-clock jumps break traces', () => {
  let now = 1000;
  const h = new TrafficHistory(() => now),
    base = Date.parse('2026-10-17T12:00:00Z');
  const send = (sequence, delta) =>
    h.observe({
      connected: true,
      generation: 'g',
      activity: {
        sequence,
        collected: new Date(base + delta).toISOString(),
        complete: true,
        rows: [row('s')],
        processes: { p: proc },
      },
    });
  send(1, 0);
  now = 2200;
  send(2, 1000);
  let p = h.view({ id: 's', seconds: 60 }).points.at(-1);
  assert.equal(p.at, 2000);
  assert.equal(p.up, 4);
  now = 3200;
  send(3, -500);
  p = h.view({ id: 's', seconds: 60 }).points.at(-1);
  assert(p.breakBefore);
  assert.equal(p.up, 4);
});
