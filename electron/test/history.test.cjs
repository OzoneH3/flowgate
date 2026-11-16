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
      const { activity: activityOptions, ...observationOptions } = options;
      const o = {
        connected: true,
        generation: 'g',
        activity: {
          sequence: ++seq,
          collected: String(seq),
          complete: true,
          rows,
          processes: { p: proc, q: { ...proc, id: 'q', pid: 2 } },
          ...activityOptions,
        },
        ...observationOptions,
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
test('UDP collector generation and Stop produce gaps while TCP continues', () => {
  const f = fixture();
  const rows = () => [row('tcp'), row('udp', 'udp')];
  f.send(rows(), { activity: { udp: { state: 'active', generation: 'collector1' } } });
  f.send(rows(), { activity: { udp: { state: 'active', generation: 'collector1' } } });
  assert.equal(f.view('udp').points.at(-1).up, 4);
  f.send(rows(), { activity: { udp: { state: 'active', generation: 'collector2' } } });
  assert.equal(f.view('udp').points.at(-1).up, undefined);
  assert(f.view('udp').points.at(-1).breakBefore);
  assert.equal(f.view('tcp').points.at(-1).up, 4);
  f.send(rows(), { activity: { udp: { state: 'active', generation: 'collector2' } } });
  assert.equal(f.view('udp').points.at(-1).up, 4);
  f.send(rows(), { activity: { udp: { state: 'disabled', generation: 'collector2' } } });
  assert.equal(f.view('udp').points.at(-1).up, undefined);
  assert.equal(f.view('tcp').points.at(-1).up, 4);
  assert(f.view('udp').points.some((p) => p.up === 4));
});

test('overview retains bounded source-separated history with shared sockets counted once', () => {
  const f = fixture();
  const tcp = row('shared', 'tcp', ['p', 'q']);
  f.send([tcp, row('u', 'udp')]);
  f.send([tcp, tcp, row('u', 'udp')]);
  const v = f.view('overview');
  assert.equal(v.label, 'All applications');
  assert.equal(v.points.filter((p) => p.source === 'tcp').at(-1).up, 4);
  assert.equal(v.points.filter((p) => p.source === 'udp').at(-1).up, 4);
  f.h.observe({ connected: false, generation: 'g' });
  assert.equal(f.view('overview').points.at(-1).up, undefined);
});
test('legend totals are source-specific socket counters, not rates; 10min is bounded and timestamped', () => {
  const f = fixture();
  const rows = [row('tcp'), row('udp', 'udp', ['p'], { uploaded: 9000, downloaded: 10000 })];
  f.send(rows);
  f.send(rows);
  const v = f.h.view({ id: 'app:app|r|uid:1000', seconds: 600 });
  assert.equal(v.points.filter((p) => p.source === 'tcp').at(-1).downloaded, 20);
  assert.equal(v.points.filter((p) => p.source === 'udp').at(-1).uploaded, 9000);
  assert.equal(v.points.filter((p) => p.source === 'tcp').at(-1).up, 4);
  f.send([row('unavailable', 'tcp', ['p'], { available: false })]);
  assert.equal(f.view('app:app|r|uid:1000').points.at(-1).uploaded, undefined);
});

test('socket churn does not fragment a continuous measured aggregate', () => {
  const f = fixture();
  f.send([row('steady')]);
  f.send([row('steady')]);
  for (let i = 0; i < 8; i++) {
    f.send([row('steady'), row('short-lived-' + i)]);
    const aggregate = f.view('overview').points.at(-1);
    assert.equal(aggregate.up, 8);
    assert.equal(aggregate.breakUpBefore, false);
    assert.equal(aggregate.breakDownBefore, false);
    assert.equal(f.view('short-lived-' + i).points.at(-1).breakUpBefore, true);
  }
  f.h.observe({ connected: false, generation: 'g' });
  assert.equal(f.view('overview').points.at(-1).up, undefined);
  f.send([row('steady')]);
  assert.equal(f.view('overview').points.at(-1).up, undefined);
});
test('aggregate continuity requires a valid contributor in that direction', () => {
  const f = fixture();
  const downloadOnly = () => row('steady', 'tcp', ['p'], { upload_bps: undefined });
  f.send([downloadOnly()]);
  f.send([downloadOnly()]);
  f.send([downloadOnly(), row('new')]);
  let p = f.view('overview').points.at(-1);
  assert.equal(p.breakUpBefore, true);
  assert.equal(p.breakDownBefore, false);
  assert.equal(p.partial, true);
  f.send([row('replacement')]);
  p = f.view('overview').points.at(-1);
  assert.equal(p.breakBefore, true);
  assert.equal(p.breakUpBefore, true);
  assert.equal(p.breakDownBefore, true);
});
test('missing publication breaks aggregate even with a stable measured contributor', () => {
  const f = fixture();
  f.send([row('steady')]);
  f.send([row('steady')]);
  f.send([row('steady'), row('new')], { activity: { sequence: 5 } });
  const p = f.view('overview').points.at(-1);
  assert.equal(p.breakUpBefore, true);
  assert.equal(p.breakDownBefore, true);
  assert.match(p.note, /Missing observation/);
});
