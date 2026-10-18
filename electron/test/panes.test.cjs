const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  PaneModel,
  visibleGeometry,
  paneKind,
  ruleAction,
  chartPatch,
} = require('../dist/test/pane-model.cjs');
const {
  chartRange,
  adjacentSample,
  observationSpacing,
  shiftedEnd,
} = require('../dist/test/chart-view.cjs');
const state = {
  observation: { generation: 'g', connected: true, activity: { rows: [], processes: {} } },
  control: {},
};
test('pane enum, fixed rule-entry fields and chart patch reject broad IPC', () => {
  for (const v of ['../file', 'prompt', '/etc/passwd', {}, null]) assert.throws(() => paneKind(v));
  assert.equal(paneKind('info'), 'info');
  assert.throws(() => ruleAction({ kind: 'save', selection: 'x', generation: 'g' }));
  assert.throws(() =>
    ruleAction({
      kind: 'quick',
      selection: 'x',
      generation: 'g',
      tier: 'process',
      direction: 'both',
    }),
  );
  assert.throws(() =>
    ruleAction({ kind: 'new', selection: 'x', generation: 'g', path: '/etc/passwd' }),
  );
  assert.equal(
    ruleAction({
      kind: 'quick',
      selection: 'x',
      generation: 'g',
      tier: 'process',
      direction: 'incoming',
    }).tier,
    'process',
  );
  for (const p of [
    { seconds: 601 },
    { end: NaN },
    { download: 'true' },
    { sampleAt: -1 },
    { path: 'x' },
  ])
    assert.throws(() => chartPatch(p));
  assert.deepEqual(chartPatch({ paused: false, end: undefined, seconds: 5 }), {
    paused: false,
    end: undefined,
    seconds: 5,
  });
});
test('one shared selection, unit/source and geometry; panes cannot set selection', () => {
  const p = new PaneModel();
  p.observe(state);
  p.update({ selection: 'overview', generation: 'g', unit: 'Mbit', source: 'udp' }, true, state);
  assert.throws(() => p.update({ selection: 'overview', generation: 'g' }, false, state));
  assert.throws(() => p.update({ selection: 'overview', generation: 'old' }, true, state));
  assert.throws(() => p.update({ source: 'all' }, true, state));
  p.mode('info', 'detached');
  p.update({ chart: { paused: true, end: 100 } }, false, state);
  assert.equal(p.value.unit, 'Mbit');
  assert.equal(p.value.source, 'udp');
  assert.equal(p.value.panes.info, 'detached');
  p.observe({ ...state, observation: { ...state.observation, generation: 'new' } });
  assert.equal(p.value.chart.paused, false);
  assert.equal(p.value.selection, 'overview');
  const area = { x: 0, y: 0, width: 860, height: 600 };
  const r = visibleGeometry({ x: 4000, y: -900, width: 9000, height: 8000 }, [area], {
    x: 0,
    y: 0,
    width: 500,
    height: 300,
  });
  assert.deepEqual(r, area);
  const tiny = visibleGeometry(
    { x: -999, y: 999, width: -1, height: -2 },
    [{ x: -200, y: 20, width: 200, height: 100 }],
    area,
  );
  assert.deepEqual(tiny, { x: -200, y: 20, width: 200, height: 100 });
});
const points = [
  { at: 1000, source: 'tcp', down: 1, up: 2, breakBefore: true },
  { at: 2300, source: 'tcp', down: 3, up: 4, breakBefore: false },
  { at: 15000, source: 'tcp', breakBefore: true },
  { at: 18000, source: 'udp', down: 9 },
];
const v = { now: 20000, started: 0, points };
const settings = { seconds: 5, paused: false, download: true, upload: true };
test('chart clamps pan to retained source history and never invents samples', () => {
  const r = chartRange(v, { ...settings, end: 900000 }, 'tcp');
  assert.equal(r.end, 20000);
  assert.equal(shiftedEnd(v, settings, 'tcp', -1e8), 6000);
  assert.equal(chartRange(v, settings, 'udp').points.length, 1);
  assert.equal(chartRange(v, { ...settings, end: 10000 }, 'tcp').points.length, 0);
});
test('sample navigation uses actual timestamps, preserving unavailable baseline spacing', () => {
  assert.equal(adjacentSample(points, 1000, 1), 2300);
  assert.equal(adjacentSample(points, 2300, 1), 15000);
  assert.equal(adjacentSample(points, 2300, -1), 1000);
  assert.equal(observationSpacing(points, points[1]), 1.3);
  assert.equal(observationSpacing(points, points[2]), undefined);
});
test('connection dots distinguish connected peers from listening/bound rows', () => {
  const { hasObservedConnection } = require('../dist/test/model.cjs');
  const row = (protocol, state, remote) => ({ rows: [{ socket: { protocol, state, remote } }] });
  assert.equal(hasObservedConnection(row('tcp', 10, '0.0.0.0:0')), false);
  assert.equal(hasObservedConnection(row('udp', 7, '[::]:0')), false);
  assert.equal(hasObservedConnection(row('tcp', 1, '192.0.2.1:443')), true);
  assert.equal(hasObservedConnection(row('udp', 1, '192.0.2.1:53')), true);
});
