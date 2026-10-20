// Display-only grouping: helpers launched by a verified Electron app (Heroic ›
// nile, legendary, gogdl) sit beneath it; each stays its own application.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hierarchy, allRows, launchingApplication } = require('../dist/test/model.cjs');

const runtime = '/usr/lib/electron43/electron', bundle = '/usr/lib/heroic-games-launcher/app.asar';
const heroic = { key: 'kh', revision: 'rh', name: 'heroic', executable: bundle, kind: 'electron', runtime, hosted: { state: 'verified', runtime, bundle, chain: [], reason: '' } };
const tool = (name) => ({ key: 'k-' + name, revision: 'r', name, executable: `/usr/lib/heroic-games-launcher/app.asar.unpacked/build/bin/x64/linux/${name}`, kind: 'native' });
const parent = (application) => ({ evidence: 'none', reason: '', stop: 'init', ancestry: [], parent: { pid: 100, start_ticks: '1', depth: 1, name: 'heroic', executable: runtime, application } });
const proc = (id, pid, application, provenance, uid = 1000) => ({ id, pid, start_ticks: String(pid), uid, executable: application.executable, application, provenance });
const sock = (id, owner, remote) => ({ id, owners: [owner], ownership_category: 'visible-holder', state: 'established', socket: { protocol: 'tcp', local: '10.0.0.2:4' + id.length, remote, state: 1 }, traffic: { available: false } });

function activity(processes, rows) {
  return { processes: Object.fromEntries(processes.map((p) => [p.id, p])), rows };
}

test('verified launch: nile, legendary and gogdl sit beneath Heroic, each its own application row', () => {
  const procs = [
    proc('h1', 100, heroic),
    proc('h2', 101, heroic), // Heroic's network-service process: same application entry
    proc('n1', 200, tool('nile'), parent(heroic)),
    proc('l1', 201, tool('legendary'), parent(heroic)),
    proc('g1', 202, tool('gogdl'), parent(heroic)),
  ];
  const rows = [sock('s1', 'h2', '104.18.1.1:443'), sock('s2', 'n1', '52.94.1.1:443'), sock('s3', 'l1', '3.3.3.3:443'), sock('s4', 'g1', '4.4.4.4:443')];
  const roots = hierarchy(activity(procs, rows));
  assert.deepEqual(roots.map((r) => r.label), ['heroic'], 'one top-level entry');
  const h = roots[0];
  const apps = h.children.filter((c) => c.kind === 'application');
  assert.deepEqual(apps.map((a) => a.label).sort(), ['gogdl', 'legendary', 'nile']);
  for (const a of apps) {
    assert.equal(a.parent, h.id);
    assert.equal(a.rows.length, 1, a.label + ' keeps only its own sockets');
    assert.notEqual(a.process.application.key, heroic.key, 'own identity, own rules');
  }
  // Heroic's own totals/rule context: only Heroic's socket.
  assert.deepEqual(h.rows.map((r) => r.id), ['s1']);
  assert.equal(h.children.filter((c) => c.kind === 'process').length, 1);
  // Row ids are unchanged by nesting (selection, history, rule status).
  assert.ok(allRows(roots).some((r) => r.id === 'app:k-nile|r|uid:1000'));
});

test('unverified or ambiguous launch relationships show the helper separately', () => {
  const unverified = { ...heroic, hosted: { ...heroic.hosted, state: 'unverified' } };
  const other = { ...heroic, key: 'ko', revision: 'ro', name: 'other' };
  const cases = {
    'no parent recorded': [proc('n1', 200, tool('nile'), { evidence: 'none', reason: '', stop: 'init', ancestry: [] })],
    'parent not an Electron app (e.g. a shell)': [proc('n1', 200, tool('nile'), { ...parent(undefined), parent: { pid: 9, start_ticks: '1', depth: 1, name: 'fish', executable: '/usr/bin/fish' } })],
    'parent Electron app unverified': [proc('n1', 200, tool('nile'), parent(unverified))],
    'two instances with different parents': [proc('n1', 200, tool('nile'), parent(heroic)), proc('n2', 201, tool('nile'), parent(other))],
    'one instance without the relationship': [proc('n1', 200, tool('nile'), parent(heroic)), proc('n2', 201, tool('nile'))],
  };
  for (const [name, helpers] of Object.entries(cases)) {
    const procs = [proc('h1', 100, heroic), ...helpers];
    const rows = [sock('s1', 'h1', '104.18.1.1:443'), ...helpers.map((p, i) => sock('t' + i, p.id, '52.94.1.' + i + ':443'))];
    const roots = hierarchy(activity(procs, rows));
    assert.ok(roots.some((r) => r.label === 'nile'), `${name}: nile stays top-level`);
    assert.ok(!roots.find((r) => r.label === 'heroic').children.some((c) => c.kind === 'application'), `${name}: nothing nested`);
  }
});

test('the launcher must itself be present; a different user never nests', () => {
  // Heroic has no socket row: nile is shown on its own, not under a guessed parent.
  const nile = proc('n1', 200, tool('nile'), parent(heroic));
  let roots = hierarchy(activity([nile], [sock('s2', 'n1', '52.94.1.1:443')]));
  assert.deepEqual(roots.map((r) => r.label), ['nile']);
  // Parent identity of another UID: a different application row key.
  const foreign = proc('n2', 201, tool('nile'), parent(heroic), 1001);
  roots = hierarchy(activity([proc('h1', 100, heroic), foreign], [sock('s1', 'h1', '1.1.1.1:443'), sock('s3', 'n2', '2.2.2.2:443')]));
  assert.ok(roots.some((r) => r.label === 'nile'));
  // Launched games use the existing launch groups, never nested here.
  assert.equal(launchingApplication({ kind: 'launch', children: [] }), undefined);
});
