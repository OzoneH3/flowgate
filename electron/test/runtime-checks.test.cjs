// runtime_checks (readiness.Check) parsing is fail-closed; degradation is display-only.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { parseRuntimeChecks, runtimeDegradation } = require('../dist/test/runtime-checks.cjs');
const { parseReply } = require('../dist/test/protocol.cjs');

const ready = { id: 'kernel.module_tree', status: 'ready', code: 'module_tree_present', detail: 'Running kernel module tree exists' };
const peers = {
  id: 'runtime.wine_unix_peers',
  status: 'optional_unavailable',
  code: 'unix_peer_probe_failed',
  detail: 'Wine/Proton attribution unavailable: Unix socket diagnostic probe failed: no such file. Native interception can remain active',
  next: 'Restore unix_diag, then repeat doctor',
};

test('all ready: no degradation notice', () => {
  assert.equal(runtimeDegradation(parseRuntimeChecks([ready])), undefined);
  assert.equal(runtimeDegradation(parseRuntimeChecks(undefined)), undefined);
});

test('optional capability unavailable is shown with detail and next step', () => {
  const d = runtimeDegradation(parseRuntimeChecks([ready, peers]));
  assert.equal(d.text, 'Degraded: Wine/Proton attribution unavailable');
  assert.deepEqual(d.lines, [`runtime.wine_unix_peers: optional_unavailable · ${peers.detail} · Next: ${peers.next}`]);
  const two = runtimeDegradation(parseRuntimeChecks([{ ...ready, status: 'not_checked' }, peers]));
  assert.match(two.text, /\(\+1 more\)$/);
});

test('malformed or unknown data degrades without rejecting the response', () => {
  const unavailable = 'Degraded: Runtime health unavailable (unrecognized data)';
  for (const bad of [{}, 'x', [{}], [{ ...ready, id: '' }], [{ ...ready, detail: 3 }], Array(65).fill(ready)])
    assert.equal(runtimeDegradation(parseRuntimeChecks(bad)).text, unavailable, JSON.stringify(bad).slice(0, 40));
  const future = parseRuntimeChecks([{ ...ready, status: 'some_future_status' }]);
  assert.equal(future[0].status, 'unrecognized');
  assert.match(runtimeDegradation(future).text, /^Degraded: Running kernel module tree exists$/);
  const long = parseRuntimeChecks([{ ...peers, detail: 'd'.repeat(5000), next: 'n'.repeat(5000) }])[0];
  assert.equal(long.detail.length, 1024);
  assert.equal(long.next.length, 1024);
  const base = { version: 1, generation: 'g', read_only: false, server_time: new Date().toISOString(), rules: [] };
  assert.deepEqual(parseReply({ ...base, runtime_checks: [peers] }).runtime_checks, [peers]);
  for (const bad of [{ nope: 1 }, [{ ...peers, status: 'degraded', detail: undefined }], Array(100).fill(peers)]) {
    const r = parseReply({ ...base, runtime_checks: bad });
    assert.equal(r.generation, 'g');
    assert.ok(runtimeDegradation(r.runtime_checks));
  }
});
