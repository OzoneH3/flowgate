// runtime_checks (readiness.Check) parsing is fail-closed; degradation is display-only.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { parseRuntimeChecks, runtimeDegradation, runtimeBadge } = require('../dist/test/runtime-checks.cjs');
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

const tree = {
  id: 'kernel.module_tree',
  status: 'not_checked',
  code: 'module_tree_unavailable',
  detail: 'Running kernel 7.3.0-3-cachyos has no accessible module tree; unavailable facilities cannot be loaded from this tree',
  next: 'If the kernel was upgraded, reboot into the installed kernel, then repeat doctor',
};

test('short label keeps dotted versions, stops at a clause boundary and is bounded', () => {
  assert.equal(runtimeDegradation(parseRuntimeChecks([tree])).text, 'Degraded: Running kernel 7.3.0-3-cachyos has no accessible module tree');
  assert.equal(runtimeDegradation(parseRuntimeChecks([{ ...tree, detail: 'Probe v1.2 failed. Retry later' }])).text, 'Degraded: Probe v1.2 failed');
  const long = runtimeDegradation(parseRuntimeChecks([{ ...tree, detail: 'x'.repeat(300) }])).text;
  assert.equal(long, 'Degraded: ' + 'x'.repeat(59) + '…');
  assert.equal(runtimeDegradation(parseRuntimeChecks([{ ...tree, detail: ': nothing first' }])).text, 'Degraded: kernel.module_tree');
});

test('toolbar badge: ready -> degraded -> ready; hidden when disconnected or unknown', () => {
  assert.equal(runtimeBadge(true, parseRuntimeChecks([ready])), undefined);
  const b = runtimeBadge(true, parseRuntimeChecks([tree, ready]));
  assert.equal(b.text, 'Degraded: Running kernel 7.3.0-3-cachyos has no accessible module tree');
  // Full actionable reason stays in the tooltip, labelled as advisory and separate from protection.
  assert.equal(b.title, `Runtime health (advisory; protection state is shown separately)\nkernel.module_tree: not_checked · ${tree.detail} · Next: ${tree.next}`);
  assert.equal(runtimeBadge(true, parseRuntimeChecks([{ ...tree, status: 'ready' }])), undefined);
  assert.equal(runtimeBadge(false, parseRuntimeChecks([tree])), undefined, 'disconnected: no stale advisory');
  assert.equal(runtimeBadge(true, undefined), undefined, 'daemon without runtime checks');
  assert.match(runtimeBadge(true, parseRuntimeChecks('garbage')).text, /^Degraded: Runtime health unavailable/);
});

test('badge is display-only and sits beside, not inside, the protection entry', () => {
  const fs = require('node:fs'), path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  const block = src.slice(src.indexOf("const health = document.getElementById('runtimeHealth');"), src.indexOf('function setupMainMenus'));
  assert.ok(block.length > 0 && !/disabled|onclick|protectionStart|canStart/.test(block));
  assert.match(src, /monitoring\.after\(health\);/);
  const css = fs.readFileSync(path.join(__dirname, '../src/style.css'), 'utf8');
  // Advisories yield space to the top-level status menus when the toolbar narrows.
  assert.match(css, /\.toolbar \.runtime-health \{ flex: 0 1 auto; min-width: 0;/);
  assert.match(css, /\.desktop-menu \{ position: relative; flex-shrink: 0; \}/);
});
