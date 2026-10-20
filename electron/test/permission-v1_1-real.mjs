// Real permission v1.1 + stored Ask journey: sandboxed GUI against an externally held, disposable
// fixture (scripts/acceptance/process-rules-isolated.py --hold --continuous --zones --other). Never the host daemon.
// Delivery is judged by the fixture's private receivers (peer-received.log), not by API saves.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(
  readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'),
  'disposable fixture required',
);
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/') && !ready.socket.startsWith('/run/'));
const run = fs.mkdtempSync(project + '/.workspace/permission-v1_1-real-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = { run, fixture: readyPath, generation: ready.generation, steps: [], errors: [] };
const step = (s) => {
  evidence.steps.push(s);
  console.log('PASS', s);
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let text = '';
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      text += b;
      if (text.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(text));
      }
    });
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, ms = 20000, label = '') => {
  for (let until = Date.now() + ms; Date.now() < until;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await sleep(80);
  }
  throw Error('timeout ' + (label || fn));
};
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture command ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const peerLines = async () => (await command({ op: 'peer-counts' })).lines.length;
// One outgoing attempt; delivered = a private receiver logged it within the window.
async function send(name, protocol, host, port, ms = 2500) {
  const before = await peerLines();
  await command({ op: 'outgoing', name, protocol, host, port, v6: host.includes(':') });
  for (let until = Date.now() + ms; Date.now() < until; await sleep(150))
    if ((await peerLines()) > before) return true;
  return false;
}
const list = () =>
  call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [], events: l.events || [] }));
const pidOf = (name) => ready[name].pid;
const awaiting = async (name) =>
  (await list()).events.filter(
    (e) =>
      e.state === 'awaiting-decision' && e.attribution?.owners?.some((o) => o.pid === pidOf(name)),
  );
let app, main;
const promptWindow = () => app.windows().find((w) => /[?&]request=/.test(w.url() || ''));
try {
  const initial = await list();
  assert.equal(initial.generation, ready.generation);
  for (const c of ['application-policy-v1', 'decision-remember-fields-v1', 'stored-ask-v1'])
    assert(initial.capabilities.includes(c), 'fixture lacks ' + c);
  for (const r of initial.rules) {
    const d = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    assert(!d.error, 'fixture reset: ' + JSON.stringify(d));
  }
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      ready.monitor_socket,
      '--control',
      ready.socket,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  main = await app.firstWindow();
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.setViewportSize({ width: 1280, height: 720 });
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  const prefs = await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences(),
  );
  assert(prefs.sandbox && prefs.contextIsolation && !prefs.nodeIntegration);

  // Protection on the FIXTURE daemon only (continuous profile both).
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(
    async () => (await list()).protection?.state === 'active',
    30000,
    'fixture protection active',
  );
  await main.evaluate(() => {
    document.getElementById('controlMenu').open = false;
    document.getElementById('toolsMenu').open = false;
  });
  step('fixture protection started from the UI (profile both); host untouched');

  // Locate alpha's application row from its pinned process.
  await main.click('#expand');
  const alphaProc = await wait(() =>
    main
      .locator(`#rows tr[data-id^="process:"][data-id$=":${ready.alpha_target.process_id}"]`)
      .first()
      .getAttribute('data-id'),
  );
  const alphaApp =
    'app:' +
    alphaProc.slice(
      'process:'.length,
      alphaProc.length - (':' + ready.alpha_target.process_id).length,
    );
  const appRow = () => main.locator(`#rows tr[data-id="${alphaApp}"]`);
  const outStrip = () => appRow().locator('.policy-cell[data-direction="outgoing"]');
  const outCell = () => main.locator('#infoRules [data-focus="cell:application:outgoing"]');
  const selectAlpha = async () => {
    await appRow().locator('.name').click();
    await wait(async () => !/Unavailable/.test(await outCell().innerText()));
  };
  await selectAlpha();

  // 1. Single-destination Allow through the prompt's Remember (address+port+protocol).
  await command({
    op: 'outgoing',
    name: 'alpha',
    protocol: 'udp',
    host: '10.79.0.2',
    port: 43001,
    v6: false,
  });
  const first = await wait(async () => promptWindow(), 20000, 'first prompt');
  await first.locator('#allow').waitFor();
  assert.match(
    await first.locator('#requestDetails').textContent(),
    /No matching rule \(default Ask\)/,
  );
  await first.locator('#rememberToggle').check();
  const fieldsShown = await first
    .locator('#rememberPanel input[data-field]')
    .evaluateAll((xs) => xs.map((x) => [x.dataset.field, x.checked, x.disabled]));
  assert.deepEqual(
    fieldsShown.map(([f, c]) => [f, c]),
    [
      ['application', true],
      ['protocol', false],
      ['process', false],
      ['address', false],
      ['port', false],
    ],
    'NetLimiter default: application only',
  );
  const durations = await first.locator('#rememberDuration option').allInnerTexts();
  assert.deepEqual(durations, [
    'Do not delete',
    '1 minute',
    '5 minutes',
    '10 minutes',
    '30 minutes',
    '1 hour',
    '6 hours',
    '12 hours',
  ]);
  for (const f of ['protocol', 'address', 'port'])
    await first.locator(`#rememberPanel input[data-field="${f}"]`).check();
  await wait(
    async () => /10\.79\.0\.2/.test(await first.locator('#rememberSummary').innerText()),
    15000,
    'remember summary',
  );
  evidence.remember_summary = await first.locator('#rememberSummary').innerText();
  await wait(() => first.locator('#allow').isEnabled());
  await first.screenshot({ path: run + '/01-remember-single-destination.png' });
  await first.click('#allow');
  const narrow = await wait(async () =>
    (await list()).rules.find(
      (r) => r.filter.remote_address === '10.79.0.2' && r.action === 'allow',
    ),
  );
  assert.equal(narrow.filter.protocol, 'udp');
  assert.equal(narrow.filter.remote_port, 43001);
  assert(await send('alpha', 'udp', '10.79.0.2', 43001), 'remembered destination delivers');
  assert(
    !(await send('alpha', 'tcp', '10.79.0.3', 44000)),
    'other destination not covered by narrow rule',
  );
  step(`Remember (protocol+address+port) stored narrow ${narrow.id}: udp 10.79.0.2:43001 only`);
  // Clear the uncovered attempt with Deny once (creates no rule).
  const p2 = await wait(async () => promptWindow());
  await p2.locator('#block').waitFor();
  await p2.click('#block');
  await wait(async () => !(await awaiting('alpha')).length);

  // 2. Cell shows the node's own rule: Not set + 1 scoped (narrow rule never masquerades).
  await selectAlpha();
  await wait(async () => /Not set/.test(await outCell().innerText()));
  assert.match(await outStrip().innerText(), /\+1/);
  step('Out cell = Not set, "+1 scoped" hint (narrow rule is not the application state)');

  // 3. Application Out Allow — one click.
  await outCell().click();
  await main.locator('.quick-popup').waitFor();
  const order = await main.locator('.quick-popup .qs-action').allInnerTexts();
  assert.deepEqual(
    order.map((t) => t.replace(/[^A-Za-z]/g, '')),
    ['Ask', 'Allow', 'Deny'],
  );
  await main.locator('.quick-popup .qs-allow').click();
  const appRule = await wait(async () =>
    (await list()).rules.find(
      (r) =>
        r.id !== narrow.id && r.filter.remote_address === '*' && r.filter.direction === 'outgoing',
    ),
  );
  assert.equal(appRule.action, 'allow');
  assert.equal(appRule.filter.protocol, '*');
  assert(
    !appRule.filter.remote_port &&
      !appRule.filter.local_port &&
      !appRule.filter.network_zone &&
      !appRule.filter.process,
  );
  const narrowAfter = (await list()).rules.find((r) => r.id === narrow.id);
  assert.deepEqual(narrowAfter, narrow, 'narrow rule preserved unchanged');
  await wait(async () => /Allow/.test(await outCell().innerText()));
  await main.screenshot({ path: run + '/02-application-allow.png' });
  step(
    `application Out Allow: own rule ${appRule.id} TCP+UDP any address/port, all zones; narrow rule unchanged`,
  );

  // 4. Real traffic to other destinations/ports/protocols/families without prompts.
  for (const [proto, host, port] of [
    ['tcp', '10.79.0.2', 43000],
    ['tcp', '10.79.0.3', 44000],
    ['udp', '10.79.0.3', 44001],
    ['udp', '10.79.0.2', 44001],
    ['tcp', 'fd79::3', 44000],
    ['udp', 'fd79::2', 43001],
  ])
    assert(await send('alpha', proto, host, port), `delivery ${proto} ${host}:${port}`);
  assert.equal((await awaiting('alpha')).length, 0, 'no prompts for allowed application');
  assert(!promptWindow(), 'no stale prompt window');
  step('TCP/UDP IPv4/IPv6 to 2 destinations x 2 ports delivered by private receivers; no prompts');

  // 5. No blinking: the Out cell stays stable across live refreshes.
  const samples = new Set();
  for (let i = 0; i < 25; i++, await sleep(200))
    samples.add((await outStrip().innerText()) + '|' + (await outCell().innerText()));
  assert.equal(samples.size, 1, 'rule cell blinked: ' + [...samples].join(' / '));
  step('Out cell stable over 5 s of live updates (no blinking)');

  // 6. Another executable still prompts; identical repeats group into one prompt.
  for (let i = 0; i < 3; i++)
    await command({
      op: 'outgoing',
      name: 'other',
      protocol: 'tcp',
      host: '10.79.0.2',
      port: 43000,
      v6: false,
    });
  await wait(async () => (await awaiting('other')).length >= 2, 20000, 'other pending');
  const otherPrompt = await wait(async () => promptWindow());
  await otherPrompt.locator('#allow').waitFor();
  assert.equal(
    app.windows().filter((w) => /[?&]request=/.test(w.url() || '')).length,
    1,
    'one prompt window',
  );
  await main.click('#requestsTab');
  const groupRows = await main.locator('#requestRows tr').count();
  evidence.other_group = { awaiting: (await awaiting('other')).length, rows: groupRows };
  assert.equal(groupRows, 1, 'identical repeats grouped into one row');
  await main.click('#activityTab');
  await otherPrompt.screenshot({ path: run + '/03-other-grouped.png' });
  step(
    `other executable prompts (${evidence.other_group.awaiting} attempts, 1 group row, 1 window)`,
  );
  await otherPrompt.click('#block');
  await sleep(500);
  for (let n = 0; n < 6 && (await awaiting('other')).length; n++) {
    const w = await wait(async () => promptWindow(), 8000).catch(() => undefined);
    if (!w) break;
    await w
      .locator('#block')
      .click()
      .catch(() => {});
    await sleep(400);
  }

  // 7. Direction separate: incoming to alpha is not covered by Out Allow.
  const inBefore = (await command({ op: 'counts', name: 'alpha' })).counts?.udp4 || 0;
  await command({ op: 'incoming', name: 'alpha', protocol: 'udp', v6: false });
  await wait(
    async () =>
      (await list()).events.some(
        (e) => e.state === 'awaiting-decision' && e.flow?.direction === 'incoming',
      ),
    15000,
    'incoming pending',
  );
  assert.equal(
    (await command({ op: 'counts', name: 'alpha' })).counts?.udp4 || 0,
    inBefore,
    'In not delivered by Out Allow',
  );
  const inPrompt = await wait(async () => promptWindow());
  await inPrompt.locator('#block').click();
  step('incoming to alpha held for a decision (Out Allow does not cover In)');

  // 8. Conflicting Deny: scoped Deny tcp 10.79.0.3:44000 beats app Allow at equal weight.
  const target = ready.alpha_target;
  const draft = {
    target_scope: 'application',
    direction: 'outgoing',
    protocol: 'tcp',
    action: 'block',
    remote_address: '10.79.0.3',
    local_port: 0,
    remote_port: 44000,
    disabled: false,
    expires: '0001-01-01T00:00:00Z',
  };
  const pv = await call({
    operation: 'observed-rule-preview',
    generation: ready.generation,
    observed_target: target,
    observed_draft: draft,
  });
  assert(!pv.error, JSON.stringify(pv));
  const sv = await call({
    operation: 'observed-rule-save',
    generation: ready.generation,
    preview_token: pv.observed_preview.token,
    observed_draft: draft,
  });
  assert(!sv.error, JSON.stringify(sv));
  assert(!(await send('alpha', 'tcp', '10.79.0.3', 44000)), 'scoped Deny wins (Deny before Allow)');
  assert(
    await send('alpha', 'tcp', '10.79.0.2', 44000),
    'app Allow still covers other destinations',
  );
  await wait(
    async () =>
      /Allow/.test(await outCell().innerText()) && /\+2/.test(await outStrip().innerText()),
  );
  step(
    'conflicting scoped Deny blocks 10.79.0.3:44000 while app Allow covers others; cell Allow +2 scoped',
  );

  // 9. Stored Ask: application Out Ask, prompt attribution, Once, re-prompt, Remember replaces Ask.
  await call({
    operation: 'rule-delete',
    generation: ready.generation,
    id: sv.saved_rule.id,
    expected_version: sv.saved_rule.version,
  });
  await outCell().click();
  await main.locator('.quick-popup .qs-ask').click();
  const askRule = await wait(async () =>
    (await list()).rules.find((r) => r.id === appRule.id && r.action === 'ask'),
  );
  await wait(async () => /Ask/.test(await outCell().innerText()));
  step(`application Out Ask set in place (${askRule.id} v${askRule.version})`);
  await command({
    op: 'outgoing',
    name: 'alpha',
    protocol: 'tcp',
    host: '10.79.0.3',
    port: 43000,
    v6: false,
  });
  const askPrompt = await wait(async () => promptWindow());
  await askPrompt.locator('#allow').waitFor();
  await wait(async () =>
    /Asked by rule/.test(await askPrompt.locator('#requestDetails').textContent()),
  );
  await askPrompt.screenshot({ path: run + '/04-ask-attribution.png' });
  const before = await peerLines();
  await askPrompt.click('#allow');
  await wait(async () => (await peerLines()) > before, 8000, 'Allow once delivers');
  assert(
    !(await send('alpha', 'tcp', '10.79.0.3', 43000, 1500)),
    'new attempt not covered by Once',
  );
  const again = await wait(async () => promptWindow());
  await again.locator('#rememberToggle').waitFor();
  await again.locator('#rememberToggle').check();
  await wait(
    async () => /replaces Ask rule/i.test(await again.locator('#rememberSummary').innerText()),
    15000,
    'replaces Ask',
  );
  await wait(() => again.locator('#allow').isEnabled());
  await again.click('#allow');
  await wait(async () => (await list()).rules.find((r) => r.id === appRule.id)?.action === 'allow');
  assert(await send('alpha', 'tcp', '10.79.0.3', 43000), 'later connection passes after Remember');
  assert.equal((await awaiting('alpha')).length, 0);
  step(
    'Ask: prompt names source rule, Allow once delivers, new attempt re-prompts, Remember(app) replaces Ask -> Allow',
  );

  // 10. No stale prompts at the end.
  await sleep(1000);
  const leftover = app.windows().filter((w) => /[?&]request=/.test(w.url() || ''));
  for (const w of leftover) {
    const id = new URL(w.url()).searchParams.get('request');
    const ev = (await list()).events.find((e) => e.id === id);
    assert(ev?.state === 'awaiting-decision', 'stale prompt for settled request ' + id);
  }
  assert.deepEqual(evidence.errors, []);
  step('no stale prompt windows; no renderer errors');
  evidence.final_rules = (await list()).rules.map((r) => ({
    id: r.id,
    action: r.action,
    filter: r.filter,
  }));
  // Stop fixture protection again.
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await main.locator('#protectionStop').click();
  await wait(
    async () => (await list()).protection?.state !== 'active',
    30000,
    'fixture protection stopped',
  );
  evidence.pass = true;
} catch (e) {
  evidence.failure = String(e?.stack || e);
  if (main) await main.screenshot({ path: run + '/failure-main.png' }).catch(() => {});
  const w = app && promptWindow();
  if (w) await w.screenshot({ path: run + '/failure-prompt.png' }).catch(() => {});
} finally {
  fs.writeFileSync(run + '/evidence.json', JSON.stringify(evidence, null, 2));
  if (app) await app.close().catch(() => {});
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
