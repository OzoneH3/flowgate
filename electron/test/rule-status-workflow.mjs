// Real Rule Status journey against an externally held, disposable process-rule fixture
// (scripts/acceptance/process-rules-isolated.py --hold). Drives API mutations through the UI popup only.
// Never point this at the host daemon. Fixture owner quits/cleans after this run.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const readyPath = process.env.FLOWGATE_TEST_READY;
if (!readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable workspace fixture ready.json required');
const ready = JSON.parse(fs.readFileSync(readyPath));
if (!ready.socket.startsWith(path.dirname(readyPath)))
  throw Error('Fixture socket outside fixture');
const run = fs.mkdtempSync(path.join(root, '.workspace/rule-status-real-'));
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const log = [];
const step = (s) => {
  log.push(s);
  console.log('·', s);
};
const wait = async (fn, ms = 20000) => {
  for (let end = Date.now() + ms; Date.now() < end;) {
    if (await fn().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout: ' + fn);
};
const call = (body) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let b = '';
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...body }) + '\n'));
    s.on('data', (c) => {
      b += c;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
    s.on('error', reject);
  });
const list = () => call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [] }));
let app;
try {
  fs.writeFileSync(prefs, '{}');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      ready.monitor_socket,
      '--control',
      ready.socket,
      '--width',
      '1280',
      '--height',
      '656',
    ],
    env: {
      ...process.env,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 656 });
  const snapshot = () => p.evaluate(() => window.flowgate.snapshot());
  await wait(async () => {
    const s = await snapshot();
    return s.control.connected && s.control.policy?.processes?.length >= 2;
  });
  // Own disposable fixture: start from zero rules through the real conditional delete API.
  for (const r of (await list()).rules) {
    const d = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    if (d.error) throw Error('reset: ' + JSON.stringify(d.error));
  }
  await wait(async () => (await snapshot()).control.rules.length === 0);
  const before = await list();
  assert(before.capabilities.includes('process-instance-rules-v1'));
  const anyProtocol = before.capabilities.includes('observed-rule-any-protocol-v1');
  step(`backend ${before.generation} any-protocol=${anyProtocol}`);
  const alpha = ready.alpha_target.process_id,
    beta = ready.beta_target.process_id;
  const rows = (pid) => p.locator(`#rows tr[data-id^="process:"][data-id$=":${pid}"]`);
  const cell = (tier, d) => p.locator(`[data-focus="cell:${tier}:${d}"]`);
  const popup = () => p.locator('.quick-popup');
  const focusKey = () => p.evaluate(() => document.activeElement?.dataset.focus);
  const select = async (pid) => {
    await rows(pid).locator('.name').click();
    await wait(async () => !/Unavailable/.test(await cell('process', 'incoming').innerText()));
  };
  const own = (s, pid) =>
    s.control.rules.filter(
      (r) => r.filter.process && `${r.filter.process.pid}` === pid.split(':')[0],
    );
  const appRules = (s) => s.control.rules.filter((r) => !r.filter.process);
  const noPending = () => wait(async () => !(await p.locator('.inline-review').count()));

  step('select application; In cell opens popup; Enter on the cell cannot trigger an action');
  await p.click('#expand');
  await p.locator('#rows tr[data-id^="app:"] .name').first().click();
  await wait(async () => !/Unavailable/.test(await cell('application', 'incoming').innerText()));
  assert.equal(await p.locator('[data-focus^="cell:process"]').count(), 0);
  const countBefore = (await list()).rules.length;
  await cell('application', 'incoming').focus();
  await p.keyboard.press('Enter');
  await wait(() => popup().isVisible());
  assert.equal(await focusKey(), 'quick', 'popup itself is focused, not an action');
  await p.keyboard.press('Enter');
  await p.waitForTimeout(800);
  assert.equal(await p.locator('.inline-review').count(), 0);
  assert.equal((await list()).rules.length, countBefore, 'nothing saved by keyboard');
  await p.screenshot({ path: path.join(run, '01-application-popup.png') });
  await p.keyboard.press('Escape');
  await wait(async () => !(await popup().count()));
  assert.equal(await focusKey(), 'cell:application:incoming');

  step('one click: application In Allow (scope shown before click), saved via backend preview');
  await cell('application', 'incoming').click();
  const shown = await p.locator('.qs-scope').innerText();
  // Before the click: target, direction, protocol scope and lifetime, plus a visible endpoint marker.
  assert.match(
    shown,
    anyProtocol
      ? /^In · Application · TCP \+ UDP · persistent$/
      : /^In · Application · (TCP|UDP) · persistent$/,
  );
  assert.equal(await p.locator('.quick-popup .qs-endpoint').innerText(), 'Any endpoint');
  await p.locator('[data-focus="qs:new:allow"]').click();
  await wait(async () => appRules(await snapshot()).some((r) => r.filter.direction === 'incoming'));
  await noPending();
  const appIn = appRules(await snapshot()).find((r) => r.filter.direction === 'incoming');
  assert.equal(appIn.action, 'allow');
  assert.equal(appIn.filter.protocol, anyProtocol ? '*' : 'tcp');
  assert.equal(appIn.filter.remote_address, '*');
  assert(appIn.expires.startsWith('0001-'), 'persistent as shown');
  await wait(async () => !(await popup().count()), 5000);
  assert.equal(await focusKey(), 'cell:application:incoming', 'focus returns to the cell');
  await wait(async () => /Allow/.test(await cell('application', 'incoming').innerText()));
  await p.screenshot({ path: path.join(run, '02-application-allow.png') });

  step('select alpha: This process row + App fallback row; create process Out Block');
  await select(alpha);
  assert.match(await cell('application', 'incoming').innerText(), /Allow/);
  assert.match(await cell('process', 'incoming').innerText(), /Not set/);
  await cell('process', 'outgoing').click();
  assert.match(await p.locator('.qs-scope').innerText(), /^Out · Process \d+ · .* · session$/);
  assert.equal(await p.locator('.quick-popup .qs-endpoint').innerText(), 'Any endpoint');
  await p.locator('[data-focus="qs:new:block"]').click();
  await wait(async () => own(await snapshot(), alpha).length === 1);
  await noPending();
  const procOut = own(await snapshot(), alpha)[0];
  assert.equal(procOut.filter.direction, 'outgoing');
  assert.equal(procOut.action, 'block');
  assert.equal(procOut.schema, 3);
  assert(procOut.expires.startsWith('0001-'));
  await wait(async () => /Deny/.test(await cell('process', 'outgoing').innerText()));
  assert.match(
    await rows(alpha).locator('.status-slot[data-direction=outgoing]').getAttribute('aria-label'),
    /Deny/,
  );
  await p.screenshot({ path: path.join(run, '03-alpha-process-block.png') });

  step('beta unaffected: no own rule; table and matrix show only the application fallback');
  await select(beta);
  assert.equal(own(await snapshot(), beta).length, 0);
  assert.match(await cell('process', 'incoming').innerText(), /Not set/);
  assert.match(await cell('process', 'outgoing').innerText(), /Not set/);
  assert.match(await cell('application', 'incoming').innerText(), /Allow/);
  const betaIn = rows(beta).locator('.status-slot[data-direction=incoming]');
  assert(await betaIn.evaluate((e) => e.classList.contains('policy-fallback')), 'dimmed fallback');
  await p.screenshot({ path: path.join(run, '04-beta-fallback.png') });

  step('alpha: flip the existing process rule via the popup pill (exact id/version, scope kept)');
  await select(alpha);
  await cell('process', 'outgoing').click();
  assert(
    await p
      .locator('[data-focus="qs:' + procOut.id + ':block"]')
      .evaluate((e) => e.classList.contains('current')),
  );
  await p.locator(`[data-focus="qs:${procOut.id}:allow"]`).click();
  await wait(
    async () =>
      (await snapshot()).control.rules.find((r) => r.id === procOut.id)?.action === 'allow',
  );
  await noPending();
  const flipped = (await snapshot()).control.rules.find((r) => r.id === procOut.id);
  assert.deepEqual(flipped.filter, procOut.filter);
  assert.equal(flipped.expires, procOut.expires);
  assert.equal(
    (await snapshot()).control.rules.find((r) => r.id === appIn.id).version,
    appIn.version,
    'app rule untouched',
  );

  step('alpha: disable via the popup checkbox');
  await cell('process', 'outgoing').click();
  await p.locator(`[data-focus="qs:${procOut.id}:enabled"]`).click();
  await wait(
    async () =>
      (await snapshot()).control.rules.find((r) => r.id === procOut.id)?.disabled === true,
  );
  await noPending();
  await wait(async () => /Disabled/.test(await cell('process', 'outgoing').innerText()));
  await p.screenshot({ path: path.join(run, '05-alpha-disabled.png') });

  step('stale action: rule deleted behind the UI → click reports conflict, nothing recreated');
  await cell('process', 'outgoing').click();
  await wait(() => popup().isVisible());
  const current = (await list()).rules.find((r) => r.id === procOut.id);
  const del = await call({
    operation: 'rule-delete',
    generation: before.generation,
    id: procOut.id,
    expected_version: current.version,
  });
  assert(!del.error, 'fixture delete ' + JSON.stringify(del.error || ''));
  await p
    .locator(`[data-focus="qs:${procOut.id}:enabled"]`)
    .click({ force: true })
    .catch(() => {});
  await p.waitForTimeout(1500);
  const after = await list();
  assert.equal(after.rules.filter((r) => r.filter.process).length, 0, 'nothing recreated');
  const text =
    (await p.locator('#infoRules').innerText()) +
    (await p
      .locator('.inline-review')
      .innerText()
      .catch(() => ''));
  step('stale text: ' + text.replace(/\s+/g, ' ').slice(0, 160));
  await p.screenshot({ path: path.join(run, '06-stale.png') });
  await p.keyboard.press('Escape');
  await p.keyboard.press('Escape');

  step('application: popup with the existing rule, Delete from the popup (conditional)');
  await p.locator('#rows tr[data-id^="app:"] .name').first().click();
  await wait(async () => !/Unavailable/.test(await cell('application', 'incoming').innerText()));
  await cell('application', 'incoming').click();
  await p.locator('[data-focus="qs-delete"]').click();
  await p.click('#confirmYes');
  await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === appIn.id));
  await wait(async () => /Not set/.test(await cell('application', 'incoming').innerText()));

  step('narrow 860×600 with popup open');
  await p.setViewportSize({ width: 860, height: 600 });
  await select(alpha);
  await cell('process', 'incoming').click();
  await p.waitForTimeout(400);
  const box = await popup().boundingBox();
  const aside = await p.locator('#activityView aside').boundingBox();
  assert(box.x + box.width <= aside.x + aside.width + 1, 'popup within Info View');
  await p.screenshot({ path: path.join(run, '07-narrow-popup.png') });
  await p.keyboard.press('Escape');
  await p.setViewportSize({ width: 1280, height: 656 });

  let exited = false;
  if (process.env.FLOWGATE_EXIT_ALPHA === '1') {
    step('recreate a process rule, exit alpha via the owner command → inactive, Delete only');
    await select(alpha);
    await cell('process', 'incoming').click();
    await p.locator('[data-focus="qs:new:allow"]').click();
    await wait(async () => own(await snapshot(), alpha).length === 1);
    await noPending();
    const finalRule = own(await snapshot(), alpha)[0];
    fs.writeFileSync(ready.command, JSON.stringify({ op: 'exit', name: 'alpha' }) + '\n');
    await wait(
      async () => (await snapshot()).control.rule_states?.[finalRule.id]?.state === 'inactive',
      30000,
    );
    await wait(async () => /Inactive|ended/i.test(await cell('process', 'incoming').innerText()));
    await cell('process', 'incoming').click();
    assert(await p.locator(`[data-focus="qs:${finalRule.id}:block"]`).isDisabled());
    assert(await p.locator('[data-focus="qs-delete"]').isEnabled());
    await p.screenshot({ path: path.join(run, '08-exited-inactive.png') });
    await p.locator('[data-focus="qs-delete"]').click();
    await p.click('#confirmYes');
    await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === finalRule.id));
    exited = true;
  }
  const g = (await list()).generation;
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const fin = await list();
  assert.equal(fin.generation, g);
  assert.equal(fin.enforcement.state, 'stopped');
  fs.writeFileSync(
    path.join(run, 'result.json'),
    JSON.stringify(
      {
        backend: process.env.FLOWGATE_TEST_BACKEND_SHA,
        generation: fin.generation,
        anyProtocol,
        alpha,
        beta,
        exited,
        steps: log,
        remaining: fin.rules.map((r) => [
          r.id,
          r.action,
          r.filter.direction,
          r.filter.protocol,
          !!r.filter.process,
        ]),
        enforcement: fin.enforcement.state,
      },
      null,
      2,
    ),
  );
  console.log('PASS rule-status popup journey ' + run);
} catch (e) {
  if (app) {
    const p = await app.firstWindow();
    await p.screenshot({ path: path.join(run, 'failure.png') }).catch(() => {});
  }
  console.error('FAIL in', run);
  throw e;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else if (fs.existsSync(prefs)) fs.unlinkSync(prefs);
}
