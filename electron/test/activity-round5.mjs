import { _electron } from 'playwright-core';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import net from 'node:net';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '../..'),
  out = fs.mkdtempSync(root + '/.workspace/round5-journey-');
const readyPath = process.env.FLOWGATE_TEST_READY;
if (!readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable project fixture required');
const ready = JSON.parse(fs.readFileSync(readyPath));
if (!ready.socket.startsWith(path.dirname(readyPath) + '/'))
  throw Error('Endpoint outside disposable fixture');
const mutate = process.env.FLOWGATE_TEST_MUTATIONS === '1',
  created = [];
const call = (body) =>
  new Promise((resolve, reject) => {
    const socket = net.createConnection(ready.socket);
    let b = '';
    socket.setTimeout(5000, () => socket.destroy(new Error('Timeout')));
    socket.on('connect', () => socket.write(JSON.stringify({ version: 1, ...body }) + '\n'));
    socket.on('data', (chunk) => {
      b += chunk;
      if (b.includes('\n')) {
        socket.destroy();
        resolve(JSON.parse(b));
      }
    });
    socket.on('error', reject);
  });
const wait = async (fn) => {
  for (let i = 0; i < 100; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timed out waiting for authoritative refresh');
};
const baseline = await call({ operation: 'list' });
assert.equal(baseline.generation, ready.generation);
if (mutate) assert.equal((baseline.rules || []).length, 0, 'Mutation fixture must start empty');
const prefs = root + '/build/desktop-session/electron-preferences.json',
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
fs.writeFileSync(prefs, '{}');
let app;
const results = {
  fixture: mutate
    ? 'Real isolated non-enforcing fixture; two UI-created test rules, conditionally deleted afterward'
    : 'Real isolated non-enforcing fixture; no rule or lifecycle mutations',
  errors: [],
};
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
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
      TMPDIR: root + '/.workspace/tmp',
      XDG_CACHE_HOME: out + '/cache',
      WAYLAND_DISPLAY: 'wayland-0',
    },
  });
  const p = await app.firstWindow();
  p.on('pageerror', (e) => results.errors.push(String(e)));
  await p.setViewportSize({ width: 1280, height: 656 });
  await p.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await p.click('#expand');
  await p.locator('#rows tr[data-id^="app:"] .name').first().click();
  await p.waitForTimeout(1000);
  results.menuNames = await p
    .locator('.toolbar > .desktop-menu > summary,.toolbar > .toolbar-window-menu summary')
    .allTextContents();
  assert.deepEqual(results.menuNames, ['File', 'Tools', 'Window', 'Help']);
  results.fonts = await p.evaluate(async () => {
    await document.fonts.load('12px Selawik');
    return document.fonts.check('12px Selawik');
  });
  assert(results.fonts);
  if (mutate) {
    await p.locator('[data-focus="cell:application:incoming"]').click();
    await p.locator('[data-focus="qs:new:allow"]').click();
    await wait(async () => {
      const s = await p.evaluate(() => window.flowgate.snapshot());
      return s.control.rules.length === 1;
    });
    created.push((await p.evaluate(() => window.flowgate.snapshot())).control.rules[0]);
  }
  await p.screenshot({ path: out + '/after-normal.png' });
  await p.locator('#settingsMenu > summary').click();
  await p.selectOption('#displayUnits', 'Mbit');
  await p.locator('#settingsMenu > summary').click();
  await p.waitForTimeout(300);
  assert.doesNotMatch(await p.locator('.col-download_bps button').innerText(), /Mbit|\(def\)/);
  assert.doesNotMatch(await p.locator('.col-upload_bps button').innerText(), /Mbit|\(def\)/);
  assert.equal((await p.evaluate(() => window.flowgate.preferences())).displayUnit, 'Mbit');
  results.sourceBefore = await p.locator('#activitySource').inputValue();
  assert.equal(results.sourceBefore, 'tcp');
  await p.click('.col-download_bps button');
  assert.equal(await p.locator('.col-download_bps').getAttribute('aria-sort'), 'descending');
  await p.click('.col-download_bps button');
  assert.equal(await p.locator('.col-download_bps').getAttribute('aria-sort'), 'ascending');
  await p.click('#rateMode');
  assert.match(await p.locator('.col-download_bps button').innerText(), /Total/);
  await p.click('#rateMode');
  await p.locator('#settingsMenu > summary').click();
  await p.selectOption('#displayUnits', 'autoByte');
  await p.locator('#settingsMenu > summary').click();
  await p.locator('#trafficGraph .pane-menu summary').click();
  await p.locator('#trafficGraph .pane-menu button', { hasText: '10 min' }).click();
  assert.equal(await p.locator('#graphWindow').inputValue(), '600');
  await p.click('#graphPause');
  const selected = p.locator('#rows tr[data-id^="process:"]').first();
  await selected.locator('.name').click();
  if (mutate) {
    await p.locator('[data-focus="cell:process:outgoing"]').click();
    await p.locator('[data-focus="qs:new:block"]').click();
    await wait(
      async () => (await p.evaluate(() => window.flowgate.snapshot())).control.rules.length === 2,
    );
    created.push(
      (await p.evaluate(() => window.flowgate.snapshot())).control.rules.find(
        (r) => !created.some((c) => c.id === r.id),
      ),
    );
    assert(created[1].filter.process);
    assert.equal(created[1].action, 'block');
    assert.equal(created[0].filter.process, undefined);
  }
  const label = await p.locator('#selectedName').getAttribute('data-label');
  await p.waitForTimeout(700);
  await p.click('#graphPause');
  await p.waitForTimeout(700);
  assert.equal(await p.locator('.graph-selection').innerText(), label);
  results.pauseSelection = true;
  await p.locator('[data-focus="cell:process:incoming"]').click();
  await p.screenshot({ path: out + '/after-process-popup.png' });
  await p.keyboard.press('Escape');
  await p.locator('#trafficCanvas').focus();
  await p.keyboard.press('ArrowLeft');
  assert.equal(await p.locator('#graphSample').isVisible(), true);
  await p.screenshot({ path: out + '/after-chart-details.png' });
  await p.keyboard.press('Escape');
  await p.screenshot({ path: out + '/after-process-fallback.png' });
  await p.locator('#controlMenu > summary').click();
  await p.screenshot({ path: out + '/after-tools.png' });
  await p.keyboard.press('Escape');
  await p.keyboard.press('Escape');
  await p.mouse.click(790, 640);
  await p.setViewportSize({ width: 860, height: 600 });
  await p.screenshot({ path: out + '/after-narrow.png' });
  results.tableScroll = await p
    .locator('.table-scroll')
    .first()
    .evaluate((e) => e.scrollWidth >= e.clientWidth);
  results.noSandboxFlag = await app.evaluate(() => process.argv.includes('--no-sandbox'));
  assert.equal(results.noSandboxFlag, false);
  assert.deepEqual(results.errors, []);
} finally {
  for (const r of created) {
    const response = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    assert(!response.error, JSON.stringify(response.error));
  }
  if (mutate) {
    assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
    results.restoredZeroRules = true;
  }
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
  fs.writeFileSync(out + '/journey.json', JSON.stringify(results, null, 2));
}
console.log({ out, ...results });
