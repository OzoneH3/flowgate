// Real isolated daemon; presentation controls plus exactly one disposable process rule.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
if (!readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable project fixture required');
const ready = JSON.parse(fs.readFileSync(readyPath));
if (!ready.socket.startsWith(path.dirname(readyPath) + '/'))
  throw Error('Endpoint outside fixture');
const run = fs.mkdtempSync(path.join(root, '.workspace/panes-real-'));
const call = (body) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let b = '';
    s.setTimeout(5000, () => s.destroy(Error('Timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...body }) + '\n'));
    s.on('data', (x) => {
      b += x;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
    s.on('error', reject);
  });
const initial = await call({ operation: 'list' });
assert.equal(initial.generation, ready.generation);
assert.equal((initial.rules || []).length, 0);
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const wait = async (fn) => {
  for (let i = 0; i < 180; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timed out');
};
let app, created;
const result = { run, generation: ready.generation, errors: [], realBackend: true };
try {
  fs.writeFileSync(prefs, '{}');
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
      XDG_CACHE_HOME: run + '/cache',
      WAYLAND_DISPLAY: 'wayland-0',
    },
  });
  const main = await app.firstWindow();
  main.on('pageerror', (e) => result.errors.push(String(e)));
  await main.setViewportSize({ width: 1280, height: 656 });
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await main.click('#expand');
  await main.locator('#rows tr[data-id^="app:"] .name').first().click();
  await main.screenshot({ path: run + '/01-main-app.png' });
  await main.locator('#rows tr[data-id^="process:"] .name').first().click();
  const pane = async (kind) => {
    await wait(async () => app.windows().some((p) => p.url().includes('pane=' + kind)));
    const p = app.windows().find((p) => p.url().includes('pane=' + kind));
    await p.locator('#paneUnits').waitFor();
    p.on('pageerror', (e) => result.errors.push(String(e)));
    return p;
  };
  await main.locator('#infoPaneControls summary').click();
  await main.locator('[data-undock=info]').click();
  const info = await pane('info');
  await main.locator('#trafficGraph .pane-menu summary').click();
  await main.locator('[data-undock=chart]').click();
  const chart = await pane('chart');
  assert.equal(app.windows().length, 3);
  await info.selectOption('#paneUnits', 'Mbit');
  await wait(async () => (await main.locator('#displayUnits').inputValue()) === 'Mbit');
  await chart.selectOption('#paneSource', 'udp');
  await wait(async () => (await info.locator('#paneSource').inputValue()) === 'udp');
  await chart.selectOption('#paneSource', 'tcp');
  await main.locator('#rows tr[data-id^="process:"] .name').last().click();
  const label = await main.locator('#selectedName').getAttribute('data-label');
  await wait(async () => (await info.locator('#selectedName').innerText()) === label);
  assert.equal(await info.evaluate(() => typeof window.flowgate.ruleSave), 'undefined');
  await info.locator('[data-focus="cell:process:incoming"]').click();
  await main.locator('.quick-popup').waitFor();
  assert.equal(await info.locator('.quick-popup').count(), 0);
  await main.locator('[data-focus="qs:new:allow"]').click();
  await wait(async () => ((await call({ operation: 'list' })).rules || []).length === 1);
  created = (await call({ operation: 'list' })).rules[0];
  assert(created.filter.process);
  assert.equal(created.filter.direction, 'incoming');
  await wait(async () =>
    /Allow/.test(await info.locator('[data-focus="cell:process:incoming"]').innerText()),
  );
  await info.screenshot({ path: run + '/02-info-real-process-rule.png' });
  await chart.screenshot({ path: run + '/03-chart-real.png' });
  await main.screenshot({ path: run + '/04-main-one-rule-owner.png' });
  await main.locator('#floatingRuleStatus > header button').click();
  await wait(async () => {
    const g = await main.evaluate(async () =>
      window.flowgate.graph({
        id: (await window.flowgate.paneSnapshot()).presentation.selection,
        seconds: 600,
      }),
    );
    return g.points.length && g.points.at(-1).at - g.points[0].at >= 7000;
  });
  await chart.locator('#trafficCanvas').focus();
  for (let i = 0; i < 15; i++) await chart.keyboard.press('=');
  await chart.keyboard.press('PageUp');
  const before = (await main.evaluate(() => window.flowgate.paneSnapshot())).presentation.chart;
  assert.equal(before.seconds, 5);
  assert(before.end !== undefined);
  await chart.keyboard.press('ArrowLeft');
  await chart.locator('#graphPrevious').click();
  await chart.locator('[data-series=upload]').click();
  assert.equal(await chart.locator('[data-series=upload]').getAttribute('aria-pressed'), 'false');
  await chart.screenshot({ path: run + '/05-chart-navigation.png' });
  await chart.locator('#graphLive').click();
  await wait(
    async () =>
      (await main.evaluate(() => window.flowgate.paneSnapshot())).presentation.chart.end ===
      undefined,
  );
  const mainID = await app.evaluate(
    ({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().find((w) => w.webContents.getURL().includes('index.html')).id,
  );
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).hide(), mainID);
  await wait(
    async () =>
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().every((w) => !w.isVisible()),
      ),
  );
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).show(), mainID);
  await wait(
    async () =>
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().every((w) => w.isVisible()),
      ),
  );
  await info.locator('#dockPane').click();
  await wait(async () => app.windows().length === 2);
  assert(await main.locator('#infoRules').isVisible());
  await chart.locator('#closePane').click();
  await wait(async () => app.windows().length === 1);
  await main.locator('.toolbar-window-menu summary').click();
  await main.locator('.toolbar-window-menu [data-pane=chart]').click();
  await wait(async () => await main.locator('#trafficGraph').isVisible());
  await main.setViewportSize({ width: 860, height: 600 });
  await main.screenshot({ path: run + '/06-narrow-docked.png' });
  // Freeze the acknowledged exact version; no blanket delete or automatic save retry.
  const deleted = await call({
    operation: 'rule-delete',
    generation: ready.generation,
    id: created.id,
    expected_version: created.version,
  });
  assert(!deleted.error, JSON.stringify(deleted.error));
  created = undefined;
  assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
  result.restoredZeroRules = true;
  assert.deepEqual(result.errors, []);
  // Test-owned response to the ordinary Quit confirmation; exercises normal frontend cleanup.
  await app.evaluate(({ dialog }) => {
    dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false });
  });
  await main.evaluate(() => {
    void window.flowgate.quit();
  });
  await app.close();
  app = undefined;
  assert.equal((await call({ operation: 'list' })).generation, ready.generation);
  result.daemonSurvivedGuiQuit = true;
} catch (e) {
  result.failure = String(e);
  throw e;
} finally {
  if (created) {
    const d = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: created.id,
      expected_version: created.version,
    });
    result.cleanup = d.error || 'acknowledged';
  }
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
  console.log(result);
}
