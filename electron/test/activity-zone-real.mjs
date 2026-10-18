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
  const create = async (page, direction, action, zone) => {
    const started = Date.now();
    await page
      .locator(
        '[data-focus="cell:application:' +
          direction +
          '"], [data-focus="cell:process:' +
          direction +
          '"]:visible',
      )
      .first()
      .click();
    await page.locator('.quick-popup').waitFor();
    const shell = Date.now() - started;
    if (zone) await page.locator('[data-focus="qs-zone"]').selectOption(zone);
    await page.locator('[data-focus="qs:new:' + action + '"]').click();
    await wait(async () => (await page.locator('.quick-popup').count()) === 0);
    result.timings ??= [];
    result.timings.push({ shell });
  };
  await main.locator('tr[data-id="network:local"] .name').click();
  await create(main, 'incoming', 'block');
  let rules = (await call({ operation: 'list' })).rules;
  assert.equal(rules.length, 1);
  assert.equal(rules[0].filter.network_zone, 'local');
  assert.equal(rules[0].filter.all_programs, true);
  assert.equal(rules[0].filter.all_uids, true);
  await main.screenshot({ path: run + '/01-local-all-programs.png' });
  await main.locator('tr[data-id="network:internet"] .name').click();
  await create(main, 'outgoing', 'block');
  await main.locator('#rows tr[data-id^="app:"] .name').first().click();
  await create(main, 'incoming', 'allow', 'local');
  await main.locator('#rows tr[data-id^="process:"] .name').first().click();
  await main.locator('#infoPaneControls summary').click();
  await main.locator('[data-undock=info]').click();
  await wait(async () => app.windows().some((w) => w.url().includes('pane=info')));
  const info = app.windows().find((w) => w.url().includes('pane=info'));
  info.on('pageerror', (e) => result.errors.push(String(e)));
  await info.locator('[data-focus="cell:process:incoming"]').click();
  await info.locator('[data-focus="qs-zone"]').selectOption('internet');
  await info.locator('[data-focus="qs:new:block"]').click();
  await wait(async () => (await info.locator('.quick-popup').count()) === 0);
  rules = (await call({ operation: 'list' })).rules;
  assert.equal(rules.length, 4);
  assert(
    rules.some(
      (r) => r.filter.process && r.filter.network_zone === 'internet' && r.action === 'block',
    ),
  );
  assert(
    rules.some(
      (r) =>
        !r.filter.process &&
        !r.filter.all_programs &&
        r.filter.network_zone === 'local' &&
        r.action === 'allow',
    ),
  );
  await info.locator('.rule-details summary').click();
  await info.screenshot({ path: run + '/02-process-zone-and-fallbacks.png' });
  await info.locator('[data-focus="cell:process:incoming"]').click();
  await info.screenshot({ path: run + '/03-popup-compact.png' });
  await info.locator('.qs-row input[type=checkbox]').click();
  await wait(async () =>
    (await call({ operation: 'list' })).rules.some((r) => r.filter.process && r.disabled),
  );
  await info.locator('#dockPane').click();
  await main.locator('tr[data-id="network:local"] .name').click();
  await main.locator('[data-focus="cell:application:incoming"]').click();
  await main.locator('[data-focus$=":allow"]').click();
  await wait(async () =>
    (await call({ operation: 'list' })).rules.some(
      (r) => r.filter.all_programs && r.filter.network_zone === 'local' && r.action === 'allow',
    ),
  );
  await main.locator('[data-focus="cell:application:incoming"]').click();
  await main.locator('[data-focus="qs-advanced"]').click();
  assert.equal(await main.locator('#editZone').inputValue(), 'local');
  assert.equal(await main.locator('#editZone').isDisabled(), true);
  await main.screenshot({ path: run + '/04-zone-advanced-editor.png' });
  await main.locator('#closeEditor').click();
  await main.setViewportSize({ width: 860, height: 600 });
  await main.screenshot({ path: run + '/05-narrow.png' });
  assert.deepEqual(result.errors, []);
  console.log(result);
} catch (e) {
  result.failure = String(e);
  console.error(result.failure);
  if (app)
    for (const w of app.windows()) {
      console.error(await w.locator('body').innerText());
      await w
        .screenshot({
          path: run + '/failure-' + (w.url().includes('pane=info') ? 'info' : 'main') + '.png',
        })
        .catch(() => {});
    }
  throw e;
} finally {
  for (const r of (await call({ operation: 'list' })).rules || []) {
    const deleted = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    if (deleted.error) throw Error('Cleanup: ' + deleted.error);
  }
  result.restoredZeroRules = ((await call({ operation: 'list' })).rules || []).length === 0;
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
  console.log(result);
}
