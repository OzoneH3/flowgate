// Attach only to an externally owned isolated fixture; never create/stop its daemon.
// Fixture owner handles namespace, optional BPF authorization, traffic and cleanup.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const endpoint = process.env.FLOWGATE_UDP_UI_ENDPOINT;
const expected = process.env.FLOWGATE_UDP_UI_EXPECT || 'active';
const synthetic = process.env.FLOWGATE_UDP_UI_SYNTHETIC === '1';
if (
  !endpoint ||
  !path.isAbsolute(endpoint) ||
  !endpoint.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/') ||
  !['active', 'failed'].includes(expected)
)
  throw Error(
    'Explicit isolated workspace endpoint and active/failed expectation required; host endpoints forbidden',
  );
const run = fs.mkdtempSync(path.join(root, '.workspace/daemon-udp-ui-'));
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : null;
let app;
const wait = async (fn) => {
  for (let i = 0; i < 300; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout ' + fn);
};
const api = () =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(endpoint);
    let b = '';
    s.setTimeout(4000, () => s.destroy(Error('timeout')));
    s.on('error', reject);
    s.on('connect', () => s.write('{"version":1,"operation":"list"}\n'));
    s.on('data', (d) => {
      b += d;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
  });
async function launch(readonly = false) {
  const a = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      endpoint + '.monitor',
      '--control',
      endpoint + (readonly ? '.monitor' : ''),
    ],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  a.process().stderr?.on('data', (b) => fs.appendFileSync(path.join(run, 'electron.log'), b));
  a.on('close', () =>
    fs.appendFileSync(
      path.join(run, 'lifecycle.log'),
      'Electron closed ' + new Date().toISOString() + '\n',
    ),
  );
  return a;
}
try {
  fs.writeFileSync(prefs, '{}');
  const original = await api();
  assert.equal(original.enforcement.state, 'stopped');
  assert.equal(original.traffic_monitor.state, 'disabled');
  app = await launch();
  const page = await app.firstWindow();
  page.on('crash', () => fs.appendFileSync(path.join(run, 'lifecycle.log'), 'renderer crash\n'));
  await page.setViewportSize({ width: 1280, height: 896 });
  const snap = () => page.evaluate(() => window.flowgate.snapshot());
  await wait(async () => !!(await snap()).control.trafficMonitor);
  await page
    .locator('.brand')
    .evaluate(
      (el, label) => (el.textContent = label),
      synthetic
        ? 'FlowGate · SYNTHETIC UDP DISPLAY'
        : expected === 'active'
          ? 'FlowGate · REAL ISOLATED UDP'
          : 'FlowGate · ISOLATED LOAD FAILURE',
    );
  const enable = async () => {
    await page.click('#extendedBadge');
    await page.click('#extendedEnable');
    await page.click('#confirmYes');
  };
  await enable();
  await wait(async () => (await snap()).control.trafficMonitor.state === expected);
  let first = (await snap()).control.trafficMonitor;
  if (expected === 'active') {
    await wait(async () =>
      (await snap()).observation.activity?.rows.some(
        (r) =>
          r.socket.protocol === 'udp' &&
          r.traffic.available &&
          (r.traffic.uploaded > 0 || r.traffic.downloaded > 0),
      ),
    );
    await page.locator('#controlMenu').evaluate((e) => (e.open = false));
    await page.click('#expand');
    const udp = (await snap()).observation.activity.rows.find(
      (r) => r.socket.protocol === 'udp' && r.traffic.available,
    );
    await page
      .locator('#rows tr')
      .filter({ has: page.locator('td') })
      .evaluateAll(
        (rows, id) =>
          rows
            .find((r) => r.dataset.id === id)
            ?.querySelector('td.name')
            ?.click(),
        udp.id,
      );
    await page.selectOption('#graphSource', 'udp');
    await page.waitForTimeout(2200);
    await page.screenshot({ path: path.join(run, 'consolidated-udp.png') });
    await page.setViewportSize({ width: 860, height: 600 });
    await page.screenshot({ path: path.join(run, 'consolidated-udp-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 896 });
  } else {
    assert(first.reason_code);
    await page.locator('#controlMenu').evaluate((e) => (e.open = true));
    await wait(async () =>
      (await page.locator('#extendedStatus').innerText()).includes(first.reason_code),
    );
    fs.writeFileSync(path.join(run, 'attachment-blocker.json'), JSON.stringify(first, null, 2));
    await page.screenshot({ path: path.join(run, 'attachment-blocker.png') });
    await page.setViewportSize({ width: 860, height: 600 });
    await page.screenshot({ path: path.join(run, 'attachment-blocker-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 896 });
  }
  await page.locator('#controlMenu').evaluate((e) => (e.open = true));
  await wait(() => page.locator('#extendedStop').isEnabled());
  await page.click('#extendedStop');
  await wait(async () => (await snap()).control.trafficMonitor.state === 'disabled');
  await wait(async () => {
    const rows = (await snap()).observation.activity?.rows || [];
    return (
      rows.some((r) => r.socket.protocol === 'tcp' && r.traffic.available) &&
      rows.filter((r) => r.socket.protocol === 'udp').every((r) => !r.traffic.available)
    );
  });
  if (expected === 'active') {
    await enable();
    await wait(async () => (await snap()).control.trafficMonitor.state === 'active');
    assert.notEqual((await snap()).control.trafficMonitor.generation, first.generation);
  }
  const before = await api();
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const after = await api();
  assert.equal(after.generation, before.generation);
  assert.equal(after.traffic_monitor.generation, before.traffic_monitor.generation);
  assert.equal(after.traffic_monitor.state, before.traffic_monitor.state);
  assert.equal(after.enforcement.state, 'stopped');
  app = await launch(true);
  const ro = await app.firstWindow();
  await wait(() =>
    ro.evaluate(async () => (await window.flowgate.extendedState()).mode === 'daemon'),
  );
  const state = await ro.evaluate(() => window.flowgate.extendedState());
  assert.equal(state.canControl, false);
  assert.equal(state.canEnable, false);
  assert.equal(state.canStop, false);
  assert(
    await ro.evaluate(async () => {
      try {
        await window.flowgate.extended('enable');
        return false;
      } catch {
        return true;
      }
    }),
  );
  fs.writeFileSync(
    path.join(run, 'result.json'),
    JSON.stringify(
      {
        expected,
        synthetic,
        daemonGeneration: after.generation,
        collector: after.traffic_monitor,
        readOnly: state,
        independentDaemonSurvived: true,
      },
      null,
      2,
    ),
  );
  console.log(
    `PASS ${synthetic ? 'SYNTHETIC replies; actual sandboxed Wayland' : 'actual sandboxed Wayland + real isolated backend'} ${expected} path, Stop/TCP continuity, read-only denial, independent daemon survives. ${run}`,
  );
} catch (e) {
  console.error('Original failure', e);
  if (app?.windows().length) {
    await app
      .firstWindow()
      .then(async (p) => {
        console.log(await p.locator('body').innerText());
        await p.screenshot({ path: path.join(run, 'failure.png') });
      })
      .catch(() => {});
  }
  throw e;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
