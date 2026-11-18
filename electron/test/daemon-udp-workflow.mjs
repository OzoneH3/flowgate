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
// Optional fixture-owner receiver counts: {states:[{family,cookies,uploaded,downloaded}],at}.
// Fixture PIDs are namespace-local, so identity is matched by socket cookie only.
const receiverFile = process.env.FLOWGATE_UDP_UI_RECEIVER;
const receiverStates = () => JSON.parse(fs.readFileSync(receiverFile, 'utf8')).states;
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
  let fixtureIds = [],
    beforeStop = new Map();
  const graph = (id) => page.evaluate((id) => window.flowgate.graph({ id, seconds: 300 }), id);
  // Rendered text of one table row: name, rates, policy, sockets, PID, downloaded, uploaded.
  const cells = (id) =>
    page.evaluate((id) => {
      const tr = [...document.querySelectorAll('#rows tr')].find((r) => r.dataset.id === id);
      return tr && [...tr.querySelectorAll('td')].map((td) => td.textContent);
    }, id);
  if (expected === 'active') {
    await wait(async () =>
      (await snap()).observation.activity?.rows.some(
        (r) =>
          r.socket.protocol === 'udp' &&
          r.traffic.available &&
          (r.traffic.uploaded > 0 || r.traffic.downloaded > 0),
      ),
    );
    await page.locator('#monitoringMenu').evaluate((e) => (e.open = false));
    await page.click('#expand');
    if (receiverFile) {
      // Receiver counts are cumulative since fixture start; the collector counts from attachment.
      // Within one collector generation, receiver minus displayed bytes must therefore stay
      // constant per socket: require two such samples with traffic in between. receiver.json
      // updates slightly before Activity, so lagging samples are kept but cannot match.
      let match;
      const seen = new Map();
      await wait(async () => {
        const states = receiverStates(),
          rows = (await snap()).observation.activity.rows,
          found = [],
          offsets = [],
          totals = [];
        for (const s of states)
          for (const [i, cookie] of s.cookies.entries()) {
            const r = rows.find(
              (r) => r.socket.protocol === 'udp' && r.socket.cookie === String(cookie),
            );
            if (
              !r?.traffic.available ||
              r.traffic.definition !== 'udp-api-reported' ||
              r.traffic.uploaded === undefined ||
              r.traffic.downloaded === undefined
            )
              return false;
            found.push(r);
            offsets.push(
              s.uploaded[i] - r.traffic.uploaded,
              s.downloaded[i] - r.traffic.downloaded,
            );
            totals.push(s.uploaded[i], s.downloaded[i]);
          }
        if (!found.length || offsets.some((o) => o < 0)) return false;
        const sample = { states, offsets, totals, rows: found };
        const key = offsets.join(','),
          earlier = seen.get(key);
        if (earlier && earlier.totals.some((t, i) => t !== totals[i])) {
          match = { first: earlier, second: sample };
          return true;
        }
        if (!earlier) seen.set(key, sample);
        return false;
      });
      match.rows = match.second.rows;
      fixtureIds = match.rows.map((r) => r.id);
      fs.writeFileSync(path.join(run, 'receiver-match.json'), JSON.stringify(match, null, 2));
      for (const id of fixtureIds) {
        const c = await cells(id);
        assert(c && c[7] !== '—' && c[8] !== '—', 'Measured UDP totals not rendered: ' + c);
      }
    } else
      fixtureIds = (await snap()).observation.activity.rows
        .filter((r) => r.socket.protocol === 'udp' && r.traffic.available)
        .map((r) => r.id);
    const udp = (await snap()).observation.activity.rows.find((r) => r.id === fixtureIds[0]);
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
    await page.locator('#monitoringMenu').evaluate((e) => (e.open = true));
    await wait(async () =>
      (await page.locator('#extendedStatus').innerText()).includes(first.reason_code),
    );
    fs.writeFileSync(path.join(run, 'attachment-blocker.json'), JSON.stringify(first, null, 2));
    await page.screenshot({ path: path.join(run, 'attachment-blocker.png') });
    await page.setViewportSize({ width: 860, height: 600 });
    await page.screenshot({ path: path.join(run, 'attachment-blocker-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 896 });
  }
  for (const id of fixtureIds) beforeStop.set(id, (await graph(id)).points);
  await page.locator('#monitoringMenu').evaluate((e) => (e.open = true));
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
  // Unavailable after Stop is rendered as unknown, never as zero; graphs stop measuring.
  for (const id of fixtureIds) {
    await page.locator('#monitoringMenu').evaluate((e) => (e.open = false));
    await wait(async () => {
      const c = await cells(id);
      return !c || (c[7] === '—' && c[8] === '—');
    });
    await wait(async () => (await graph(id)).points.at(-1)?.up === undefined);
  }
  if (expected === 'active') {
    await enable();
    await wait(async () => (await snap()).control.trafficMonitor.state === 'active');
    assert.notEqual((await snap()).control.trafficMonitor.generation, first.generation);
    // New collector generation: a break separates old samples and the first new rates are not a spike.
    const restart = {};
    for (const id of fixtureIds) {
      // Graph views are time-windowed and may trim, so split by sample time, not index.
      const stopAt = Math.max(...beforeStop.get(id).map((p) => p.at)),
        old = beforeStop
          .get(id)
          .filter((p) => p.up !== undefined)
          .map((p) => p.up + p.down);
      // A final old-generation sample may land between the snapshot and Stop, so locate
      // the gap itself and require restarted samples after it.
      let after, gap, resumed;
      try {
        await wait(async () => {
          after = (await graph(id)).points.filter((p) => p.at > stopAt);
          gap = after.findIndex((p) => p.up === undefined);
          resumed = gap < 0 ? [] : after.slice(gap).filter((p) => p.up !== undefined);
          return resumed.length >= 2;
        });
      } finally {
        restart[id] = { stopAt, after };
        fs.writeFileSync(path.join(run, 'restart-graph.json'), JSON.stringify(restart, null, 2));
      }
      assert(after[gap].breakBefore, 'UDP gap point does not break the trace');
      const peak = Math.max(...resumed.map((p) => p.up + p.down));
      assert(peak <= 4 * Math.max(0, ...old) + 65536, `Restart rate spike ${peak} vs ${old}`);
      restart[id] = {
        priorPeak: Math.max(0, ...old),
        restartedPeak: peak,
        gapPoints: after.slice(gap).findIndex((p) => p.up !== undefined),
        after,
      };
    }
    fs.writeFileSync(path.join(run, 'restart-graph.json'), JSON.stringify(restart, null, 2));
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
