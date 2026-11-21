// Bounded real monitoring soak. Explicit disposable fixture only; never a host endpoint.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const readyPath = process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'));
const ready = JSON.parse(fs.readFileSync(readyPath));
assert(ready.socket.startsWith(path.dirname(readyPath) + '/'));
const duration = Number(process.env.SOAK_MINUTES || 45);
assert(duration >= 1 && duration <= 60);
const run = fs.mkdtempSync(root + '/.workspace/daily-soak-');
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let text = '';
    s.on('error', reject);
    s.setTimeout(6000, () => s.destroy(Error('fixture timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      text += b;
      if (text.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(text));
      }
    });
  });
const first = await call({ operation: 'list' });
assert.equal(first.generation, ready.generation);
assert.equal((first.rules || []).length, 0);
let offline = false;
const transport = { current: 0, max: 0, requests: 0, errors: 0 };
const endpoint = run + '/api';
const proxy = net.createServer((s) =>
  s.once('data', async (raw) => {
    transport.current++;
    transport.max = Math.max(transport.max, transport.current);
    transport.requests++;
    try {
      if (offline) throw Error('deliberate disconnect');
      const r = await call(JSON.parse(raw));
      s.end(JSON.stringify(r) + '\n');
    } catch {
      transport.errors++;
      s.destroy();
    } finally {
      transport.current--;
    }
  }),
);
await new Promise((r) => proxy.listen(endpoint, r));
const prefs = root + '/build/desktop-session/electron-preferences.json',
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const result = {
  run,
  rows: first.activity.rows.length,
  minutes: duration,
  samples: [],
  errors: [],
  rules: 0,
  panes: 0,
  reconnects: 0,
  churn: 0,
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let until = Date.now() + 15000; Date.now() < until;) {
    if (await fn()) return;
    await sleep(50);
  }
  throw Error('condition timeout ' + fn);
};
let app;
const cleanRules = async () => {
  for (const r of (await call({ operation: 'list' })).rules || []) {
    const v = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    assert(!v.error, v.error);
  }
};
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
      endpoint,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  let main = await app.firstWindow();
  main.on('pageerror', (e) => result.errors.push(String(e)));
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await main.setViewportSize({ width: 1280, height: 720 });
  await main.click('#expand');
  const cdp = await main.context().newCDPSession(main);
  await cdp.send('Performance.enable');
  await app.evaluate(() => {
    const { monitorEventLoopDelay } = process.getBuiltinModule('node:perf_hooks');
    globalThis.__lag = monitorEventLoopDelay({ resolution: 10 });
    __lag.enable();
  });
  await main.evaluate(() => {
    globalThis.__soak = { full: 0, clock: 0, long: 0, total: 0, max: 0, frames: 0, slowFrames: 0 };
    window.flowgate.subscribe(() => __soak.full++);
    window.flowgate.onClock(() => __soak.clock++);
    new PerformanceObserver((l) => {
      for (const t of l.getEntries()) {
        __soak.long++;
        __soak.total += t.duration;
        __soak.max = Math.max(__soak.max, t.duration);
      }
    }).observe({ type: 'longtask' });
    let last = performance.now();
    const frame = (now) => {
      __soak.frames++;
      if (now - last > 50) __soak.slowFrames++;
      last = now;
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  });
  const started = Date.now();
  let step = 0;
  while (Date.now() - started < duration * 60000) {
    const loopStart = Date.now();
    if (step % 4 === 0) {
      await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
      await main.evaluate(() => window.flowgate.paneControl('chart', 'undock'));
      await wait(() => app.windows().length === 3);
      const info = app.windows().find((w) => w.url().includes('pane=info'));
      await info.locator('#paneContent').waitFor();
      await main
        .locator('#rows tr[data-id^="process:"] .name')
        .nth((step / 4) % 2)
        .click();
      await main.locator('#toolsMenu > summary').click();
      await main.locator('#optionsMenu > summary').click();
      await main.selectOption('#displayUnits', step % 8 ? 'autoBit' : 'autoByte');
      await main.locator('#toolsMenu > summary').click();
      await info.locator('[data-focus="cell:process:incoming"]').first().click();
      await info.locator('.quick-popup').waitFor();
      await info.keyboard.press('Enter');
      await info.keyboard.press('Escape');
      assert.equal(
        (await call({ operation: 'list' })).rules?.length || 0,
        0,
        'opening Enter cannot mutate',
      );
      if (step % 12 === 0) {
        await info.locator('[data-focus="cell:process:incoming"]').first().click();
        await info.locator('[data-focus="qs:new:allow"]').click();
        await wait(async () => !(await info.locator('.quick-popup').count()));
        const own = (await call({ operation: 'list' })).rules[0];
        assert(own);
        for (let i = 0; i < 3; i++) {
          const s = await main.evaluate(() => window.flowgate.snapshot());
          assert(s.control.rules.some((r) => r.id === own.id));
          await sleep(750);
        }
        await cleanRules();
        result.rules++;
        await wait(
          async () => !(await main.evaluate(() => window.flowgate.snapshot())).control.rules.length,
        );
      }
      await main.evaluate(() => window.flowgate.paneControl('info', 'close'));
      await main.evaluate(() => window.flowgate.paneControl('chart', 'dock'));
      await wait(() => app.windows().length === 1);
      result.panes++;
    }
    if (step % 8 === 5) {
      offline = true;
      await wait(
        async () => !(await main.evaluate(() => window.flowgate.snapshot())).control.connected,
      );
      offline = false;
      await wait(
        async () => (await main.evaluate(() => window.flowgate.snapshot())).control.connected,
      );
      result.reconnects++;
    }
    if (step % 4 === 2) {
      fs.writeFileSync(
        ready.command,
        JSON.stringify({
          op: 'outgoing',
          name: step % 8 ? 'alpha' : 'beta',
          protocol: 'tcp',
          v6: false,
        }),
      );
      result.churn++;
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows()
          .find((w) => w.webContents.getURL().includes('/index.html'))
          .hide(),
      );
      await sleep(500);
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows()
          .find((w) => w.webContents.getURL().includes('/index.html'))
          .show(),
      );
    }
    const m = await app.evaluate(({ app, BrowserWindow }) => ({
      memory: process.memoryUsage(),
      resources: process
        .getActiveResourcesInfo()
        .reduce((o, k) => ((o[k] = (o[k] || 0) + 1), o), {}),
      windows: BrowserWindow.getAllWindows().length,
      metrics: app
        .getAppMetrics()
        .map((x) => ({ type: x.type, cpu: x.cpu.percentCPUUsage, memory: x.memory })),
      lag: { max: __lag.max / 1e6, p99: __lag.percentile(99) / 1e6 },
    }));
    const metrics = (await cdp.send('Performance.getMetrics')).metrics;
    result.samples.push({
      seconds: (Date.now() - started) / 1000,
      main: m,
      dom: await cdp.send('Memory.getDOMCounters'),
      renderer: await main.evaluate(() => __soak),
      heap: metrics.find((x) => x.name === 'JSHeapUsedSize')?.value,
      transport: { ...transport },
    });
    assert(result.samples.length <= 245);
    assert.deepEqual(result.errors, []);
    fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
    if (step % 4 === 0)
      console.log(
        'SOAK',
        Math.round((Date.now() - started) / 60000) + 'min',
        JSON.stringify({
          windows: m.windows,
          heap: result.samples.at(-1).heap,
          resources: m.resources,
          transport,
        }),
      );
    step++;
    await sleep(Math.max(0, 15000 - (Date.now() - loopStart)));
  }
  result.completed = true;
  console.log(
    'PASS SOAK',
    run,
    JSON.stringify({
      samples: result.samples.length,
      minutes: duration,
      rules: result.rules,
      panes: result.panes,
      reconnects: result.reconnects,
      churn: result.churn,
    }),
  );
} catch (e) {
  result.failure = String(e);
  throw e;
} finally {
  offline = false;
  await cleanRules().catch((e) => (result.cleanupError = String(e)));
  if (app) await app.close();
  proxy.close();
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
}
