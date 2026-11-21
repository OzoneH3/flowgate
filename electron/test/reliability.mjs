// Real isolated monitor, bounded performance trace + rule refresh journey. No host endpoints.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'));
const ready = JSON.parse(fs.readFileSync(readyPath));
assert(ready.socket.startsWith(path.dirname(readyPath) + '/'));
const stage = process.env.STAGE || 'before',
  run = fs.mkdtempSync(path.join(root, '.workspace/reliability-' + stage + '-'));
const call = (q) =>
  new Promise((resolve, reject) => {
    let b = '';
    const s = net.createConnection(ready.socket);
    s.on('error', reject);
    s.setTimeout(5000, () => s.destroy(Error('Timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (x) => {
      b += x;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
  });
const initial = await call({ operation: 'list' });
assert.equal(initial.generation, ready.generation);
assert.equal((initial.rules || []).length, 0);
let offline = false,
  dropSave = false,
  mutationWrites = 0;
const transport = [];
let holdPolicy = false,
  heldPolicy,
  releasePolicy;
const proxyEndpoint = path.join(run, 'control');
const proxy = net.createServer((s) =>
  s.once('data', async (raw) => {
    const q = JSON.parse(raw),
      started = performance.now();
    if (offline) {
      s.destroy();
      return;
    }
    try {
      const r = await call(q);
      transport.push({
        operation: q.operation,
        started,
        arrived: performance.now(),
        generation: r.generation,
        rules: (r.rules || []).map((r) => [r.id, r.version]),
        policy: r.policy_view?.snapshot.token,
      });
      if (
        ['observed-rule-save', 'rule-save', 'rule-delete', 'zone-rule-save'].includes(q.operation)
      )
        mutationWrites++;
      if (dropSave && q.operation === 'observed-rule-save') {
        dropSave = false;
        s.destroy();
        return;
      }
      if (holdPolicy && q.operation === 'policy-view') {
        holdPolicy = false;
        releasePolicy = () => s.end(JSON.stringify(r) + '\n');
        heldPolicy?.();
        return;
      }
      s.end(JSON.stringify(r) + '\n');
    } catch (error) {
      s.destroy();
    }
  }),
);
await new Promise((r) => proxy.listen(proxyEndpoint, r));
const prefs = path.join(root, 'build/desktop-session/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let end = Date.now() + 15000; Date.now() < end;) {
    const v = await fn();
    if (v) return v;
    await sleep(50);
  }
  throw Error('Timeout ' + fn);
};
let app;
const result = {
  run,
  stage,
  generation: ready.generation,
  rows: initial.activity.rows.length,
  errors: [],
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
      proxyEndpoint,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  const main = await app.firstWindow();
  main.on('pageerror', (e) => result.errors.push(String(e)));
  await main.setViewportSize({ width: 1280, height: 720 });
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await app.evaluate(() => {
    const { monitorEventLoopDelay } = process.getBuiltinModule('node:perf_hooks');
    globalThis.__lag = monitorEventLoopDelay({ resolution: 10 });
    globalThis.__lag.enable();
  });
  await main.evaluate(() => {
    globalThis.__perf = { tasks: [], replacements: 0, addedRows: 0, frames: [], states: [] };
    let previous = performance.now();
    const frame = (at) => {
      if (__perf.frames.length < 3000) __perf.frames.push(at - previous);
      previous = at;
      __perf.raf = requestAnimationFrame(frame);
    };
    __perf.raf = requestAnimationFrame(frame);
    new PerformanceObserver((list) => {
      for (const e of list.getEntries())
        if (__perf.tasks.length < 500) __perf.tasks.push({ at: e.startTime, duration: e.duration });
    }).observe({ type: 'longtask', buffered: false });
    new MutationObserver((records) => {
      for (const r of records) {
        __perf.replacements++;
        __perf.addedRows += r.addedNodes.length;
      }
    }).observe(document.getElementById('rows'), { childList: true });
    window.flowgate.subscribe((s) => {
      if (__perf.states.length < 300)
        __perf.states.push({
          at: performance.now(),
          generation: s.control.generation,
          list: (s.control.rules || []).map((r) => [r.id, r.version]),
          policy:
            s.control.policy?.applications
              .flatMap((a) => [...a.incoming.rules, ...a.outgoing.rules])
              .map((r) => [r.id, r.version]) ?? null,
        });
    });
  });
  const cdp = await main.context().newCDPSession(main);
  if (process.env.PROFILE_CPU) {
    await cdp.send('Profiler.enable');
    await cdp.send('Profiler.start');
    await app.evaluate(async () => {
      const inspector = process.getBuiltinModule('node:inspector');
      globalThis.__cpu = new inspector.Session();
      __cpu.connect();
      await new Promise((resolve, reject) =>
        __cpu.post('Profiler.enable', (e) => (e ? reject(e) : resolve())),
      );
      await new Promise((resolve, reject) =>
        __cpu.post('Profiler.start', (e) => (e ? reject(e) : resolve())),
      );
    });
  }
  await cdp.send('Tracing.start', {
    categories: 'devtools.timeline,v8,disabled-by-default-devtools.timeline',
    transferMode: 'ReturnAsStream',
  });
  await main.click('#expand');
  await main.locator('#rows tr[data-id^="process:"] .name').first().click();
  await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
  await main.evaluate(() => window.flowgate.paneControl('chart', 'undock'));
  const info = await wait(() => app.windows().find((w) => w.url().includes('pane=info')));
  await info.locator('[data-focus="cell:process:incoming"]').first().click();
  await info.locator('.quick-popup').waitFor();
  await info.keyboard.press('Escape');
  for (let i = 0; i < 4; i++) {
    await main
      .locator('#rows tr[data-id^="process:"] .name')
      .nth(i % 2)
      .click();
    await main.locator('#toolsMenu > summary').click();
    await main.locator('#optionsMenu > summary').click();
    await main.selectOption('#displayUnits', i % 2 ? 'autoBit' : 'autoByte');
    await main.locator('#toolsMenu > summary').click();
    await main
      .locator('.table-scroll')
      .first()
      .evaluate((n) => (n.scrollTop = 800));
    await sleep(1800);
  }
  if (process.env.JOURNEY) {
    await main.locator('#rows tr[data-id^="process:"] .name').first().click();
    await info.locator('[data-focus="cell:process:incoming"]').first().click();
    await info.locator('[data-focus="qs:new:allow"]').click();
    await wait(async () => !(await info.locator('.quick-popup').count()));
    let rules = await wait(async () => {
      const r = (await call({ operation: 'list' })).rules || [];
      return r.length ? r : undefined;
    });
    const own = rules[0];
    result.created = { id: own.id, version: own.version };
    const seen = [];
    for (let i = 0; i < 5; i++) {
      const s = await main.evaluate(() => window.flowgate.snapshot());
      seen.push({
        list: s.control.rules?.map((r) => r.id),
        policy: s.control.policy?.processes?.flatMap((p) => p.incoming.rules.map((r) => r.id)),
      });
      await sleep(800);
    }
    result.ruleSamples = seen;
    if (stage === 'after')
      assert(
        seen.every((s) => s.list?.includes(own.id) && s.policy?.includes(own.id)),
        'Created rule must remain in authoritative list and selected inventory',
      );
    for (const disabled of [true, false]) {
      const r = (await call({ operation: 'list' })).rules.find((r) => r.id === own.id);
      const reply = await call({
        operation: 'rule-save',
        generation: ready.generation,
        id: r.id,
        expected_version: r.version,
        rule: { ...r, disabled },
      });
      assert(!reply.error, reply.error);
      await wait(async () => {
        const s = await main.evaluate(() => window.flowgate.snapshot());
        return s.control.rules?.some((v) => v.id === own.id && v.disabled === disabled);
      });
    }
    const r = (await call({ operation: 'list' })).rules.find((r) => r.id === own.id);
    assert(
      !(
        await call({
          operation: 'rule-delete',
          generation: ready.generation,
          id: r.id,
          expected_version: r.version,
        })
      ).error,
    );
    await wait(
      async () =>
        !(await main.evaluate(() => window.flowgate.snapshot())).control.rules?.some(
          (v) => v.id === own.id,
        ),
    );
    result.externalEditDelete = true;
    if (stage === 'after') {
      const blocked = new Promise((r) => (heldPolicy = r));
      holdPolicy = true;
      const refresh = main.evaluate(() => window.flowgate.ruleContext());
      await blocked;
      await main.locator('#rows tr[data-id^="app:"] .name').first().click();
      await main.locator('tr[data-id="network:local"] .name').click();
      releasePolicy();
      await refresh;
      assert.equal(
        (await main.evaluate(() => window.flowgate.paneSnapshot())).presentation.selection,
        'network:local',
      );
      await main.locator('#rows tr[data-id^="process:"] .name').first().click();
      result.selectionDuringPendingRead = true;
      dropSave = true;
      const writesBefore = mutationWrites;
      await info.locator('[data-focus="cell:process:incoming"]').first().click();
      await info.locator('[data-focus="qs:new:block"]').click();
      await info.locator('[data-focus="review-reconcile"]').waitFor();
      const saved = (await call({ operation: 'list' })).rules || [];
      assert.equal(saved.length, 1);
      offline = true;
      await wait(
        async () => !(await main.evaluate(() => window.flowgate.snapshot())).control.connected,
      );
      offline = false;
      await wait(async () => {
        const s = await main.evaluate(() => window.flowgate.snapshot());
        return s.control.connected && s.control.rules?.some((r) => r.id === saved[0].id);
      });
      await info.locator('[data-focus="review-reconcile"]').click();
      await wait(async () => !(await info.locator('.quick-popup').count()));
      assert.equal(mutationWrites - writesBefore, 1, 'Lost ACK/reconnect must not resend save');
      const deleted = await call({
        operation: 'rule-delete',
        generation: ready.generation,
        id: saved[0].id,
        expected_version: saved[0].version,
      });
      assert(!deleted.error, deleted.error);
      await wait(
        async () => !(await main.evaluate(() => window.flowgate.snapshot())).control.rules?.length,
      );
      result.lostAckReconnect = { saveWrites: mutationWrites - writesBefore, deleted: saved[0].id };
    }
  }
  await sleep(1500);
  result.main = await app.evaluate(() => {
    const value = {
      maxMs: __lag.max / 1e6,
      p99Ms: __lag.percentile(99) / 1e6,
      meanMs: __lag.mean / 1e6,
    };
    __lag.reset();
    return value;
  });
  if (process.env.PROFILE_CPU) {
    fs.writeFileSync(
      path.join(run, 'renderer.cpuprofile'),
      JSON.stringify((await cdp.send('Profiler.stop')).profile),
    );
    fs.writeFileSync(
      path.join(run, 'main.cpuprofile'),
      JSON.stringify(
        await app.evaluate(
          () =>
            new Promise((resolve, reject) =>
              __cpu.post('Profiler.stop', (e, r) => {
                __cpu.disconnect();
                e ? reject(e) : resolve(r.profile);
              }),
            ),
        ),
      ),
    );
  }
  const done = cdp.waitForEvent ? null : null;
  const completed = new Promise((resolve) => cdp.once('Tracing.tracingComplete', resolve));
  await cdp.send('Tracing.end');
  const { stream } = await completed;
  let trace = '';
  for (;;) {
    const chunk = await cdp.send('IO.read', { handle: stream, size: 65536 });
    trace += chunk.data;
    if (chunk.eof) break;
    if (trace.length > 30 * 1024 * 1024) throw Error('Trace exceeded bound');
  }
  await cdp.send('IO.close', { handle: stream });
  fs.writeFileSync(path.join(run, 'trace.json'), trace);
  result.renderer = await main.evaluate(() => {
    cancelAnimationFrame(__perf.raf);
    return __perf;
  });
  result.instrumentationMain = await app.evaluate(() => {
    __lag.disable();
    return { maxMs: __lag.max / 1e6, p99Ms: __lag.percentile(99) / 1e6, meanMs: __lag.mean / 1e6 };
  });
  await main.screenshot({ path: path.join(run, 'activity.png') });
  await info.screenshot({ path: path.join(run, 'info.png') });
  assert.deepEqual(result.errors, []);
  console.log(
    'PASS',
    run,
    JSON.stringify({
      rows: result.rows,
      main: result.main,
      longTasks: result.renderer.tasks.length,
      maxTask: Math.max(0, ...result.renderer.tasks.map((t) => t.duration)),
      replacements: result.renderer.replacements,
    }),
  );
} catch (error) {
  result.failure = String(error);
  throw error;
} finally {
  fs.writeFileSync(path.join(run, 'result.json'), JSON.stringify(result, null, 2));
  fs.writeFileSync(path.join(run, 'transport.json'), JSON.stringify(transport, null, 2));
  proxy.close();
  if (app) await app.close();
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
