// Bounded real concurrent prompt soak; exclusive disposable fixture grant required.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'));
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/'));
const minutes = Number(process.env.PROMPT_SOAK_MINUTES || 15);
assert(minutes >= 1 && minutes <= 20);
const run = fs.mkdtempSync(project + '/.workspace/prompt-soak-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let until = Date.now() + 20000; Date.now() < until;) {
    const v = await fn();
    if (v) return v;
    await sleep(60);
  }
  throw Error('timeout ' + fn);
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let text = '';
    s.on('error', reject);
    s.setTimeout(5000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      text += b;
      if (text.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(text));
      }
    });
  });
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(() => fs.existsSync(f));
  return JSON.parse(fs.readFileSync(f));
}
let offline = false,
  drop = false,
  writes = 0;
const proxy = net.createServer((s) =>
  s.once('data', async (raw) => {
    try {
      if (offline) throw Error('deliberate offline');
      const q = JSON.parse(raw);
      if (q.operation === 'decide') writes++;
      const r = await call(q);
      if (drop && q.operation === 'decide') {
        drop = false;
        s.end();
        return;
      }
      s.end(JSON.stringify(r) + '\n');
    } catch {
      s.destroy();
    }
  }),
);
await new Promise((r) => proxy.listen(run + '/api', r));
let app, main;
const result = { run, minutes, generation: ready.generation, samples: [], errors: [], cycles: [] };
async function launch() {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      ready.monitor_socket,
      '--control',
      run + '/api',
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  main = await app.firstWindow();
  main.on('pageerror', (e) => result.errors.push(String(e)));
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await app.evaluate(({ app }) => {
    globalThis.__focus = 0;
    app.on('browser-window-created', (_e, w) => w.on('focus', () => __focus++));
  });
}
try {
  assert.equal((await call({ operation: 'list' })).generation, ready.generation);
  assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
  await launch();
  await main.evaluate(() => {
    document.getElementById('controlMenu').open = true;
  });
  if ((await call({ operation: 'list' })).protection.state !== 'active') {
    await main.selectOption('#protectionProfile', 'both');
    await main.click('#protectionCheck');
    await wait(async () => (await main.evaluate(() => window.flowgate.protectionState())).canStart);
    await main.click('#protectionStart');
    await wait(async () => (await call({ operation: 'list' })).protection.state === 'active');
  } else {
    result.reusedActiveFixture = true;
  }
  await main.evaluate(() => {
    document.getElementById('controlMenu').open = false;
  });
  const start = Date.now();
  for (let i = 0; i < minutes; i++) {
    const at = Date.now();
    if (i % 2 === 0) await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()
        .find((w) => w.webContents.getURL().endsWith('/index.html'))
        .hide(),
    );
    const other = ready.other ? 'other' : 'beta';
    await command({
      op: 'batch',
      items: [
        {
          op: 'incoming',
          name: 'alpha',
          protocol: 'udp',
          v6: process.env.SWAP_NETWORK_FAMILIES === '1',
        },
        {
          op: 'outgoing',
          name: other,
          protocol: 'udp',
          v6: process.env.SWAP_NETWORK_FAMILIES !== '1',
        },
      ],
    });
    const pair = await wait(async () => {
      const p = ((await call({ operation: 'list' })).events || []).filter(
        (e) => e.state === 'awaiting-decision',
      );
      return p.length >= 2 ? p : undefined;
    });
    if (ready.other) assert.equal(new Set(pair.map((e) => e.attribution.application?.key)).size, 2);
    const prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=')));
    prompt.on('pageerror', (e) => result.errors.push(String(e)));
    const id = new URL(prompt.url()).searchParams.get('request');
    assert(pair.some((e) => e.id === id));
    await prompt.locator('#requestDetails').focus();
    await prompt.keyboard.press('Enter');
    await prompt.keyboard.press('Enter');
    assert.equal(
      ((await call({ operation: 'list' })).events || []).find((e) => e.id === id).state,
      'awaiting-decision',
    );
    await sleep(500);
    const focus = await app.evaluate(() => __focus);
    await sleep(800);
    assert.equal(
      await app.evaluate(() => __focus),
      focus,
      'polls must not repeatedly activate prompt',
    );
    if (i % 4 === 3) {
      offline = true;
      await wait(async () => prompt.locator('#allow').isDisabled());
      offline = false;
      await wait(async () => !(await prompt.locator('#allow').isDisabled()));
    }
    drop = i % 3 === 1;
    const before = writes;
    await prompt.click(i % 2 ? '#block' : '#allow');
    const terminal = await wait(async () => {
      const e = ((await call({ operation: 'list' })).events || []).find((e) => e.id === id);
      return e && e.state !== 'awaiting-decision' ? e : undefined;
    });
    assert.equal(terminal.state, i % 2 ? 'blocked' : 'allowed');
    await sleep(400);
    assert.equal(writes - before, 1);
    await prompt.click('#dismiss');
    const remaining = pair.find((e) => e.id !== id);
    const second = await wait(() =>
      app
        .windows()
        .find(
          (w) => new URL(w.url() || 'about:blank').searchParams.get('request') === remaining.id,
        ),
    );
    if (i % 2) {
      await second.keyboard.press('Escape').catch((e) => {
        if (!second.isClosed()) throw e;
      });
    } else {
      await wait(async () => second.locator('#allow').isDisabled());
      await second.close();
    }
    await wait(
      async () =>
        !((await call({ operation: 'list' })).events || []).some(
          (e) => e.state === 'awaiting-decision',
        ),
    );
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()
        .find((w) => w.webContents.getURL().endsWith('/index.html'))
        .show(),
    );
    await main.evaluate(() => window.flowgate.paneControl('info', 'close'));
    await wait(() => app.windows().length === 1);
    const metric = await app.evaluate(({ app, BrowserWindow }) => ({
      memory: process.memoryUsage(),
      resources: process
        .getActiveResourcesInfo()
        .reduce((o, k) => ((o[k] = (o[k] || 0) + 1), o), {}),
      windows: BrowserWindow.getAllWindows().length,
      processes: app
        .getAppMetrics()
        .map((m) => ({ type: m.type, cpu: m.cpu.percentCPUUsage, memory: m.memory })),
    }));
    result.samples.push({ seconds: (Date.now() - start) / 1000, ...metric });
    result.cycles.push({
      i,
      decisionId: id,
      terminal: { state: terminal.state, reason: terminal.reason },
      ids: pair.map((e) => e.id),
      applications: pair.map((e) => e.attribution.application?.key),
      writes,
      elapsed: Date.now() - at,
    });
    assert.deepEqual(result.errors, []);
    assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
    fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
    console.log(
      'PROMPT SOAK',
      i + 1,
      JSON.stringify({
        windows: metric.windows,
        heap: metric.memory.heapUsed,
        resources: metric.resources,
        writes,
      }),
    );
    await sleep(Math.max(0, 60000 - (Date.now() - at)));
  }
  await main.evaluate(() => {
    document.getElementById('controlMenu').open = true;
  });
  await main.click('#protectionStop');
  await wait(async () => (await call({ operation: 'list' })).protection.state === 'stopped');
  result.completed = true;
  console.log('PASS PROMPT SOAK', run);
} catch (e) {
  result.failure = String(e);
  throw e;
} finally {
  offline = false;
  if (app) await app.close();
  proxy.close();
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
}
