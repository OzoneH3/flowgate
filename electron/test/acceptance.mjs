// Actual Electron/Wayland + real read-only observer and existing isolated lab.
// CDP is enabled only by this external test runner, never by the production launcher.
import { chromium } from 'playwright-core';
import { spawn, execFileSync } from 'node:child_process';
import {
  mkdtempSync,
  mkdirSync,
  copyFileSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { call } = require('../dist/test/backend.cjs');
const root = path.resolve(import.meta.dirname, '../..');
const run = mkdtempSync(path.join(root, '.workspace/el-check-'));
const children = [];
let browser;
const browsers = [];
const logs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn, seconds = 15) {
  const end = Date.now() + seconds * 1000;
  let error;
  while (Date.now() < end) {
    try {
      const r = await fn();
      if (r) return r;
    } catch (e) {
      error = e;
    }
    await sleep(80);
  }
  throw Error('Wait timed out: ' + (error ?? String(fn)));
}
function start(command, args = [], name = 'process') {
  const p = spawn(command, args, {
    cwd: root,
    env: {
      ...process.env,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  children.push(p);
  let output = '';
  p.stdout.on('data', (b) => {
    output += b;
  });
  p.stderr.on('data', (b) => {
    output += b;
  });
  p.on('close', (code) =>
    writeFileSync(path.join(run, name + '.log'), output + `\nEXIT ${code}\n`),
  );
  p.output = () => output;
  return p;
}
async function fixture(name, mode) {
  const dir = path.join(run, name);
  mkdirSync(dir);
  copyFileSync(path.join(root, '.workspace/electron-traffic-fixture'), path.join(dir, 'fixture'));
  const p = start(path.join(dir, 'fixture'), mode ? [mode] : [], name);
  const info = await wait(() => {
    const line = p.output().split('\n')[0];
    return line.startsWith('{') ? JSON.parse(line) : null;
  });
  return [p, info];
}
async function freePort() {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  await new Promise((r) => server.close(r));
  return port;
}
async function electron(observer, controller, size = []) {
  const port = await freePort();
  const p = start(
    path.join(root, 'electron/node_modules/electron/dist/electron'),
    [
      '--ozone-platform=wayland',
      '--remote-debugging-address=127.0.0.1',
      '--remote-debugging-port=' + port,
      path.join(root, 'electron'),
      '--observer',
      observer,
      ...(controller ? ['--control', controller] : []),
      ...size,
    ],
    'electron',
  );
  await wait(async () => {
    if (p.exitCode !== null) throw Error(p.output());
    try {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 500 });
      return true;
    } catch {
      return false;
    }
  }, 20);
  browsers.push(browser);
  const page = await wait(() => browser.contexts()[0]?.pages()[0]);
  page.on('pageerror', (e) => logs.push('PAGE ERROR ' + e.message));
  await page.waitForFunction(() => !!window.flowgate);
  return [p, page];
}
const snap = (page) => page.evaluate(() => window.flowgate.snapshot());
const received = (port) =>
  (readFileSync(path.join(run, `receiver-${port}.log`), 'utf8').match(/RECEIVED/g) || []).length;
function command(operation, port = 41001) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(path.join(run, 'demo.sock'));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ operation, port })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
function cpuTree(pid) {
  const processes = execFileSync('ps', ['-eo', 'pid=,ppid=,rss=,time='], { encoding: 'utf8' })
    .trim()
    .split('\n')
    .map((l) => l.trim().split(/\s+/));
  const ids = new Set([pid]);
  let change = true;
  while (change) {
    change = false;
    for (const [id, parent] of processes)
      if (ids.has(+parent) && !ids.has(+id)) {
        ids.add(+id);
        change = true;
      }
  }
  let ticks = 0,
    rss = 0;
  for (const [id, , memory] of processes) {
    if (!ids.has(+id)) continue;
    try {
      const text = readFileSync(`/proc/${id}/stat`, 'utf8');
      const f = text.slice(text.lastIndexOf(')') + 2).split(' ');
      ticks += +f[11] + +f[12];
      rss += +memory;
    } catch {}
  }
  return { pids: [...ids], ticks, rssKiB: rss };
}
try {
  const [first, fi] = await fixture('alpha');
  const [second, si] = await fixture('beta');
  const [hidden, hi] = await fixture('hidden', 'hidden');
  let obs = start(
    path.join(root, '.workspace/flowgate'),
    ['observe', '--socket', path.join(run, 'obs.sock'), '--interval', '500ms'],
    'observer',
  );
  await wait(() => existsSync(path.join(run, 'obs.sock')));
  const lab = start('scripts/lab.sh', ['python3', 'scripts/desktop-lab.py', run, '6s'], 'lab');
  await wait(() => existsSync(path.join(run, 'ready')));
  const [gui, page] = await electron(path.join(run, 'obs.sock'), path.join(run, 'control.sock'));
  await wait(async () => {
    const s = await snap(page);
    return s.observation.connected && s.control.connected;
  });
  assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
  assert.equal(await page.evaluate(() => typeof window.process), 'undefined');
  assert.deepEqual(await page.evaluate(() => Object.keys(window.flowgate).sort()), [
    'decide',
    'dismissPrompt',
    'openPrompt',
    'snapshot',
    'subscribe',
  ]);
  await assert.rejects(() =>
    page.evaluate(() =>
      window.flowgate.decide({
        id: 'x',
        action: 'allow',
        scope: 'once',
        generation: 'x',
        operation: 'stop',
      }),
    ),
  );
  console.log('PASS sandboxed renderer bridge surface, no Node globals, invalid decision rejected');
  const socketRow = async (info) =>
    (await snap(page)).observation.activity?.rows.find(
      (r) => r.socket.protocol === 'tcp' && r.socket.local.endsWith(':' + info.client4),
    );
  await wait(async () => {
    const r = await socketRow(fi);
    return r?.traffic.available;
  });
  await page.locator('#search').fill(run);
  await page.locator('#expand').click();
  for (const p of [first, second]) p.stdin.write('t\n');
  await wait(async () => {
    const r = await socketRow(fi);
    return (
      r?.traffic.uploaded === 262144 && r.traffic.downloaded === 131072 && r.traffic.upload_bps > 0
    );
  });
  const id = (await socketRow(fi)).id;
  await page.locator(`[data-id=${JSON.stringify(id)}]`).click();
  await page.evaluate(() => {
    const range = document.createRange();
    range.selectNodeContents(document.querySelector('#info dd'));
    getSelection().removeAllRanges();
    getSelection().addRange(range);
  });
  await sleep(1100);
  assert.equal(await page.evaluate(() => getSelection().toString()), 'tcp');
  console.log('PASS selectable detail text survives real observer refresh');
  await page.locator('.col-uploaded button').click();
  assert.equal(
    await page.locator(`[data-id=${JSON.stringify(id)}]`).getAttribute('aria-selected'),
    'true',
  );
  await page.screenshot({ path: path.join(run, 'electron-activity.png') });
  await page.locator('#search').fill(String(fi.pid));
  await wait(async () => (await page.locator('#rows tr').count()) > 0);
  assert.equal(
    await page
      .locator('#rows')
      .innerText()
      .then((s) => s.includes(String(si.pid))),
    false,
  );
  await page.locator('#filter').selectOption('listening');
  await wait(async () => !(await page.locator('#rows').innerText()).includes('Established'));
  await page.locator('#filter').selectOption('all');
  // Hidden ownership is exercised by a real non-dumpable fixture, then restored.
  await page.locator('#search').fill(':' + hi.client4);
  await page.locator('#expand').click();
  const before = await socketRow(hi);
  assert.equal(before.owners.length, 0);
  await page.locator(`[data-id=${JSON.stringify(before.id)}]`).click();
  hidden.stdin.write('v\n');
  await wait(async () => !!(await socketRow(hi))?.owners.length);
  await wait(
    async () =>
      (await page
        .locator(`[data-id=${JSON.stringify(before.id)}]`)
        .getAttribute('aria-selected')) === 'true',
  );
  assert.equal((await socketRow(hi)).id, before.id);
  console.log(
    'PASS real TCP4 endpoints, exact observed bytes and positive rates; search/filter/sort; real Unidentified expansion and reassociation preserves selection',
  );
  obs.kill('SIGTERM');
  await wait(() => obs.exitCode !== null);
  await wait(async () => !(await snap(page)).observation.connected);
  assert.equal(await page.locator('#rows tr').count(), 0);
  obs = start(
    path.join(root, '.workspace/flowgate'),
    ['observe', '--socket', path.join(run, 'obs.sock'), '--interval', '500ms'],
    'observer-restart',
  );
  await wait(async () => (await snap(page)).observation.connected);
  await wait(async () => (await socketRow(fi))?.traffic.uploaded === 0);
  console.log('PASS observer loss clears rows/rates; reconnect starts fresh observed baseline');
  await page.locator('#search').fill(run);
  await page.locator('#expand').click();
  // Idle UI process tree: current RSS sum (shared mappings may be counted twice).
  const c0 = cpuTree(gui.pid);
  await sleep(2500);
  const c1 = cpuTree(gui.pid);
  const hz = +execFileSync('getconf', ['CLK_TCK'], { encoding: 'utf8' });
  const resources = {
    intervalSeconds: 2.5,
    rssSumKiB: c1.rssKiB,
    cpuSeconds: (c1.ticks - c0.ticks) / hz,
    pids: c1.pids,
  };
  writeFileSync(path.join(run, 'resources.json'), JSON.stringify(resources, null, 2));
  console.log('RESOURCES', JSON.stringify(resources));
  await page.locator('#requestsTab').click();
  async function request(port) {
    await command('send', port);
    return await wait(async () =>
      (await snap(page)).control.events.find(
        (e) => e.flow.local.endsWith(':' + port) && e.state === 'awaiting-decision',
      ),
    );
  }
  async function select(e) {
    await page.locator(`#requestRows tr[data-id=${JSON.stringify(e.id)}]`).click();
  }
  let e = await request(41001);
  assert.equal(received(41001), 0);
  await select(e);
  await page.locator('.open-prompt').click();
  const prompt = await wait(() =>
    browser
      .contexts()[0]
      .pages()
      .find((p) => p.url().includes('?request=')),
  );
  await prompt.waitForSelector('#allow');
  await prompt.screenshot({ path: path.join(run, 'electron-prompt.png') });
  await prompt.locator('#allow').click();
  await wait(() => received(41001) === 1);
  await prompt.close();
  console.log('PASS Electron prompt Allow delivers actual retained UDP');
  e = await request(41002);
  await select(e);
  await page.locator('#block').click();
  await wait(
    async () => (await snap(page)).control.events.find((v) => v.id === e.id)?.state === 'blocked',
  );
  assert.equal(received(41002), 0);
  console.log('PASS Electron Block prevents actual UDP delivery');
  e = await request(41003);
  await select(e);
  await page.locator('#scope').selectOption('application');
  const preview = await page.locator('#scopePreview').innerText();
  assert.equal(preview, e.scope_previews.application);
  await page.locator('#allow').click();
  await wait(() => received(41003) === 1);
  await command('send', 41003);
  await wait(() => received(41003) === 2);
  console.log(
    'PASS exact backend scope preview; remembered scope delivers a new source-port attempt',
  );
  e = await request(41004);
  await select(e);
  await wait(
    async () => (await snap(page)).control.events.find((v) => v.id === e.id)?.remainingMs === 0,
    9,
  );
  assert.equal(received(41004), 0);
  await assert.rejects(async () =>
    page.evaluate((d) => window.flowgate.decide(d), {
      generation: (await snap(page)).control.generation,
      id: e.id,
      action: 'allow',
      scope: 'once',
    }),
  );
  console.log('PASS expired/stale request cannot grant');
  e = await request(41005);
  await select(e);
  const r = await call(path.join(run, 'control.sock'), {
    operation: 'decide',
    id: e.id,
    action: 'block',
    scope: 'once',
  });
  assert.equal(r.decision.state, 'blocked');
  await wait(async () => await page.locator('#allow').isDisabled());
  assert.equal(received(41005), 0);
  console.log('PASS resolution through another authenticated client disables Electron decision');
  e = await request(41006);
  await select(e);
  const [readGui, readPage] = await electron(
    path.join(run, 'obs.sock'),
    path.join(run, 'control.sock.monitor'),
  );
  await wait(async () => (await snap(readPage)).control.connected);
  assert.equal((await snap(readPage)).control.readOnly, true);
  await readPage.locator('#requestsTab').click();
  await readPage.locator(`#requestRows tr[data-id=${JSON.stringify(e.id)}]`).click();
  assert.equal(await readPage.locator('#allow').isDisabled(), true);
  await assert.rejects(async () =>
    readPage.evaluate((d) => window.flowgate.decide(d), {
      generation: (await snap(readPage)).control.generation,
      id: e.id,
      action: 'allow',
      scope: 'once',
    }),
  );
  readGui.kill('SIGTERM');
  console.log('PASS actual read-only API disables and rejects decisions');
  await command('stop-backend');
  await wait(async () => !(await snap(page)).control.connected);
  assert.equal(await page.locator('#allow').isDisabled(), true);
  assert.equal((await snap(page)).observation.connected, true);
  assert.equal(received(41006), 0);
  console.log('PASS controller loss disables decisions while real Activity continues');
  await page.locator('#activityTab').click();
  await page.screenshot({ path: path.join(run, 'electron-main.png') });
  const [narrowGui, narrow] = await electron(path.join(run, 'obs.sock'), undefined, [
    '--width',
    '860',
    '--height',
    '600',
  ]);
  await wait(async () => (await snap(narrow)).observation.connected);
  await narrow.locator('#search').fill(run);
  await narrow.locator('#expand').click();
  await narrow.screenshot({ path: path.join(run, 'electron-narrow.png') });
  assert.equal(await narrow.evaluate(() => innerWidth), 860);
  assert.equal(
    await narrow.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
  );
  narrowGui.kill('SIGTERM');
  assert.equal(logs.length, 0, logs.join('\n'));
  console.log('PASS normal/narrow captures; no renderer exceptions');
  console.log('EVIDENCE', run);
} finally {
  for (const b of browsers) await b.close().catch(() => {});
  for (const p of children.reverse()) {
    if (p.exitCode === null) {
      p.kill('SIGTERM');
      await wait(() => p.exitCode !== null, 5).catch(() => p.kill('SIGKILL'));
    }
  }
  writeFileSync(path.join(run, 'renderer.log'), logs.join('\n'));
}
