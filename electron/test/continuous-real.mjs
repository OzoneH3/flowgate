// Released real private backend, sandboxed GUI. Uses no host endpoint or lifecycle.
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
const run = fs.mkdtempSync(project + '/.workspace/continuous-real-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const call = (q, socket = ready.socket) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(socket);
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let until = Date.now() + 20000; Date.now() < until;) {
    const v = await fn();
    if (v) return v;
    await sleep(60);
  }
  throw Error('condition timeout ' + fn);
};
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(() => fs.existsSync(f));
  return JSON.parse(fs.readFileSync(f));
}
let offline = false,
  dropDecision = false;
const operations = [];
const proxy = net.createServer((s) =>
  s.once('data', async (b) => {
    const q = JSON.parse(b);
    operations.push({ op: q.operation, generation: q.generation, id: q.id, at: Date.now() });
    try {
      if (offline) throw Error('deliberate disconnect');
      const r = await call(q);
      if (dropDecision && q.operation === 'decide') {
        dropDecision = false;
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
const evidence = { run, generation: ready.generation, errors: [], steps: [] };
let app, main;
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
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
  await main.setViewportSize({ width: 1280, height: 720 });
}
const state = () => main.evaluate(() => window.flowgate.protectionState());
const promptFor = (id) =>
  wait(() =>
    app.windows().find((w) => new URL(w.url() || 'about:blank').searchParams.get('request') === id),
  );
const pending = async () =>
  ((await call({ operation: 'list' })).events || []).filter((e) => e.state === 'awaiting-decision');
try {
  const initial = await call({ operation: 'list' });
  assert.equal(initial.generation, ready.generation);
  assert.equal((initial.rules||[]).length, 0);
  await launch();
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  assert.match((await state()).label, /Monitoring only/);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(async () => (await state()).canStart);
  await main.locator('#protectionStart').click();
  await wait(async () => (await state()).status?.state === 'active');
  assert.equal((await state()).status.profile, 'both');
  assert.match((await state()).label, /outgoing.*active/);
  evidence.steps.push('continuous both active from authoritative status');
  await main.screenshot({ path: run + '/continuous-active.png' });
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = false;
    document.getElementById('controlMenu').open = false;
  });
  await main.click('#expand');
  await main.locator('#rows tr[data-id^="process:"] .name').first().click();
  await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
  const info = await wait(() => app.windows().find((w) => w.url().includes('pane=info')));
  await info.locator('#paneContent').waitFor();
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()
      .find((w) => w.webContents.getURL().endsWith('/index.html'))
      .hide(),
  );
  await command({
    op: 'batch',
    items: [
      { op: 'incoming', name: 'alpha', protocol: 'tcp', v6: false },
      { op: 'outgoing', name: 'beta', protocol: 'udp', v6: true },
    ],
  });
  const pair = await wait(async () => {
    const v = await pending();
    return v.length >= 2 ? v : undefined;
  });
  const first = await wait(() => app.windows().find((w) => w.url().includes('?request=')));
  const firstId = new URL(first.url()).searchParams.get('request');
  first.on('pageerror', (e) => evidence.errors.push(String(e)));
  assert(pair.some((e) => e.id === firstId));
  await first.locator('#allow').waitFor();
  await first.locator('#requestDetails').focus();
  await first.keyboard.press('Enter');
  await first.keyboard.press('Enter');
  assert.equal((await pending()).length, 2);
  await first.screenshot({ path: run + '/concurrent-first.png' });
  await first.click('#allow');
  await wait(
    async () =>
      (await call({ operation: 'list' })).events.find((e) => e.id === firstId)?.state === 'allowed',
  );
  await first.locator('#dismiss').click();
  const other = pair.find((e) => e.id !== firstId);
  const second = await promptFor(other.id);
  await wait(async () => await second.locator('#allow').isDisabled());
  assert.equal(new URL(second.url()).searchParams.get('request'), other.id);
  evidence.steps.push(
    'concurrent requests pinned; Enter does not decide; expiry disables current request',
  );
  await command({
    op: 'batch',
    items: [{ op: 'incoming', name: 'beta', protocol: 'tcp', v6: true }],
  });
  const third = await wait(async () =>
    (await pending()).find((e) => e.id !== firstId && e.id !== other.id),
  );
  assert.equal(new URL(second.url()).searchParams.get('request'), other.id);
  await second.locator('#dismiss').filter({ hasText: 'Next request' }).click();
  const next = await promptFor(third.id);
  await next.click('#block');
  await wait(
    async () =>
      (await call({ operation: 'list' })).events.find((e) => e.id === third.id)?.state ===
      'blocked',
  );
  await next.close();
  await command({
    op: 'batch',
    items: [{ op: 'outgoing', name: 'alpha', protocol: 'udp', v6: false }],
  });
  const fourth = await wait(async () =>
    (await pending()).find((e) => ![firstId, other.id, third.id].includes(e.id)),
  );
  const lost = await promptFor(fourth.id);
  offline = true;
  await wait(async () => await lost.locator('#allow').isDisabled());
  offline = false;
  await wait(async () => !(await lost.locator('#allow').isDisabled()));
  dropDecision = true;
  const writes = operations.filter((o) => o.op === 'decide').length;
  await lost.click('#allow');
  await wait(
    async () =>
      (await call({ operation: 'list' })).events.find((e) => e.id === fourth.id)?.state ===
      'allowed',
  );
  await sleep(1200);
  assert.equal(operations.filter((o) => o.op === 'decide').length - writes, 1);
  await lost.screenshot({ path: run + '/lost-ack-outcome.png' });
  await lost.close();
  evidence.steps.push(
    'disconnect disables; lost Once ACK never replayed, actual final state visible',
  );
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()
      .find((w) => w.webContents.getURL().endsWith('/index.html'))
      .show(),
  );
  await main.locator('#rows tr[data-id^="process:"] .name').first().click();
  await info.locator('[data-focus="cell:process:incoming"]').first().click();
  await info.locator('[data-focus="qs:new:block"]').click();
  await wait(async () => !(await info.locator('.quick-popup').count()));
  const own = (await call({ operation: 'list' })).rules;
  assert.equal(own.length, 1);
  for (let i = 0; i < 3; i++) {
    assert(
      (await main.evaluate(() => window.flowgate.snapshot())).control.rules.some(
        (r) => r.id === own[0].id,
      ),
    );
    await sleep(800);
  }
  const del = await call({
    operation: 'rule-delete',
    generation: ready.generation,
    id: own[0].id,
    expected_version: own[0].version,
  });
  assert(!del.error, del.error);
  evidence.steps.push('detached quick rule stable; exact conditional deletion');
  await main.setViewportSize({ width: 860, height: 600 });
  await main.screenshot({ path: run + '/narrow.png' });
  await app.close();
  app = undefined;
  assert.equal((await call({ operation: 'list' })).protection.state, 'active');
  await launch();
  await wait(async () => (await state()).status?.state === 'active');
  assert.match((await state()).label, /outgoing.*active/);
  evidence.steps.push(
    'GUI exit leaves protection active; reopen recovers state without Start replay',
  );
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await main.locator('#protectionStop').click();
  await wait(async () => (await state()).status?.state === 'stopped');
  assert.equal((await state()).status.desired_mode, 'monitoring');
  assert.equal(operations.filter((o) => o.op === 'protection-start').length, 1);
  assert.equal(((await call({ operation: 'list' })).rules||[]).length, 0);
  evidence.steps.push('explicit Stop confirmed monitoring, one Start total');
  assert.deepEqual(evidence.errors, []);
  evidence.passed = true;
  console.log('PASS', run, JSON.stringify(evidence.steps));
} catch (e) {
  evidence.failure = String(e);
  throw e;
} finally {
  offline = false;
  if (app) await app.close();
  proxy.close();
  fs.writeFileSync(run + '/evidence.json', JSON.stringify({ ...evidence, operations }, null, 2));
}
