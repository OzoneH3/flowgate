// Targeted real requests while the GUI is absent. Disposable fixture only.
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
const run = fs.mkdtempSync(project + '/.workspace/gui-reopen-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let end = Date.now() + 20000; Date.now() < end;) {
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
async function batch(item) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify({ op: 'batch', items: [item] }));
  await wait(() => fs.existsSync(f));
}
let app, main;
const result = { run, generation: ready.generation, errors: [], steps: [] };
async function launch() {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      root + '/electron',
      '--observer',
      ready.monitor_socket,
      '--control',
      ready.socket,
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  main = await app.firstWindow();
  main.on('pageerror', (e) => result.errors.push(String(e)));
  await main.locator('#rows tr[data-id^="app:"]').first().waitFor();
}
async function quit() {
  const closed = app.waitForEvent('close');
  await main
    .evaluate(() => {
      void window.flowgate.quit();
    })
    .catch((e) => {
      if (!/closed|destroyed/i.test(String(e))) throw e;
    });
  await closed;
  app = undefined;
}
try {
  await launch();
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await main.selectOption('#protectionProfile', 'both');
  await main.click('#protectionCheck');
  await wait(async () => (await main.evaluate(() => window.flowgate.protectionState())).canStart);
  await main.click('#protectionStart');
  await wait(async () => (await call({ operation: 'list' })).protection.state === 'active');
  await quit();
  assert.equal((await call({ operation: 'list' })).protection.state, 'active');
  result.steps.push('ordinary GUI Quit leaves continuous protection active');
  await batch({ op: 'incoming', name: 'alpha', protocol: 'tcp', v6: true });
  const held = await wait(async () =>
    ((await call({ operation: 'list' })).events || []).find((e) => e.state === 'awaiting-decision'),
  );
  await launch();
  const prompt = await wait(() =>
    app
      .windows()
      .find((w) => new URL(w.url() || 'about:blank').searchParams.get('request') === held.id),
  );
  await prompt.click('#allow');
  await wait(
    async () =>
      ((await call({ operation: 'list' })).events || []).find((e) => e.id === held.id)?.state ===
      'allowed',
  );
  await prompt.close();
  result.steps.push('attempt during GUI absence is actionable on reopen before original deadline');
  await quit();
  await batch({ op: 'incoming', name: ready.other ? 'other' : 'beta', protocol: 'tcp', v6: false });
  const expires = await wait(async () =>
    ((await call({ operation: 'list' })).events || []).find((e) => e.state === 'awaiting-decision'),
  );
  await wait(
    async () =>
      Date.parse(expires.deadline) < Date.parse((await call({ operation: 'list' })).server_time),
  );
  await launch();
  await sleep(1000);
  assert.equal(app.windows().filter((w) => w.url().includes('?request=')).length, 0);
  assert.equal(
    (await main.evaluate(() => window.flowgate.snapshot())).control.events.filter(
      (e) => e.state === 'awaiting-decision' && e.remainingMs > 0,
    ).length,
    0,
  );
  result.steps.push('expired attempt during GUI absence is never reopened as actionable');
  await main.evaluate(() => {
    document.getElementById('toolsMenu').open = true;
    document.getElementById('controlMenu').open = true;
  });
  await main.click('#protectionStop');
  await wait(async () => (await call({ operation: 'list' })).protection.state === 'stopped');
  assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
  result.passed = true;
  assert.deepEqual(result.errors, []);
  console.log('PASS GUI REOPEN', run, JSON.stringify(result.steps));
} catch (e) {
  result.failure = String(e);
  throw e;
} finally {
  if (app) await app.close();
  fs.writeFileSync(run + '/result.json', JSON.stringify(result, null, 2));
}
