// Real private native fixture; UI owns decisions until explicit DONE to fixture owner.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
if (!readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable project fixture required');
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/'));
const run = fs.mkdtempSync(path.join(root, '.workspace/connection-real-'));
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn) {
  for (let end = Date.now() + 15000; Date.now() < end;) {
    const v = await fn();
    if (v) return v;
    await sleep(100);
  }
  throw Error('Timeout ' + fn);
}
async function command(q) {
  const result = path.join(dir, 'command-result.json');
  fs.rmSync(result, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(() => fs.existsSync(result));
  return JSON.parse(fs.readFileSync(result));
}
const initial = await call({ operation: 'list' });
assert.equal(initial.generation, ready.generation);
assert.equal((initial.rules || []).length, 0);
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
let app;
const evidence = { run, generation: ready.generation, journeys: [], errors: [] };
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
    ],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  const main = await app.firstWindow();
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  await main.setViewportSize({ width: 1280, height: 656 });
  await main.locator('#requestsTab').click();
  const seen = new Set();
  async function decide(op, name, protocol, v6, action, scope = 'once') {
    const before = await command(
      op === 'incoming' ? { op: 'counts', name } : { op: 'peer-counts' },
    );
    const transfer = command({ op, name, protocol, v6 });
    const e = await wait(async () => {
      const r = await call({ operation: 'list' });
      return (r.events || []).find(
        (e) =>
          e.state === 'awaiting-decision' &&
          e.flow.direction === op &&
          e.flow.protocol === protocol &&
          !seen.has(e.id),
      );
    });
    seen.add(e.id);
    assert.equal(e.flow.direction, op);
    assert.equal(e.flow.protocol, protocol);
    // It must appear automatically, independently of main-window selection.
    const prompt = await wait(() =>
      app
        .windows()
        .find((w) => new URL(w.url() || 'about:blank').searchParams.get('request') === e.id),
    );
    evidence.automaticWindow = true;
    evidence.promptBounds = await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()
        .filter((w) => w.webContents.getURL().includes('?request='))
        .map((w) => ({
          bounds: w.getBounds(),
          parent: !!w.getParentWindow(),
          sandbox: w.webContents.getLastWebPreferences().sandbox,
        })),
    );
    prompt.on('pageerror', (e) => evidence.errors.push(String(e)));
    await prompt.locator('#allow').waitFor();
    assert.match(
      await prompt.locator('#requestDetails').innerText(),
      op === 'incoming' ? /Remote peer → this program/ : /This program → remote peer/,
    );
    await prompt.locator('#requestDetails').focus();
    await prompt.keyboard.press('Enter');
    await prompt.keyboard.press('Enter');
    assert.equal(
      (await call({ operation: 'list' })).events.find((x) => x.id === e.id).state,
      'awaiting-decision',
    );
    await prompt.locator('#scope').selectOption(scope);
    if (scope !== 'once')
      assert.match(await prompt.locator('#permissionTarget').innerText(), /Any network/);
    await prompt.screenshot({
      path: path.join(run, `${op}-${protocol}-${v6 ? '6' : '4'}-${action}.png`),
    });
    if (op === 'incoming' && action === 'allow') {
      await prompt.setViewportSize({ width: 480, height: 500 });
      await prompt.screenshot({ path: path.join(run, 'incoming-narrow.png') });
    }
    await prompt.locator('#' + action).click();
    await wait(() =>
      prompt
        .locator('#requestResult')
        .innerText()
        .then((t) => /confirmed|submitted|accepted|allow|block/i.test(t)),
    );
    const response = await transfer;
    await sleep(300);
    const after = await command(op === 'incoming' ? { op: 'counts', name } : { op: 'peer-counts' });
    const key = protocol + (v6 ? '6' : '4');
    const delta =
      op === 'incoming'
        ? (after.counts[key] || 0) - (before.counts[key] || 0)
        : after.lines.length - before.lines.length;
    assert.equal(delta, action === 'allow' ? 1 : 0);
    const current = await call({ operation: 'list' });
    evidence.journeys.push({
      op,
      name,
      protocol,
      v6,
      action,
      scope,
      id: e.id,
      zone: e.flow.network_scope,
      before,
      after,
      delta,
      response,
      rules: current.rules,
    });
    fs.writeFileSync(path.join(run, 'evidence.json'), JSON.stringify(evidence, null, 2));
    await prompt.close();
  }
  await decide('incoming', 'alpha', 'udp', false, 'allow');
  await decide('incoming', 'alpha', 'udp', true, 'block');
  await decide('outgoing', 'alpha', 'udp', false, 'allow', 'application');
  const saved = (await call({ operation: 'list' })).rules || [];
  assert.equal(saved.length, 1);
  assert(!saved[0].filter.network_zone);
  assert(!saved[0].filter.process);
  const before = await command({ op: 'peer-counts' });
  await command({ op: 'outgoing', name: 'beta', protocol: 'udp', v6: false });
  await sleep(300);
  const after = await command({ op: 'peer-counts' });
  assert.equal(after.lines.length - before.lines.length, 1);
  evidence.rememberedSiblingDelivery = true;
  await decide('outgoing', 'alpha', 'tcp', false, 'block');
  await main.locator('#activityTab').click();
  await main.locator('#rows tr[data-id="network:local"] [data-direction=incoming]').click();
  await main.locator('.quick-popup').waitFor();
  await main.screenshot({ path: path.join(run, 'local-setter.png') });
  await main.keyboard.press('Escape');
  await main.locator('#rows tr[data-id="network:internet"] [data-direction=outgoing]').click();
  await main.locator('.quick-popup').waitFor();
  await main.screenshot({ path: path.join(run, 'internet-setter.png') });
  await main.keyboard.press('Escape');
  // The pane's local rule service uses the same pinned selection and backend; no extra observer.
  await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
  const pane = await wait(() => app.windows().find((w) => w.url().includes('pane.html')));
  await pane.locator('#infoRules').waitFor();
  await pane.locator('[data-direction="incoming"]').first().click();
  await pane.locator('.quick-popup').waitFor();
  await pane.screenshot({ path: path.join(run, 'detached-setter.png') });
  await pane.keyboard.press('Escape');
  await pane.locator('#dockPane').click();
  await main.setViewportSize({ width: 860, height: 600 });
  await main.screenshot({ path: path.join(run, 'activity-narrow.png') });
  const cleanup = [];
  for (const r of (await call({ operation: 'list' })).rules || []) {
    const response = await call({
      operation: 'rule-delete',
      generation: ready.generation,
      id: r.id,
      expected_version: r.version,
    });
    assert(!response.error, response.error);
    cleanup.push(response.deleted_rule);
  }
  assert.equal(((await call({ operation: 'list' })).rules || []).length, 0);
  evidence.cleanup = cleanup;
  assert.deepEqual(evidence.errors, []);
  fs.writeFileSync(path.join(run, 'evidence.json'), JSON.stringify(evidence, null, 2));
  console.log(
    'PASS real incoming Allow/Deny, outgoing Remember/nonmatch, receiver counts, quick setters, detached/narrow; rules0',
    run,
  );
} catch (e) {
  evidence.failure = String(e);
  fs.writeFileSync(path.join(run, 'evidence.json'), JSON.stringify(evidence, null, 2));
  throw e;
} finally {
  if (app) await app.close();
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
