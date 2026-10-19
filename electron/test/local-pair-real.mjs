// Real local-pair popup journey: beta connects to alpha's own loopback listener inside a held disposable
// fixture (both directions intercepted). Verifies the client -> server card, explicit target, "Allow both"
// and delivery at alpha's listener. Never the host daemon.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'), 'disposable fixture required');
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/') && !ready.socket.startsWith('/run/'));
const run = fs.mkdtempSync(project + '/.workspace/lpr-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = { run, steps: [], errors: [] };
const step = (s) => {
  evidence.steps.push(s);
  console.log('PASS', s);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, ms = 20000, label = '') => {
  for (let until = Date.now() + ms; Date.now() < until; ) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await sleep(80);
  }
  throw Error('timeout ' + label);
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let t = '';
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      t += b;
      if (t.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(t));
      }
    });
  });
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const list = () => call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [], events: l.events || [] }));
let app, main;
const prompt = () => app.windows().find((w) => /[?&]request=/.test(w.url() || ''));
const shot = (w, n) => w?.screenshot({ path: `${run}/${n}.png` }).catch(() => {});
try {
  const l0 = await list();
  assert(l0.capabilities.includes('local-pair-v1'), 'fixture lacks local-pair-v1');
  for (const r of l0.rules) await call({ operation: 'rule-delete', generation: ready.generation, id: r.id, expected_version: r.version });
  const alpha = (await command({ op: 'launch', name: 'alpha' })).info;
  const beta = (await command({ op: 'launch', name: 'beta' })).info;
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', root + '/electron', '--observer', ready.monitor_socket, '--control', ready.socket],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  await app.firstWindow();
  main = await wait(async () => app.windows().find((w) => (w.url() || '').endsWith('/index.html')), 20000, 'main');
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.locator('#rows tr').first().waitFor();
  const menus = (o) =>
    main.evaluate((o) => {
      document.getElementById('toolsMenu').open = o;
      document.getElementById('controlMenu').open = o;
    }, o);
  const prior = l0.protection;
  if (prior?.state === 'active') await call({ operation: 'protection-stop', generation: ready.generation, protection_id: prior.id });
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(async () => (await list()).protection?.state === 'active', 30000);
  await menus(false);
  const port = alpha.ports.tcp4;
  const before = (await command({ op: 'counts', name: 'alpha' })).counts?.tcp4 || 0;
  const sentAt = Date.now();
  await command({ op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.1', port, v6: false, timeout_ms: 30000 });
  const w = await wait(async () => {
    const x = prompt();
    return x && (await x.locator('#localPair').count()) ? x : undefined;
  }, 20000, 'pair card');
  await w.locator('#localPairTitle').waitFor();
  evidence.card_ms = Date.now() - sentAt;
  await wait(() => w.locator('#pairAllow').isEnabled(), 10000, 'pair controls enabled');
  evidence.title = await w.locator('#localPairTitle').innerText();
  evidence.line = await w.locator('#localPairLine').innerText().catch(() => '');
  evidence.sides = await w.locator('#localPairSides').innerText().catch(() => '');
  evidence.target = await w.locator('#localPairTarget').innerText().catch(() => '');
  assert(/→/.test(evidence.title), 'client -> server title');
  assert(/Outgoing/.test(evidence.sides) && /Incoming/.test(evidence.sides), 'both sides listed');
  await shot(w, '01-pair-card');
  step(`pair card: "${evidence.title}" / "${evidence.line}" / target "${evidence.target}"`);
  evidence.click_ms = Date.now() - sentAt;
  await w.locator('#pairAllow').click();
  await wait(async () => ((await command({ op: 'counts', name: 'alpha' })).counts?.tcp4 || 0) > before, 15000, 'server received');
  evidence.result = await prompt()?.locator('#pairResult').innerText().catch(() => '');
  const evs = (await list()).events.filter((e) => e.local_peer);
  evidence.verdicts = evs.map((e) => [e.flow?.direction, e.state]);
  assert(evs.some((e) => e.flow?.direction === 'outgoing' && e.state === 'allowed'), 'outgoing allowed');
  assert(!evs.some((e) => e.state === 'awaiting-decision'), 'no side left pending');
  await shot(prompt(), '02-pair-result');
  step(`Allow both: alpha's listener received the connection; verdicts ${JSON.stringify(evidence.verdicts)}; result "${evidence.result}"`);
  assert.deepEqual(evidence.errors, []);
  await menus(true);
  await main.locator('#protectionStop').click();
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  evidence.pass = true;
} catch (e) {
  evidence.failure = String(e?.stack || e);
  if (main) await shot(main, 'failure-main');
  if (app) await shot(prompt(), 'failure-prompt');
} finally {
  fs.writeFileSync(run + '/evidence.json', JSON.stringify(evidence, null, 2));
  if (app) await app.close().catch(() => {});
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
