// Real queue-reconciliation journey: sandboxed GUI against a held disposable fixture through a proxy socket
// that can replay a stale (pre-decision) list response. Never the host daemon. Receivers judge delivery.
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
const run = fs.mkdtempSync(project + '/.workspace/qr-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = { run, fixture: readyPath, steps: [], errors: [] };
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
  throw Error('timeout ' + (label || fn));
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let text = '';
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      text += b;
      if (text.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(text));
      }
    });
  });
// Proxy: forwards everything; when armed, answers the next `list` with a stale captured response once.
let staleList = null,
  replayStale = false,
  staleServed = 0;
const proxyPath = run + '/api';
const proxy = net.createServer((s) =>
  s.once('data', async (b) => {
    const q = JSON.parse(b);
    try {
      if (q.operation === 'list' && replayStale && staleList) {
        replayStale = false;
        staleServed++;
        s.end(staleList + '\n');
        return;
      }
      const r = await call(q);
      s.end(JSON.stringify(r) + '\n');
    } catch {
      s.destroy();
    }
  }),
);
await new Promise((r) => proxy.listen(proxyPath, r));
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const peerLines = async () => (await command({ op: 'peer-counts' })).lines.length;
const list = () =>
  call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [], events: l.events || [], leases: l.process_leases || [] }));
const awaiting = async (pid) =>
  (await list()).events.filter((e) => e.state === 'awaiting-decision' && (!pid || e.attribution?.owners?.some((o) => o.pid === pid)));
let app, main;
const prompt = () => app.windows().find((w) => /[?&]request=/.test(w.url() || ''));
const shot = (w, n) => w?.screenshot({ path: `${run}/${n}.png` }).catch(() => {});
const cardText = async () => (await prompt()?.locator('body').innerText().catch(() => '')) || '';
async function drain() {
  for (let n = 0; n < 10 && (await awaiting()).length; n++) {
    const w = prompt();
    if (w && (await w.locator('#block').isEnabled().catch(() => false))) await w.locator('#block').click();
    await sleep(900);
  }
}
try {
  const initial = await list();
  for (const c of ['queue-reconcile-v1', 'request-for-a-while-v1', 'decision-for-a-while-durations-v1'])
    assert(initial.capabilities.includes(c), 'fixture lacks ' + c);
  for (const r of initial.rules)
    await call({ operation: 'rule-delete', generation: ready.generation, id: r.id, expected_version: r.version });
  const pids = {};
  for (const n of ['alpha', 'beta', 'other']) pids[n] = (await command({ op: 'launch', name: n })).info.pid;
  evidence.pids = pids;
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', root + '/electron', '--observer', ready.monitor_socket, '--control', proxyPath],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  await app.firstWindow();
  main = await wait(async () => app.windows().find((w) => (w.url() || '').endsWith('/index.html')), 20000, 'main window');
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.locator('#rows tr').first().waitFor();
  const menus = (o) =>
    main.evaluate((o) => {
      document.getElementById('toolsMenu').open = o;
      document.getElementById('controlMenu').open = o;
    }, o);
  const prior = (await list()).protection;
  if (prior?.state === 'active') await call({ operation: 'protection-stop', generation: ready.generation, protection_id: prior.id });
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(async () => (await list()).protection?.state === 'active', 30000);
  await menus(false);

  // 1. Several pending from alpha (2 TCP same destination = distinct source ports, TCP other destination, UDP) + sibling beta.
  for (const [p, h, port] of [
    ['tcp', '10.79.0.2', 43000],
    ['tcp', '10.79.0.2', 43000],
    ['tcp', '10.79.0.3', 44000],
    ['udp', '10.79.0.3', 44001],
  ])
    await command({ op: 'outgoing', name: 'alpha', protocol: p, host: h, port, v6: false, timeout_ms: 25000 });
  await command({ op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.2', port: 43000, v6: false, timeout_ms: 25000 });
  await wait(async () => (await awaiting()).length >= 5, 15000, '5 pending');
  const w0 = await wait(async () => prompt(), 15000, 'prompt');
  await w0.locator('#allow').waitFor();
  await sleep(800);
  const firstText = await cardText();
  evidence.first_card = firstText.slice(0, 400);
  assert(/:\d{4,5}/.test(firstText), 'card shows local source port to distinguish connections');
  staleList = JSON.stringify(await call({ operation: 'list' })); // captured BEFORE the decision
  const firstId = new URL(w0.url()).searchParams.get('request');
  const before = await peerLines();
  const clickAt = Date.now();
  await w0.locator('#allow').click(); // Allow Once
  // Same click must not decide/advance onto the next request immediately.
  const pend1 = await wait(async () => {
    const e = (await list()).events.find((x) => x.id === firstId);
    return e && e.state !== 'awaiting-decision' ? e : undefined;
  }, 8000);
  evidence.once_state = pend1.state;
  await wait(async () => (await peerLines()) > before, 6000, 'once delivered');
  const stillAwaiting = (await awaiting()).length;
  assert(stillAwaiting >= 3, `Once settles nothing else (awaiting ${stillAwaiting})`);
  // Stale poll: replay the pre-decision list once; the decided request must not reappear.
  replayStale = true;
  await wait(async () => staleServed > 0, 10000, 'stale list served');
  await sleep(1500);
  const shown = prompt() ? new URL(prompt().url()).searchParams.get('request') : null;
  assert.notEqual(shown, firstId, 'stale poll reopened the decided request');
  const nextAt = await wait(async () => {
    const w = prompt();
    return w && new URL(w.url()).searchParams.get('request') !== firstId ? Date.now() : undefined;
  }, 10000, 'next card');
  evidence.advance_ms = nextAt - clickAt;
  assert(evidence.advance_ms >= 650, 'next prompt appeared under the same click (' + evidence.advance_ms + 'ms)');
  step(`Allow Once delivered its flow only (${stillAwaiting} still pending); stale pre-decision list did not reopen ${firstId.slice(0, 8)}; next card after ${evidence.advance_ms} ms`);

  // 2. For a while (1 min) on an alpha card: alpha's queued requests settle without prompts; beta keeps its own.
  let w = await wait(async () => {
    const x = prompt();
    if (!x) return undefined;
    const id = new URL(x.url()).searchParams.get('request');
    const e = (await list()).events.find((v) => v.id === id);
    return e?.attribution?.owners?.some((o) => o.pid === pids.alpha) ? x : undefined;
  }, 15000, 'alpha card').catch(async () => {
    // Beta may be presented first; answer it once with Deny, then the alpha card follows.
    await prompt()?.locator('#block').click();
    await sleep(1200);
    return prompt();
  });
  await w.locator('#forAWhileToggle').check();
  await w.locator('#forAWhileDuration').waitFor();
  await w.locator('#forAWhileDuration').selectOption('60');
  evidence.expiry_preview = await w.locator('#forAWhileExpiry').innerText();
  assert(/until/i.test(evidence.expiry_preview), 'expiry shown before click');
  const b2 = await peerLines();
  await w.locator('#allow').click();
  await wait(async () => !(await awaiting(pids.alpha)).length, 10000, 'alpha queue settled');
  await wait(async () => (await peerLines()) >= b2 + 2, 8000, 'settled alpha flows delivered');
  const lease = (await list()).leases.find((l) => l.pid === pids.alpha);
  assert(lease && lease.seconds === 60, 'backend lease 60 s');
  evidence.lease = lease;
  assert((await awaiting(pids.beta)).length >= 1, 'sibling still pending');
  await shot(prompt(), '02-after-for-a-while');
  step(`For a while (60 s, backend until ${lease.until}) settled all queued alpha requests without prompts; sibling still pending`);
  await drain();

  // 3. Ended request, process alive: For a while Deny (1 min) blocks next TCP+UDP; sibling independent.
  await command({ op: 'outgoing', name: 'other', protocol: 'tcp', host: '10.79.0.3', port: 44000, v6: false, timeout_ms: 30000 });
  await wait(async () => /10\.79\.0\.3:44000/.test(await cardText()), 15000, 'other card');
  await command({ op: 'close', name: 'other' });
  await wait(async () => /connection has ended|no longer pending/i.test(await cardText()), 30000, 'ended card');
  w = prompt();
  evidence.ended_card = (await cardText()).slice(0, 500);
  assert(!/original socket is no longer present/.test(evidence.ended_card), 'raw diagnostics hidden from main card');
  assert(await w.locator('#forAWhileToggle').isEnabled(), 'For a while offered for live process');
  await w.locator('#forAWhileToggle').check();
  await w.locator('#forAWhileDuration').selectOption('60');
  await w.locator('#block').click();
  const res = await wait(async () => {
    const t = await cardText();
    return /This ended request was not delivered/.test(t) ? t : undefined;
  }, 10000, 'ended lease result');
  evidence.ended_result = res.match(/For a while:[^\n]*/)?.[0];
  const b3 = await peerLines();
  await command({ op: 'outgoing', name: 'other', protocol: 'tcp', host: '10.79.0.2', port: 43000, v6: false, timeout_ms: 4000 });
  await command({ op: 'outgoing', name: 'other', protocol: 'udp', host: '10.79.0.3', port: 44001, v6: false, timeout_ms: 4000 });
  await sleep(2500);
  assert.equal(await peerLines(), b3, 'lease Deny blocks next TCP+UDP');
  assert(!(await awaiting(pids.other)).length, 'no prompt for covered attempts');
  await shot(prompt(), '03-ended-live-deny');
  step(`ended card (process alive): "${evidence.ended_result}"; next TCP+UDP blocked without prompt`);
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
  proxy.close();
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
