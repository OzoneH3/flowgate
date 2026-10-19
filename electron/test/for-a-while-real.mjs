// Real "For a while" + compact prompt journey: sandboxed GUI against an externally held, disposable fixture
// (scripts/process-rules-isolated.py --hold --continuous --zones --other; op "launch" relaunches an executable).
// Never the host daemon. Private receivers (peer-received.log) judge delivery.
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
const run = fs.mkdtempSync(project + '/.workspace/for-a-while-real-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = { run, fixture: readyPath, generation: ready.generation, steps: [], errors: [] };
const step = (s) => {
  evidence.steps.push(s);
  console.log('PASS', s);
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, ms = 20000, label = '') => {
  for (let until = Date.now() + ms; Date.now() < until; ) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await sleep(80);
  }
  throw Error('timeout ' + (label || fn));
};
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture command ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const peerLines = async () => (await command({ op: 'peer-counts' })).lines.length;
const list = () =>
  call({ operation: 'list' }).then((l) => ({
    ...l,
    rules: l.rules || [],
    events: l.events || [],
    leases: l.process_leases || [],
  }));
const pidOf = async (name) => (await command({ op: 'counts', name })).pid ?? null;
let app, main;
const prompt = () => app.windows().find((w) => /[?&]request=/.test(w.url() || ''));
const facts = () =>
  app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()
      .filter((w) => /[?&]request=/.test(w.webContents.getURL()))
      .map((w) => ({ bounds: w.getBounds(), focused: w.isFocused(), top: w.isAlwaysOnTop(), visible: w.isVisible() }))[0],
  );
const shot = (w, name) => w?.screenshot({ path: `${run}/${name}.png` }).catch(() => {});
const card = async (re) =>
  wait(async () => {
    const w = prompt();
    return w && re.test(await w.locator('body').innerText()) ? w : undefined;
  }, 20000, 'card ' + re);
// Answer every remaining awaiting request once with Deny (no rule) so the next step starts clean.
async function drain() {
  for (let n = 0; n < 8; n++) {
    if (!(await list()).events.some((e) => e.state === 'awaiting-decision')) return;
    const w = prompt();
    if (w && (await w.locator('#block').isEnabled().catch(() => false))) await w.locator('#block').click();
    await sleep(500);
  }
}
async function send(name, protocol, host, port) {
  const before = await peerLines();
  await command({ op: 'outgoing', name, protocol, host, port, v6: host.includes(':'), timeout_ms: 20000 });
  return before;
}
const delivered = async (before, ms = 4000) => {
  for (let until = Date.now() + ms; Date.now() < until; await sleep(150)) if ((await peerLines()) > before) return true;
  return false;
};
try {
  const initial = await list();
  assert.equal(initial.generation, ready.generation);
  for (const c of ['decision-for-a-while-v1', 'decision-remember-fields-v1', 'request-application-rule-v1'])
    assert(initial.capabilities.includes(c), 'fixture lacks ' + c);
  for (const r of initial.rules) {
    const d = await call({ operation: 'rule-delete', generation: ready.generation, id: r.id, expected_version: r.version });
    assert(!d.error, 'fixture reset ' + JSON.stringify(d));
  }
  for (const n of ['alpha', 'beta', 'other']) await command({ op: 'launch', name: n });
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', root + '/electron', '--observer', ready.monitor_socket, '--control', ready.socket],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  main = await app.firstWindow();
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.setViewportSize({ width: 1280, height: 720 });
  await main.locator('#rows tr').first().waitFor();
  const menus = (open) =>
    main.evaluate((open) => {
      document.getElementById('toolsMenu').open = open;
      document.getElementById('controlMenu').open = open;
    }, open);
  const prior = (await list()).protection;
  if (prior?.state === 'active') await call({ operation: 'protection-stop', generation: ready.generation, protection_id: prior.id });
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(async () => (await list()).protection?.state === 'active', 30000, 'protection active');
  await menus(false);
  step('fixture protection active (UI Start); host untouched');

  // 1. Compact first view, no focus theft, always on top, NetLimiter order, mutual exclusion.
  let before = await send('alpha', 'tcp', '10.79.0.2', 43000);
  let w = await card(/10\.79\.0\.2:43000/);
  await w.locator('#forAWhileToggle').waitFor();
  await sleep(900);
  const compact = await facts();
  evidence.compact = compact;
  assert.equal(compact.bounds.width, 520);
  assert.equal(compact.bounds.height, 460);
  assert(!compact.focused, 'prompt took focus');
  assert(compact.top, 'prompt not always on top');
  const order = await w.locator('#allow, #block, #rememberToggle, #forAWhileToggle').evaluateAll((xs) => xs.map((x) => x.id));
  assert.deepEqual(order, ['allow', 'block', 'rememberToggle', 'forAWhileToggle'], 'NetLimiter order');
  assert(!(await w.locator('#requestMore').evaluate((d) => d.open)), 'Details collapsed');
  evidence.compact_text = (await w.locator('body').innerText()).slice(0, 800);
  await shot(w, '01-compact');
  await w.locator('#rememberToggle').check();
  await w.locator('#forAWhileToggle').check();
  assert(!(await w.locator('#rememberToggle').isChecked()), 'For a while unchecks Remember');
  await w.locator('#rememberToggle').check();
  assert(!(await w.locator('#forAWhileToggle').isChecked()), 'Remember unchecks For a while');
  step(`compact 520x460, unfocused, always-on-top; order Allow|Deny|Remember|For a while; mutually exclusive both ways`);

  // 800x550: buttons and duration select stay visible.
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL())).setSize(800, 550),
  );
  await sleep(700);
  const visible = await w.evaluate(() => {
    const inView = (id) => {
      const r = document.getElementById(id)?.getBoundingClientRect();
      return !!r && r.height > 0 && r.top >= 0 && r.bottom <= window.innerHeight;
    };
    return { allow: inView('allow'), block: inView('block'), duration: inView('rememberDuration'), h: window.innerHeight };
  });
  evidence.at_800x550 = visible;
  assert(visible.allow && visible.block && visible.duration, '800x550 visibility ' + JSON.stringify(visible));
  await shot(w, '02-remember-800x550');
  step('at 800x550 Allow, Deny and the deletion-time select are visible');

  // 2. For a while + Allow: current delivered, lease line counts down, same process new TCP/UDP no prompt.
  await w.locator('#forAWhileToggle').check();
  await w.locator('#allow').click();
  assert(await delivered(before), 'current request delivered');
  const lease = await wait(async () => (await list()).leases[0], 8000, 'lease listed');
  evidence.lease = lease;
  assert.equal(lease.action, 'allow');
  assert.equal((await list()).rules.length, 0, 'no rule stored');
  const line1 = await wait(async () => {
    const t = await prompt()?.locator('#leaseLine').innerText();
    return /s left/.test(t || '') ? t : undefined;
  }, 5000, 'lease line');
  await sleep(2200);
  const line2 = (await prompt()?.locator('#leaseLine').innerText().catch(() => '')) || '';
  evidence.lease_lines = [line1, line2];
  const secs = (t) => Number((t.match(/(\d+) s left/) || [])[1]);
  assert(secs(line2) < secs(line1), 'countdown decreases ' + JSON.stringify(evidence.lease_lines));
  await shot(prompt(), '03-lease-line');
  before = await send('alpha', 'udp', '10.79.0.3', 44001);
  assert(await delivered(before), 'same process UDP delivered');
  before = await send('alpha', 'tcp', '10.79.0.3', 44000);
  assert(await delivered(before), 'same process TCP delivered');
  assert(!(await list()).events.some((e) => e.state === 'awaiting-decision'), 'no new prompt');
  step(`For a while Allow: lease ${lease.id} (${lease.seconds}s), line "${line1}" -> "${line2}", same process TCP+UDP delivered without prompt, no rule`);

  // 3. Sibling instance (beta, same executable) is prompted inside the window.
  before = await send('beta', 'tcp', '10.79.0.2', 43000);
  w = await card(/10\.79\.0\.2:43000/);
  assert(!(await delivered(before, 1200)), 'sibling not delivered');
  const sib = await facts();
  assert.equal(sib.bounds.height, 460, 'next request reset to compact');
  await w.locator('#block').click();
  step('sibling instance prompted inside the window; new request compact 520x460');

  // 4. Expiry: after the lease the same process is prompted again.
  await wait(async () => !(await list()).leases.length, 25000, 'lease expired');
  before = await send('alpha', 'tcp', '10.79.0.2', 43000);
  w = await card(/10\.79\.0\.2:43000/);
  assert(!(await delivered(before, 1200)), 'not delivered after expiry');
  step('lease expired and vanished; same process prompted again');

  // 5. For a while + Deny: current and a later connection blocked, no prompt.
  await w.locator('#forAWhileToggle').check();
  await w.locator('#block').click();
  await wait(async () => (await list()).leases.some((l) => l.action === 'block'), 8000);
  assert(!(await delivered(before, 1500)), 'denied current');
  before = await send('alpha', 'udp', '10.79.0.3', 44001);
  assert(!(await delivered(before, 2500)), 'denied later UDP');
  assert(!(await list()).events.some((e) => e.state === 'awaiting-decision'), 'Deny lease: no prompt');
  step('For a while Deny: current and later connections not delivered, no prompt');
  await wait(async () => !(await list()).leases.length, 25000, 'deny lease expired');
  await drain();

  // 6. Ended request: Remember -> Deny, relaunch blocked; repeat click creates no duplicate.
  before = await send('other', 'tcp', '10.79.0.3', 44000);
  w = await card(/10\.79\.0\.3:44000/);
  await command({ op: 'exit', name: 'other' });
  await wait(async () => /has ended|no longer pending/i.test(await prompt().locator("body").innerText()), 40000, 'ended card');
  w = prompt();
  assert(await w.locator('#forAWhileToggle').isDisabled(), 'For a while unavailable when ended');
  assert(await w.locator('#allow').isVisible(), 'Allow stays visible');
  if (await w.locator('#forAWhileToggle').isChecked()) throw Error('For a while left checked');
  if (!(await w.locator('#rememberToggle').isChecked())) await w.locator('#rememberToggle').check();
  assert(!(await w.locator('#rememberPanel input[data-field="process"]').isChecked()), 'process not preselected');
  await wait(() => w.locator('#block').isEnabled(), 15000, 'deny enabled');
  await w.locator('#block').click();
  const result = await wait(async () => {
    const t = await prompt().locator('#requestResult').innerText();
    return /Rule saved/.test(t) ? t : undefined;
  }, 15000, 'result text');
  evidence.ended_result = result;
  assert.equal(result.trim(), 'Rule saved for future connections; this request has ended.');
  await prompt().locator('#block').click({ trial: false }).catch(() => {});
  await sleep(1500);
  const denyRules = (await list()).rules.filter((r) => r.action === 'block');
  assert.equal(denyRules.length, 1, 'exactly one rule after repeated click');
  await shot(prompt(), '04-ended-remember-deny');
  const relaunch = await command({ op: 'launch', name: 'other' });
  before = await send('other', 'tcp', '10.79.0.3', 44000);
  assert(!(await delivered(before, 2500)), 'relaunch blocked');
  assert(!(await list()).events.some((e) => e.state === 'awaiting-decision'), 'relaunch not prompted');
  step(`ended request Remember->Deny saved ${denyRules[0].id} once ("${result.trim()}"); relaunched PID ${relaunch.info.pid} blocked without prompt`);

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
