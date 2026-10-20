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
const run = mkdtempSync(path.join(root, '.workspace/er-'));
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
    // Own a distinct process group so failed namespace startup can be cleaned up too.
    detached: name === 'lab',
    env: {
      ...process.env,
      PATH: path.join(run, 'bin') + ':' + process.env.PATH,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  p.ownedGroup = name === 'lab';
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

const snap = (p) => p.evaluate(() => window.flowgate.snapshot());
function command(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(path.join(run, 'demo.sock'));
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('harness timeout')));
    s.on('connect', () => s.write(JSON.stringify({ operation, ...fields })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
const received = (port) =>
  (readFileSync(path.join(run, `receiver-${port}.log`), 'utf8').match(/RECEIVED/g) || []).length;
let lab;
try {
  mkdirSync(path.join(run, 'bin'));
  writeFileSync(
    path.join(run, 'bin/konsole'),
    `#!/usr/bin/python3
import sys,socket,json,pathlib,time
run=pathlib.Path(${JSON.stringify(run)})
a=sys.argv;op=a[a.index('--action')+1];job=a[a.index('--job')+1]
mode=(run/'auth-mode').read_text() if (run/'auth-mode').exists() else ''
if op=='start' and mode in ['cancel','refuse']:op=mode
q={'operation':op,'job':job,'token':a[a.index('--token')+1] if '--token' in a else ''}
with socket.socket(socket.AF_UNIX) as s:
 s.connect(str(run/'demo.sock'));s.sendall(json.dumps(q).encode());r=json.loads(s.recv(65536))
if op=='status':
 pathlib.Path(job,'result.json').write_text(json.dumps({'version':1,'sequence':1,'phase':'status','message':json.dumps(r),'generation':''}))
`,
    { mode: 0o700 },
  );
  // Private copy only lengthens this test's evaluation; no product deadline changes.
  const harness = readFileSync(path.join(root, 'scripts/acceptance/host-lab.py'), 'utf8')
    .replace('ROOT=Path(__file__).resolve().parents[1]', `ROOT=Path(${JSON.stringify(root)})`)
    .replace("start('30s')", "start('120s')");
  writeFileSync(path.join(run, 'harness.py'), harness);
  lab = start(
    'scripts/lab.sh',
    ['python3', path.join(run, 'harness.py'), run, '--desktop-workflow'],
    'lab',
  );
  await wait(() => existsSync(path.join(run, 'ready')));
  let [gui, page] = await electron(
    path.join(run, 'observer.sock'),
    path.join(run, 'api/control.sock'),
  );
  await wait(async () => (await snap(page)).observation.connected);
  for (const mode of ['cancel', 'refuse']) {
    writeFileSync(path.join(run, 'auth-mode'), mode);
    await page.click('#evalStart');
    await page.click('#confirmYes');
    await wait(async () =>
      ['cancelled', 'failed'].includes(
        (await page.evaluate(() => window.flowgate.evaluationState())).phase,
      ),
    );
    assert((await snap(page)).observation.connected);
  }
  writeFileSync(path.join(run, 'auth-mode'), '');
  await page.selectOption('#evalProfile', 'both');
  await page.click('#evalStart');
  await page.click('#confirmYes');
  await wait(async () => (await snap(page)).control.enforcement?.state === 'active');
  assert.equal((await snap(page)).control.enforcement.profile, 'both');
  console.log(
    'PASS simulated authentication cancellation/refusal; selected both profile reaches real backend',
  );
  await page.screenshot({ path: path.join(run, 'evaluation.png') });
  await command('send', { port: 44001 });
  await wait(async () =>
    (await snap(page)).control.events.some((e) => e.state === 'awaiting-decision'),
  );
  await page.click('#requestsTab');
  await page.locator('#requestRows tr').first().click();
  await page.click('#createRule');
  await page.screenshot({ path: path.join(run, 'rule-editor.png') });
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#saveRule');
  await wait(() => received(44001) === 1);
  await wait(async () => (await snap(page)).control.rules.length === 1);
  console.log('PASS create Allow from pending in Electron delivers retained UDP');
  await page.click('#rulesTab');
  await page.locator('#ruleRows tr').first().click();
  await page.click('#editRule');
  const initial = (await snap(page)).control.rules[0];
  const [readOnlyGui, readOnlyPage] = await electron(
    path.join(run, 'observer.sock'),
    path.join(run, 'api/control.sock.monitor'),
  );
  await wait(async () => (await snap(readOnlyPage)).control.connected);
  assert((await snap(readOnlyPage)).control.readOnly);
  assert(
    await readOnlyPage.evaluate(async (id) => {
      try {
        await window.flowgate.ruleDraft({ id });
        return false;
      } catch {
        return true;
      }
    }, initial.id),
  );
  readOnlyGui.kill('SIGTERM');
  console.log('PASS real read-only API cannot create an editable draft');

  await page.selectOption('#editAction', 'block');
  await page.fill('#editAddress', 'invalid-address');
  await page.click('#previewRule');
  await wait(async () => (await page.textContent('#editorFeedback')).includes('address'));
  assert.equal(await page.inputValue('#editAddress'), 'invalid-address');
  assert(await page.locator('#saveRule').isDisabled());
  await page.fill('#editAddress', initial.filter.remote_address);
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#saveRule');
  await wait(async () => (await snap(page)).control.rules[0].action === 'block');
  await command('send', { port: 44001 });
  await sleep(400);
  assert.equal(received(44001), 1);
  console.log('PASS edit Block prevents new UDP delivery; failed preview preserves input');
  for (const disabled of [true, false]) {
    await page.click('#toggleRule');
    await page.click('#previewRule');
    await wait(() => page.locator('#saveRule').isEnabled());
    await page.click('#saveRule');
    await wait(async () => (await snap(page)).control.rules[0].disabled === disabled);
    assert.equal((await snap(page)).control.rules[0].expires, initial.expires);
  }
  console.log('PASS disable/re-enable preserve absolute expiry');
  await page.click('#editRule');
  await page.selectOption('#editAction', 'allow');
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await call(path.join(run, 'api/control.sock'), {
    operation: 'rule',
    id: initial.id,
    action: 'disable',
  });
  await page.click('#saveRule');
  await wait(async () => (await page.textContent('#editorFeedback')).includes('version'));
  assert.equal(await page.inputValue('#editAction'), 'allow');
  await page.click('#reloadRule');
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#closeEditor');
  console.log(
    'PASS stale version rejected; fields retained; explicit reload permits fresh preview',
  );
  await page.screenshot({ path: path.join(run, 'rules.png') });
  await page.setViewportSize({ width: 860, height: 600 });
  await page.click('#editRule');
  await page.screenshot({ path: path.join(run, 'editor-narrow.png') });
  await page.click('#closeEditor');
  await page.click('#deleteRule');
  await page.click('#confirmYes');
  await wait(async () => (await snap(page)).control.rules.length === 0);
  console.log('PASS delete authoritative rule');
  await page.click('#evalStop');
  await wait(
    async () => (await page.evaluate(() => window.flowgate.evaluationState())).phase === 'stopped',
  );
  assert((await snap(page)).observation.connected);
  assert.equal((await command('status')).table_present, false);
  console.log('PASS Stop cleanup acknowledged while Activity continues');
  const previousGeneration = (await snap(page)).control.generation;
  await wait(() => page.locator('#evalStart').isEnabled());
  await page.click('#evalStart');
  await page.click('#confirmYes');
  await wait(async () => (await snap(page)).control.enforcement?.state === 'active');
  await wait(
    async () =>
      (await snap(page)).control.generation !== previousGeneration &&
      (await page.evaluate(() => window.flowgate.evaluationState())).phase === 'active',
  );
  const deadline = (await snap(page)).control.enforcement.stops_at;
  gui.kill('SIGTERM');
  await sleep(600);
  assert.equal(
    (await call(path.join(run, 'api/control.sock'), { operation: 'list' })).enforcement.stops_at,
    deadline,
  );
  [gui, page] = await electron(path.join(run, 'observer.sock'), path.join(run, 'api/control.sock'));
  await wait(async () => (await snap(page)).control.connected);
  console.log('PASS closing Electron preserves independent controller and original deadline');
  await command('kill');
  await wait(async () => !(await snap(page)).control.connected);
  await wait(async () => (await page.textContent('#evaluationStatus')).includes('unknown'));
  assert((await snap(page)).observation.connected);
  assert(
    await page.evaluate(async () => {
      try {
        await window.flowgate.ruleDraft({ id: 'gone' });
        return false;
      } catch {
        return true;
      }
    }),
  );
  console.log(
    'PASS controller loss is unknown; Activity continues; disconnected mutation rejected',
  );
  await page.click('#evalRecover');
  await page.click('#confirmYes');
  await wait(
    async () => (await page.evaluate(() => window.flowgate.evaluationState())).phase === 'stopped',
  );
  // Explicit synthetic observer fixture: UI availability/partial/disconnect only, not UDP evidence.
  let udpState = 'active';
  const fixturePath = path.join(run, 'synthetic.sock');
  const fixture = net.createServer((socket) =>
    socket.once('data', () =>
      socket.end(
        JSON.stringify({
          version: 1,
          generation: 'synthetic-ui',
          read_only: true,
          mode: 'host-monitor',
          server_time: new Date().toISOString(),
          activity: {
            sequence: Date.now(),
            collected: new Date().toISOString(),
            complete: true,
            issues: ['SYNTHETIC UI FIXTURE — no kernel collection'],
            rows: [],
            processes: {},
            udp: {
              state: udpState,
              reason: 'SYNTHETIC UI FIXTURE: socket-level API bytes, not per-peer',
              generation: 'fixture',
              missed_operations: 1,
              uid: 1000,
              collected: new Date().toISOString(),
            },
          },
        }) + '\n',
      ),
    ),
  );
  await new Promise((r) => fixture.listen(fixturePath, r));
  const [fixtureGui, fixturePage] = await electron(fixturePath);
  await wait(async () =>
    (await fixturePage.textContent('#extendedStatus')).includes('partial coverage'),
  );
  assert(await fixturePage.locator('#extendedEnable').isDisabled());
  await fixturePage.screenshot({ path: path.join(run, 'synthetic-udp-partial.png') });
  udpState = 'disconnected';
  await wait(async () =>
    (await fixturePage.textContent('#extendedStatus')).includes('disconnected'),
  );
  assert(await fixturePage.locator('#extendedEnable').isEnabled());
  fixtureGui.kill('SIGTERM');
  await new Promise((r) => fixture.close(r));
  console.log(
    'PASS synthetic UDP availability, partial-coverage and disconnect UI; no privileged collector launched',
  );
  console.log('EVIDENCE', run);
  assert.deepEqual(logs, []);
} finally {
  if (existsSync(path.join(run, 'demo.sock')))
    try {
      await command('quit');
      await sleep(600);
    } catch {}
  for (const b of browsers)
    try {
      await b.close();
    } catch {}
  for (const c of children.reverse()) {
    if (c.exitCode === null && c.signalCode === null) {
      c.kill('SIGTERM');
      await sleep(500);
      if (c.exitCode === null && c.signalCode === null) {
        if (c.ownedGroup)
          try {
            process.kill(-c.pid, 'SIGKILL');
          } catch {}
        else c.kill('SIGKILL');
      }
    }
    c.stdin?.destroy();
    c.stdout?.destroy();
    c.stderr?.destroy();
  }
  console.log('Artifacts', run);
}
