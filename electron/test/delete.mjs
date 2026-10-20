// Focused real isolated controller + sandboxed Wayland Electron. Proxy faults labelled below.
import { _electron } from 'playwright-core';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { call } = createRequire(import.meta.url)('../dist/test/backend.cjs');
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/del-'));
const api = path.join(run, 'api/control.sock'),
  proxyPath = path.join(run, 'p.sock');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn) {
  let last;
  for (let i = 0; i < 180; i++) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await sleep(100);
  }
  throw Error('Timeout ' + (last || fn));
}
function command(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(path.join(run, 'demo.sock'));
    s.on('error', reject);
    s.setTimeout(5000, () => s.destroy(Error('command timeout')));
    s.on('connect', () => s.write(JSON.stringify({ operation, ...fields })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
let app,
  lab,
  strip = false,
  lose = false,
  deletes = 0;
const proxy = net.createServer((client) =>
  client.once('data', (q) => {
    const req = JSON.parse(q);
    if (req.operation === 'rule-delete') deletes++;
    const upstream = net.createConnection(api);
    let data = '';
    upstream.on('connect', () => upstream.write(q));
    upstream.on('error', () => client.destroy());
    upstream.on('data', (b) => {
      data += b;
      if (!data.includes('\n')) return;
      upstream.destroy();
      if (lose && req.operation === 'rule-delete') {
        lose = false;
        client.destroy();
        return;
      }
      if (strip) {
        const r = JSON.parse(data);
        delete r.capabilities;
        data = JSON.stringify(r) + '\n';
      }
      client.end(data);
    });
    client.on('error', () => {});
    client.on('close', () => upstream.destroy());
  }),
);
const pref = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
try {
  const harness = fs
    .readFileSync(path.join(root, 'scripts/acceptance/host-lab.py'), 'utf8')
    .replace('ROOT=Path(__file__).resolve().parents[1]', `ROOT=Path(${JSON.stringify(root)})`)
    .replace("start('30s')", "start('120s')");
  fs.writeFileSync(path.join(run, 'harness.py'), harness);
  const log = fs.openSync(path.join(run, 'lab.log'), 'w');
  lab = spawn(
    'scripts/lab.sh',
    ['python3', path.join(run, 'harness.py'), run, '--desktop-workflow'],
    {
      cwd: root,
      detached: true,
      stdio: ['ignore', log, log],
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    },
  );
  fs.closeSync(log);
  await wait(() => fs.existsSync(path.join(run, 'ready')));
  const job = path.join(run, 'job');
  fs.mkdirSync(job);
  fs.writeFileSync(path.join(job, 'request.json'), '{"profile":"incoming"}');
  assert((await command('start', { job })).ok);
  await new Promise((r) => proxy.listen(proxyPath, r));
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'observer.sock'),
      '--control',
      proxyPath,
    ],
    cwd: root,
    env: {
      ...process.env,
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const pid = await app.evaluate(() => process.pid);
  assert(!fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('--no-sandbox'));
  const page = await app.firstWindow();
  const snap = () => page.evaluate(() => window.flowgate.snapshot());
  await wait(async () => (await snap()).control.connected);
  async function create(port) {
    await command('send', { port });
    await wait(async () =>
      (await snap()).control.events.some(
        (e) => e.state === 'awaiting-decision' && e.flow.local.endsWith(':' + port),
      ),
    );
    await page.click('#requestsTab');
    await page.locator('#requestRows tr').filter({ hasText: 'awaiting' }).last().click();
    await page.click('#createRule');
    await page.click('#previewRule');
    await wait(() => page.locator('#saveRule').isEnabled());
    await page.click('#saveRule');
    await wait(async () => (await snap()).control.rules.some((r) => r.filter.local_port === port));
    await page.click('#rulesTab');
    return (await snap()).control.rules.find((r) => r.filter.local_port === port);
  }
  const initial = await create(44001);
  await page.locator('#ruleRows tr').first().click();
  await page.click('#deleteRule');
  const shown = await page.locator('#confirmText').innerText();
  assert(shown.includes('version ' + initial.version));
  // Deterministic barrier: UI confirmation visible before external edit; await authoritative save before confirm.
  const before = await call(api, { operation: 'list' });
  const edited = await call(api, {
    operation: 'rule-save',
    generation: before.generation,
    id: initial.id,
    expected_version: initial.version,
    rule: { ...initial, disabled: true },
  });
  assert(!edited.error, edited.error);
  assert(edited.saved_rule.version > initial.version);
  await wait(async () => (await snap()).control.rules[0].version === edited.saved_rule.version);
  assert.equal(await page.locator('#confirmText').innerText(), shown);
  await page.click('#confirmYes');
  await wait(async () =>
    (await page.locator('#ruleFeedback').innerText()).includes('version_conflict'),
  );
  assert.equal(
    (await call(api, { operation: 'list' })).rules[0].version,
    edited.saved_rule.version,
  );
  console.log(
    'PASS deterministic external edit while confirmation open: stale delete conflicts; newer rule survives',
  );
  await page.click('#deleteRule');
  const generationShown = await page.locator('#confirmText').innerText();
  const oldGeneration = (await snap()).control.generation;
  assert((await command('stopbackend')).ok);
  assert((await command('start', { job })).ok);
  await wait(
    async () =>
      (await snap()).control.connected && (await snap()).control.generation !== oldGeneration,
  );
  assert.equal(await page.locator('#confirmText').innerText(), generationShown);
  await page.click('#confirmYes');
  await wait(async () =>
    (await page.locator('#ruleFeedback').innerText()).includes('generation_conflict'),
  );
  assert.equal((await call(api, { operation: 'list' })).rules.length, 1);
  console.log('PASS actual controller restart rejects displayed old generation without mutation');
  strip = true;
  await wait(() => page.locator('#deleteRule').isDisabled());
  assert.match(
    await page.locator('#deleteCompatibility').innerText(),
    /conditional-rule-delete-v1/,
  );
  const n = deletes;
  assert(
    await page.evaluate(async () => {
      const c = (await window.flowgate.snapshot()).control;
      try {
        await window.flowgate.ruleDelete({
          generation: c.generation,
          id: c.rules[0].id,
          version: c.rules[0].version,
        });
        return false;
      } catch {
        return true;
      }
    }),
  );
  assert.equal(deletes, n);
  console.log(
    'PASS synthetic capability stripping disables UI and rejects bridge deletion; no legacy fallback',
  );
  strip = false;
  await wait(() => page.locator('#deleteRule').isEnabled());
  await page.click('#deleteRule');
  await page.screenshot({ path: path.join(run, 'conditional-delete.png') });
  await page.click('#confirmYes');
  await wait(async () =>
    (await page.locator('#ruleFeedback').innerText()).includes(
      'matching conditional acknowledgement',
    ),
  );
  assert.equal((await call(api, { operation: 'list' })).rules.length, 0);
  console.log('PASS actual Electron conditional Delete acknowledged by real isolated backend');
  await create(44003);
  await page.locator('#ruleRows tr').first().click();
  await page.click('#deleteRule');
  lose = true;
  const prior = deletes;
  await page.click('#confirmYes');
  await wait(async () => (await page.locator('#ruleFeedback').innerText()).includes('unresolved'));
  await wait(async () => (await snap()).control.rules.length === 0);
  await sleep(1200);
  assert.equal(deletes, prior + 1);
  assert.equal((await call(api, { operation: 'list' })).rules.length, 0);
  assert(
    !(await page.locator('#ruleFeedback').innerText()).includes(
      'matching conditional acknowledgement',
    ),
  );
  console.log(
    'PASS real deletion with synthetic response loss: authoritative absence, unresolved client outcome, no replay',
  );
  assert((await snap()).observation.connected);
  console.log('PASS Activity remains connected. EVIDENCE ' + run);
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  proxy.close();
  if (lab) {
    await command('quit').catch(() => {});
    for (let i = 0; i < 50 && lab.exitCode === null; i++) await sleep(100);
    if (lab.exitCode === null) {
      try {
        process.kill(-lab.pid, 'SIGTERM');
      } catch {}
    }
  }
  if (old) fs.writeFileSync(pref, old);
  else fs.rmSync(pref, { force: true });
}
