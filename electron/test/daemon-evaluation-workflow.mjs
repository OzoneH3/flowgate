// REAL isolated daemon/receiver journey. Fixture owner sets up/cleans namespaces.
// This runner exclusively drives lifecycle and one command at a time until DONE.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  fixture = process.env.FLOWGATE_EVALUATION_UI_RUN;
if (
  !fixture ||
  !path.isAbsolute(fixture) ||
  !fixture.includes('/.workspace/') ||
  fixture.startsWith('/run/')
)
  throw Error('Disposable .workspace fixture required; host endpoints refused');
const ready = JSON.parse(fs.readFileSync(path.join(fixture, 'ready.json'), 'utf8')),
  endpoint = ready.socket;
if (!endpoint.startsWith(fixture + '/')) throw Error('Fixture socket outside run directory');
const run = fs.mkdtempSync(path.join(root, '.workspace/evaluation-ui-'));
const log = (s) => {
  console.log(s);
  fs.appendFileSync(path.join(run, 'result.log'), s + '\n');
};
const api = (q = {}, readonly = false) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(endpoint + (readonly ? '.monitor' : ''));
    let b = '';
    s.setTimeout(5000, () => s.destroy(Error('API timeout')));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ version: 1, operation: 'list', ...q }) + '\n'));
    s.on('data', (d) => {
      b += d;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
  });
const wait = async (fn, label) => {
  for (let i = 0; i < 200; i++) {
    const r = await fn();
    if (r) return r;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout ' + label);
};
async function command(cmd) {
  const f = path.join(fixture, 'verification.log'),
    offset = fs.statSync(f).size;
  fs.writeFileSync(path.join(fixture, 'command'), cmd + '\n');
  await wait(
    () =>
      fs
        .readFileSync(f, 'utf8')
        .slice(offset)
        .includes('DONE ' + cmd.split(' ')[0]),
    cmd,
  );
}
let app, page;
const pref = path.join(root, 'build/desktop-session/electron-preferences.json'),
  saved = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
try {
  const before = await api();
  assert(before.capabilities.includes('daemon-evaluation-v1'));
  assert.equal(before.evaluation.state, 'stopped');
  const launchOptions = {
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      endpoint + '.monitor',
      '--control',
      endpoint,
    ],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  };
  app = await _electron.launch(launchOptions);
  app.process().stderr?.on('data', (b) => fs.appendFileSync(path.join(run, 'electron.log'), b));
  page = await app.firstWindow();
  page.on('pageerror', (e) => log('renderer error ' + e.message));
  await page.setViewportSize({ width: 1280, height: 760 });
  await page
    .locator('.brand')
    .evaluate((e) => (e.textContent = 'FlowGate · ISOLATED real evaluation'));
  await page.click('#controlMenu > summary');
  await wait(
    () => page.locator('#evalStatus').evaluate((e) => e.textContent === 'Check readiness'),
    'daemon controls',
  );
  const previousCheck = (await api()).evaluation.readiness.checked_at;
  await page.click('#evalStatus');
  await wait(async () => {
    const r = await api();
    return (
      r.evaluation.readiness.state === 'ready' &&
      r.evaluation.readiness.checked_at !== previousCheck
    );
  }, 'fresh readiness completion');
  await wait(
    async () => (await page.evaluate(() => window.flowgate.evaluationState())).canStart,
    'fresh readiness projected',
  );
  await wait(() => page.locator('#evalStart').isEnabled(), 'real readiness');
  await page.click('#evalStart');
  await page.locator('#confirmation').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#confirmText').innerText(), (await api()).evaluation.review);
  await page.screenshot({ path: path.join(run, 'review-real.png') });
  await page.click('#confirmYes');
  const active = await wait(async () => {
    const r = await api();
    return r.evaluation.state === 'active' && r;
  }, 'active');
  const deadline = active.evaluation.stops_at;
  assert.equal(active.evaluation.duration_seconds, 300);
  assert.equal(active.mode, 'daemon-monitor');
  assert.equal(active.permissions.can_decide, true);
  log('PASS actual readiness -> reviewed Start -> active incoming, daemon generation unchanged');
  await wait(() => page.locator('#evalStop').isEnabled(), 'Stop available');
  await wait(
    async () => (await page.evaluate(() => window.flowgate.evaluationState())).phase === 'active',
    'active UI projection',
  );
  await wait(
    () =>
      page
        .locator('#controlMenu > summary')
        .evaluate((e) => /FW: [0-5]:/.test(e.textContent)),
    'visible active countdown',
  );
  await page.screenshot({ path: path.join(run, 'active-normal.png') });
  await page.setViewportSize({ width: 860, height: 600 });
  await page.screenshot({ path: path.join(run, 'active-narrow.png') });
  await page.setViewportSize({ width: 1280, height: 760 });
  // Clicking a tab closes the menu, without changing evaluation.
  await page.click('#requestsTab');
  for (const [port, action] of [
    [44001, 'allow'],
    [44003, 'block'],
  ]) {
    await command('send ' + port);
    const event = await wait(async () => {
      const r = await api();
      return r.events.find(
        (e) => e.state === 'awaiting-decision' && e.flow.local.endsWith(':' + port),
      );
    }, 'incoming prompt ' + port);
    await wait(() => page.locator(`#requestRows tr[data-id="${event.id}"]`).count(), 'prompt row');
    await page.click(`#requestRows tr[data-id="${event.id}"]`);
    await wait(() => page.locator('#' + action).isEnabled(), 'action enabled');
    await page.selectOption('#scope', 'once');
    await page.click('#' + action);
    await wait(async () => {
      const r = await api();
      return (
        r.events.find((e) => e.id === event.id)?.state ===
        (action === 'allow' ? 'allowed' : 'blocked')
      );
    }, 'decision acknowledged');
    await command('counts');
    const counts = JSON.parse(fs.readFileSync(path.join(fixture, 'counts.json'), 'utf8'));
    assert.equal(counts[String(port)], action === 'allow' ? 1 : 0);
    log(
      `PASS real incoming ${action}: receiver count ${counts[String(port)]}, retained UDP ${port}`,
    );
  }
  await page.click('#decisionLogTab');
  await wait(async () => {
    const r = await api({ operation: 'decision-log', decision_query: { limit: 100 } });
    return (
      r.decision_log?.records.filter((x) => x.kind === 'final' && x.decision?.source === 'user')
        .length >= 2
    );
  }, 'decision log commit');
  await wait(
    () =>
      page
        .locator('#logRows tr')
        .count()
        .then((n) => n >= 4),
    'Decision Log rendered',
  );
  await page.screenshot({ path: path.join(run, 'decisions-real.png') });
  log('PASS Decision Log contains real user Allow/Block outcomes');
  const ro = await api(
    {
      operation: 'evaluation-start',
      generation: before.generation,
      evaluation_id: active.evaluation.id,
      request_id: 'f'.repeat(32),
      profile: 'incoming',
    },
    true,
  );
  assert.equal(ro.error_code, 'forbidden');
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const independent = await api();
  assert.equal(independent.evaluation.state, 'active');
  assert.equal(independent.evaluation.stops_at, deadline);
  assert.equal(independent.generation, before.generation);
  log('PASS active daemon evaluation survives GUI process exit with original deadline');
  app = await _electron.launch(launchOptions);
  page = await app.firstWindow();
  await wait(
    async () => (await page.evaluate(() => window.flowgate.evaluationState())).phase === 'active',
    'active after GUI reconnect',
  );
  await page.click('#controlMenu > summary');
  await page.click('#evalStop');
  await wait(async () => {
    const r = await api();
    return r.evaluation.state === 'stopped' && r.evaluation.cleanup === 'confirmed';
  }, 'cleanup confirmed');
  const after = await api();
  assert.equal(after.generation, before.generation);
  assert.deepEqual(after.rules, before.rules);
  assert.equal(after.evaluation.stops_at, deadline);
  await page.click('#activityTab');
  await wait(
    () => page.evaluate(() => window.flowgate.snapshot()).then((s) => s.observation.connected),
    'Activity after Stop',
  );
  log(
    'PASS Stop -> monitoring/cleanup confirmed; Activity, generation, rules and original deadline preserved; read-only Start forbidden',
  );
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const survived = await api();
  assert.equal(survived.generation, before.generation);
  assert.equal(survived.evaluation.state, 'stopped');
  log('PASS GUI exit leaves independent daemon alive; DONE UI fixture driver ' + run);
} catch (error) {
  if (page) await page.screenshot({ path: path.join(run, 'failure.png') }).catch(() => {});
  log('FAILED ' + error.stack);
  throw error;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (saved) fs.writeFileSync(pref, saved);
  else fs.rmSync(pref, { force: true });
}
