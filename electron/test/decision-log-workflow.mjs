// Decision Log against an externally owned ISOLATED daemon (own database). The fixture
// owner creates real decisions, performs fixture operations and cleans up. Every UI check
// is compared with the same daemon's decision-log API; host /run endpoints are refused.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
// Fixture run directory from scripts/acceptance/decision-log-isolated.py --hold (fixture owns it).
const fixture = process.env.FLOWGATE_LOG_UI_RUN;
// Project or worktree .workspace only; never /run host endpoints.
if (
  !fixture ||
  !path.isAbsolute(fixture) ||
  !fixture.includes('/.workspace/') ||
  fixture.startsWith('/run/')
)
  throw Error('Isolated .workspace fixture run directory required; host endpoints refused');
const endpoint = JSON.parse(fs.readFileSync(path.join(fixture, 'ready.json'), 'utf8')).socket;
if (!endpoint.startsWith(fixture + '/')) throw Error('Fixture socket outside its run directory');
const run = fs.mkdtempSync(path.join(root, '.workspace/decision-log-ui-'));
const log = (s) => (console.log(s), fs.appendFileSync(path.join(run, 'result.log'), s + '\n'));
const api = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(endpoint);
    let b = '';
    s.setTimeout(5000, () => s.destroy(Error('timeout')));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (d) => {
      b += d;
      if (b.includes('\n')) (s.destroy(), resolve(JSON.parse(b)));
    });
  });
const query = (decision_query) => api({ operation: 'decision-log', decision_query });
async function allIds(filter = {}) {
  const ids = [];
  let before;
  for (let i = 0; i < 100; i++) {
    const r = await query({ limit: 100, ...filter, ...(before ? { before } : {}) });
    assert(!r.error, r.error);
    ids.push(...r.decision_log.records.map((x) => x.id));
    if (!r.decision_log.has_more) return ids;
    before = r.decision_log.next_before;
  }
  throw Error('paging did not terminate');
}
// One plain command at a time via <run>/command; completion is 'DONE <cmd>' or 'FAILED'.
async function op(cmd) {
  const logFile = path.join(fixture, 'verification.log');
  const offset = fs.statSync(logFile).size;
  fs.writeFileSync(path.join(fixture, 'command'), cmd + '\n');
  const word = cmd.split(' ')[0];
  for (let i = 0; i < 600; i++) {
    const tail = fs.readFileSync(logFile, 'utf8').slice(offset);
    if (tail.includes('FAILED ' + cmd) || tail.includes('UNKNOWN ' + cmd))
      throw Error('Fixture command failed: ' + tail.trim());
    if (tail.includes('DONE ' + word)) return tail.trim();
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Fixture command timed out: ' + cmd);
}
const wait = async (fn, what, tries = 300) => {
  for (let i = 0; i < tries; i++) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout: ' + what);
};
let app;
try {
  const first = await api({ operation: 'list' });
  assert(first.capabilities.includes('decision-log-v1'), 'decision-log-v1 not advertised');
  app = await _electron.launch({
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
  });
  app.process().stderr?.on('data', (b) => fs.appendFileSync(path.join(run, 'electron.log'), b));
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 1280, height: 800 });
  await page
    .locator('.brand')
    .evaluate((e) => (e.textContent = 'FlowGate · ISOLATED FIXTURE DECISIONS'));
  await page.click('#decisionLogTab');
  const state = () => page.evaluate(() => window.flowgate.decisionLog());
  const shown = () =>
    page.locator('#logRows tr').evaluateAll((rows) => rows.map((r) => r.dataset.id));

  // 1. Newest page equals the daemon's newest page.
  const newest = (await query({ limit: 100 })).decision_log.records;
  assert(newest.length > 0, 'fixture has no recorded decisions');
  await wait(async () => (await shown())[0] === newest[0].id, 'newest record shown');
  assert.deepEqual(
    (await shown()).slice(0, newest.length),
    newest.map((r) => r.id),
  );
  log(`newest page matches daemon (${newest.length} records)`);

  // 2. Recorded user and rule decisions with their recorded reasons.
  const pick = (source) => newest.find((r) => r.kind === 'final' && r.decision?.source === source);
  for (const source of ['user', 'rule']) {
    const r = pick(source);
    if (!r) {
      log(`no ${source} decision on newest page (fixture coverage)`);
      continue;
    }
    await page.click(`#logRows tr[data-id="${r.id}"]`);
    const text = await wait(async () => {
      const t = await page.locator('#logDetails').innerText();
      return t.includes(r.sequence) && t;
    }, 'details for ' + r.id);
    assert.match(text, source === 'user' ? /User decision/i : /Rule at decision time/i);
    if (r.decision.reason) assert(text.includes(r.decision.reason), 'recorded reason missing');
    if (r.decision.scope) assert.match(text, /Scope/);
    assert.doesNotMatch(text, /Delivered/i);
    assert.match(text, /Not observed by FlowGate/);
    assert.doesNotMatch(text, /no longer exists/, 'deletion claimed without rule inventory');
    log(
      `${source} decision ${r.id}: source/reason${r.decision.scope ? '/scope ' + r.decision.scope : ''} shown`,
    );
  }
  await page.screenshot({ path: path.join(run, 'log-details.png') });

  // 3. Live arrivals do not steal the selection.
  const inspect = newest[Math.min(3, newest.length - 1)];
  await page.click(`#logRows tr[data-id="${inspect.id}"]`);
  const top0 = (await query({ limit: 1 })).decision_log.records[0].sequence;
  log('fixture: ' + (await op('decide-allow')));
  await wait(async () => (await state()).records[0].sequence !== top0, 'new decision in UI');
  assert.equal(
    await page.locator('#logRows tr[aria-selected="true"]').getAttribute('data-id'),
    inspect.id,
  );
  const arrived = (await state()).records.filter((r) => BigInt(r.sequence) > BigInt(top0));
  log(
    `live: ${arrived.length} new records (${arrived.map((r) => r.kind + '/' + (r.decision?.source || '')).join(', ')}); selection kept on ${inspect.id}`,
  );

  // 4. More than one page of real rule decisions, then full paging.
  log('fixture: ' + (await op('rule-traffic 130')));
  const settled = await wait(async () => {
    const a = await allIds();
    await new Promise((r) => setTimeout(r, 1500));
    const b = await allIds();
    return a.length === b.length && b;
  }, 'records committed (nominal batching interval)');
  await wait(async () => (await shown())[0] === settled[0], 'live view caught up');
  for (let i = 0; i < 20 && (await state()).hasOlder; i++) {
    await page.click('#logOlder');
    await wait(async () => !(await state()).busy, 'older page');
  }
  const ids = await shown();
  assert.equal(new Set(ids).size, ids.length, 'duplicate rows');
  assert.deepEqual(ids, settled, 'UI rows differ from daemon paging');
  assert(ids.length > 100, 'fixture produced a single page only');
  log(`paging: ${ids.length} records equal the daemon's full newest-first paging; no duplicates`);

  // 5. Server-side filters equal the daemon's filtered results.
  for (const [select, value, key] of [
    ['#logDirection', 'incoming', 'direction'],
    ['#logAction', 'block', 'action'],
    ['#logSource', 'user', 'source'],
  ]) {
    await page.selectOption(select, value);
    const want = (await query({ limit: 100, [key]: value })).decision_log.records.map((r) => r.id);
    await wait(
      async () => JSON.stringify((await shown()).slice(0, want.length)) === JSON.stringify(want),
      `${key} filter`,
    );
    log(`filter ${key}=${value}: ${want.length} records, equals daemon query`);
    await page.selectOption(select, '');
  }
  // Capacity buckets can commit after the earlier paging snapshot. Compare
  // with current authoritative state, not a frozen pre-filter newest ID.
  await wait(async () => {
    const latest = (await query({ limit: 1 })).decision_log.records[0];
    return latest && (await shown())[0] === latest.id;
  }, 'unfiltered again');

  // 6. Restart with the same database: history persists and the view continues.
  const before = await shown(),
    gen0 = (await api({ operation: 'list' })).generation;
  log('fixture: ' + (await op('restart')));
  await wait(
    async () =>
      (await state()).status === 'ready' &&
      (await state()).generation &&
      (await state()).generation !== gen0,
    'reconnected to new generation',
    600,
  );
  log('fixture: ' + (await op('decide-block')));
  await wait(async () => {
    const v = await state();
    return v.records[0]?.generation === v.generation;
  }, 'post-restart record');
  const after = await shown();
  assert(
    before.every((id) => after.includes(id)),
    'persisted records missing after restart',
  );
  assert.equal(new Set(after).size, after.length, 'duplicates after restart');
  log(
    `restart: generation ${(await state()).generation}; all ${before.length} earlier records still shown, new records appended`,
  );
  const blocked = (await state()).records.find(
    (r) => r.kind === 'final' && r.decision?.action === 'block' && r.decision.source === 'user',
  );
  if (blocked) {
    await page.click(`#logRows tr[data-id="${blocked.id}"]`);
    await wait(
      async () => (await page.locator('#logDetails').innerText()).includes(blocked.sequence),
      'blocked details',
    );
  }
  await page.screenshot({ path: path.join(run, 'log-after-restart.png') });

  await page.setViewportSize({ width: 860, height: 600 });
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(run, 'log-narrow.png') });
  log('PASS isolated decision log ' + run);
} catch (e) {
  console.error('Original failure', e);
  if (app?.windows().length)
    await app
      .firstWindow()
      .then((p) => p.screenshot({ path: path.join(run, 'failure.png') }))
      .catch(() => {});
  throw e;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
}
