// Decision Log against an externally owned ISOLATED daemon (own database). The fixture
// owner creates real decisions, performs fixture operations and cleans up. Every UI check
// is compared with the same daemon's decision-log API; host /run endpoints are refused.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const endpoint = process.env.FLOWGATE_LOG_UI_ENDPOINT;
// Fixture operations: a JSON line appended to this file per operation (owner-defined).
const opsFile = process.env.FLOWGATE_LOG_UI_OPS;
if (!endpoint?.startsWith(path.join(root, '.workspace') + '/'))
  throw Error('Isolated .workspace endpoint required; host endpoints refused');
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
async function op(name, extra = {}) {
  if (!opsFile) throw Error('FLOWGATE_LOG_UI_OPS required for fixture operation ' + name);
  fs.appendFileSync(opsFile, JSON.stringify({ operation: name, ...extra }) + '\n');
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
    assert.match(text, source === 'user' ? /User decision/ : /Rule at decision time/);
    if (r.decision.reason) assert(text.includes(r.decision.reason), 'recorded reason missing');
    if (r.decision.scope) assert.match(text, /Scope/);
    assert.doesNotMatch(text, /Delivered/);
    log(
      `${source} decision ${r.id}: source/reason${r.decision.scope ? '/scope ' + r.decision.scope : ''} shown`,
    );
  }
  await page.screenshot({ path: path.join(run, 'log-details.png') });

  // 3. Full paging without duplicates or gaps at page boundaries.
  const expected = await allIds();
  for (let i = 0; i < 20 && (await state()).hasOlder; i++) {
    await page.click('#logOlder');
    await page.waitForTimeout(150);
  }
  const ids = await shown();
  assert.equal(new Set(ids).size, ids.length, 'duplicate rows');
  assert.deepEqual(ids.slice(0, expected.length), expected.slice(0, ids.length));
  log(`paged ${ids.length}/${expected.length} records; no duplicates, boundaries contiguous`);

  // 4. Server-side filter equals the daemon's filtered result.
  for (const [select, value, key] of [
    ['#logDirection', 'incoming', 'direction'],
    ['#logAction', 'block', 'action'],
  ]) {
    await page.selectOption(select, value);
    const want = (await query({ limit: 100, [key]: value })).decision_log.records.map((r) => r.id);
    await wait(
      async () => JSON.stringify((await shown()).slice(0, want.length)) === JSON.stringify(want),
      `${key} filter`,
    );
    log(`${key}=${value}: ${want.length} records, equals daemon query`);
    await page.selectOption(select, '');
  }
  await wait(async () => (await shown())[0] === newest[0].id, 'unfiltered again');

  if (opsFile) {
    // 5. New decisions do not steal selection or move the inspected row.
    const inspect = newest[Math.min(5, newest.length - 1)];
    await page.click(`#logRows tr[data-id="${inspect.id}"]`);
    const y0 = await page.locator(`#logRows tr[data-id="${inspect.id}"]`).boundingBox();
    const top0 = (await query({ limit: 1 })).decision_log.records[0].sequence;
    await op('decide');
    await wait(
      async () => (await query({ limit: 1 })).decision_log.records[0].sequence !== top0,
      'new decision recorded',
    );
    await wait(async () => (await state()).records[0].sequence !== top0, 'new decision in UI');
    assert.equal(
      await page.locator('#logRows tr[aria-selected="true"]').getAttribute('data-id'),
      inspect.id,
    );
    log(
      `selection preserved across new records (row moved ${Math.round((await page.locator(`#logRows tr[data-id="${inspect.id}"]`).boundingBox()).y - y0.y)}px)`,
    );

    // 6. Historical rule snapshot after the rule changes and is deleted.
    const ruled = (await allIds({ source: 'rule' }))[0];
    if (ruled) {
      const rec = (await api({ operation: 'decision-log-get', decision_id: ruled }))
        .decision_record;
      await op('edit-rule', { rule_id: rec.decision.rule.id });
      await page.click(`#logRows tr[data-id="${ruled}"]`).catch(() => {});
      const edited = await wait(async () => {
        const t = await page.locator('#logDetails').innerText();
        return /rule has changed since/.test(t) && t;
      }, 'edited rule comparison');
      assert(
        edited.includes(`Version\n${rec.decision.rule.version}`) ||
          edited.includes(rec.decision.rule.version),
      );
      await page.screenshot({ path: path.join(run, 'rule-edited.png') });
      await op('delete-rule', { rule_id: rec.decision.rule.id });
      await page.click('#logRows tr:first-child');
      await page.click(`#logRows tr[data-id="${ruled}"]`);
      await wait(
        async () => /no longer exists/.test(await page.locator('#logDetails').innerText()),
        'deleted rule',
      );
      log('decision-time rule snapshot kept after edit and delete; current rule shown separately');
    }

    // 7. Daemon restart (same database): records persist, view continues.
    const before = await shown();
    await op('restart');
    await wait(
      async () =>
        (await state()).status === 'disconnected' ||
        (await state()).generation !== first.generation,
      'restart observed',
      600,
    );
    await wait(
      async () =>
        (await state()).status === 'ready' &&
        (await api({ operation: 'list' })).generation !== first.generation,
      'reconnected',
      600,
    );
    const after = await shown();
    assert(
      before.every((id) => after.includes(id)),
      'persisted records missing after restart',
    );
    log(`restart: ${before.length} previously shown records still present`);
  } else log('fixture operations unavailable: live/rule-change/restart checks skipped');

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
