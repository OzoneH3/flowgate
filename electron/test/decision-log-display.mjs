// SYNTHETIC decision-log presentation states (draft decision-log-v1 replies). No daemon,
// no firewall decisions. Covers states a real fixture cannot cheaply produce: missing
// capability, permission denial, degraded health with dropped records and a gap row.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { _electron } from 'playwright-core';
const root = path.resolve(import.meta.dirname, '../..'),
  dir = fs.mkdtempSync(path.join(root, '.workspace/synlog-'));
let variant = 'unsupported';
let navigation = [];
let missingId = '';
let outcomeCapability = false;
let outcomeError = '';
const outcomeRequests = [];
let evidence = [];
let heldRecovery;
let catchUpPages = 0;
let raceArmed = false;
const prefPath = path.join(root, 'build/desktop-session/electron-preferences.json');
const preferences = fs.existsSync(prefPath) ? fs.readFileSync(prefPath) : undefined;
const base = (readonly) => ({
  version: 1,
  generation: 'synthetic-daemon',
  read_only: readonly,
  mode: readonly ? 'host-monitor' : 'daemon-monitor',
  backend_mode: 'daemon-monitor',
  server_time: new Date().toISOString(),
  capabilities: [
    'explicit-administrator-v1',
    ...(variant === 'unsupported' ? [] : ['decision-log-v1']),
    ...(outcomeCapability ? ['decision-log-outcome-v1'] : []),
  ],
  permissions: {
    role: variant === 'evidence-self' ? 'user' : 'administrator',
    policy_scope: variant === 'evidence-self' ? 'self' : 'machine',
    observation_scope: variant === 'evidence-self' ? 'self' : 'machine',
    can_manage_rules: !readonly,
    can_decide: false,
  },
  enforcement: { state: 'stopped', profile: '', detail: 'Synthetic fixture' },
  // Rule-managing primary returns the current inventory: syn-rule-a is now version 4.
  rules: readonly
    ? []
    : [
        {
          id: 'syn-rule-a',
          version: 4,
          created: '2026-01-01T00:00:00Z',
          expires: '0001-01-01T00:00:00Z',
          schema: 2,
          executable: '/synthetic/app',
          filter: { application: 'synthetic', direction: 'outgoing', protocol: 'tcp' },
          priority: 0,
          action: 'block',
          disabled: false,
        },
      ],
  activity: {
    sequence: 1,
    collected: new Date().toISOString(),
    complete: true,
    rows: [],
    processes: {},
  },
});
const record = (seq, action, source, rule = null) => ({
  id: 'syn-' + seq,
  sequence: String(seq),
  time: new Date(Date.now() - (40 - seq) * 60e3).toISOString(),
  generation: 'synthetic-daemon',
  mode: 'isolated-lab',
  kind: 'final',
  request_id: 'req-' + seq,
  flow: {
    direction: 'outgoing',
    protocol: 'tcp',
    family: 'ipv4',
    local: '10.0.0.2:40000',
    remote: '192.0.2.10:443',
    interface_index: 2,
  },
  application: {
    key: 'synthetic',
    name: 'SYNTHETIC app',
    kind: 'executable',
    executable: '/synthetic/app',
    revision: 'r1',
  },
  principal_uid: 1000,
  attribution: { status: 'attributed', reason: '' },
  decision: {
    action,
    source,
    scope: source === 'user' ? 'once' : '',
    reason: 'SYNTHETIC record',
    rule,
    matching_rules: rule ? [rule.id] : [],
    decided_by_uid: source === 'user' ? 1000 : null,
  },
  verdict: { state: action === 'allow' ? 'accept_submitted' : 'drop_submitted', detail: '' },
  delivery: 'not_observed',
});
const page = () => ({
  records:
    variant === 'empty'
      ? []
      : [
          record(12, 'block', 'user'),
          {
            id: 'gap-11',
            sequence: '11',
            time: new Date().toISOString(),
            kind: 'gap',
            gap: { dropped: 4, reason: 'SYNTHETIC buffer overflow' },
          },
          record(10, 'allow', 'user'),
          { ...record(7, 'pending', 'default_ask'), kind: 'pending' },
          record(9, 'allow', 'rule', {
            id: 'syn-rule-a',
            version: '2',
            action: 'allow',
            priority: 0,
            expires: '0001-01-01T00:00:00Z',
            disabled: false,
            filter: { application: 'synthetic' },
          }),
          record(8, 'block', 'rule', {
            id: 'syn-rule-gone',
            version: '1',
            action: 'block',
            priority: 0,
            expires: '0001-01-01T00:00:00Z',
            disabled: false,
            filter: { application: 'synthetic' },
          }),
        ],
  has_more: false,
  next_before: '',
  next_after: '',
  order: 'newest_first',
  scope: 'machine',
  limitations: [],
  health: {
    log_id: 'synthetic-log',
    state: variant === 'empty' ? 'ok' : 'degraded',
    recording: true,
    buffered: 0,
    dropped: variant === 'empty' ? 0 : 4,
    write_failures: 0,
    lost_in_failures: 0,
    last_error: variant === 'empty' ? '' : 'SYNTHETIC queue overflow',
    durability_window_ms: 1000,
    retention: { max_records: 20000, max_age_days: 30, removed: 0, removed_through: '0' },
    oldest: '',
    newest: '',
  },
});
// Explicitly synthetic server-side filters and cursor pages for navigation checks.
function fixturePage(q = {}) {
  if (variant === 'evidence' || variant === 'evidence-self') {
    const self = variant === 'evidence-self';
    return {
      ...page(),
      scope: self ? 'self' : 'machine',
      records: q.after ? [] : evidence.map((r) =>
        self && r.kind === 'gap' ? { ...r, gap: { reason: r.gap.reason } } : r),
      health: { state: 'ok', recording: true, counts_withheld: self },
    };
  }
  if (variant === 'filter-race') {
    const incoming = (sequence) => {
      const r = record(sequence, 'allow', 'user');
      return { ...r, flow: { ...r.flow, direction: 'incoming' } };
    };
    if (q.direction === 'outgoing')
      return { ...page(), records: q.after ? [] : [record(4001, 'allow', 'user')] };
    if (!q.after) return { ...page(), records: [incoming(4000)] };
    const has_more = raceArmed && ++catchUpPages <= 5;
    return { ...page(), records: has_more ? [incoming(4010 + catchUpPages)] : [], has_more };
  }
  if (variant !== 'navigation') return page();
  let rows = navigation.filter(
    (r) =>
      (!q.application || r.application?.key === q.application) &&
      (!q.direction || r.flow.direction === q.direction) &&
      (!q.action || r.decision.action === q.action),
  );
  rows = q.after
    ? rows
        .filter((r) => BigInt(r.sequence) > BigInt(q.after))
        .sort((a, b) => Number(a.sequence) - Number(b.sequence))
    : rows
        .filter((r) => !q.before || BigInt(r.sequence) < BigInt(q.before))
        .sort((a, b) => Number(b.sequence) - Number(a.sequence));
  const loaded = rows.slice(0, q.limit ?? 100);
  return {
    ...page(),
    records: loaded,
    has_more: rows.length > loaded.length,
    next_before: !q.after && rows.length > loaded.length ? loaded.at(-1).sequence : '',
    health: {
      ...page().health,
      state: 'ok',
      dropped: 0,
      last_error: '',
      newest: navigation.at(-1)?.sequence || '',
    },
  };
}
const servers = [];
let app;
try {
  for (const readonly of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', (b) => {
        const q = JSON.parse(b);
        let r = base(readonly);
        if (q.operation === 'decision-log' && variant === 'filter-race' && catchUpPages === 5 &&
            !q.decision_query.after && !q.decision_query.direction && !heldRecovery) {
          heldRecovery = s;
          return;
        }
        if (q.operation === 'decision-log')
          r =
            variant === 'forbidden'
              ? { ...r, error: 'SYNTHETIC denial', error_code: 'forbidden' }
              : { ...r, decision_log: fixturePage(q.decision_query) };
        if (q.operation === 'decision-log-get')
          r =
            q.decision_id === missingId
              ? { ...r, error_code: 'not_found', error: 'Unavailable' }
              : {
                  ...r,
                  decision_record: (variant === 'navigation' ? navigation : fixturePage().records).find(
                    (x) => x.id === q.decision_id,
                  ),
                };
        if (q.operation === 'decision-log-outcome') {
          outcomeRequests.push(q.decision_id);
          const origin = navigation.find((x) => x.kind === 'pending' && x.id === q.decision_id && x.id !== missingId);
          const finals = origin ? navigation.filter((x) => x.kind === 'final' && x.id !== missingId &&
            x.generation === origin.generation && x.request_id === origin.request_id) : [];
          r = outcomeCapability && !outcomeError && finals.length === 1
            ? { ...r, decision_record: finals[0] }
            : { ...r, error_code: outcomeError || 'not_found', error: 'Unavailable' };
        }
        s.end(JSON.stringify(r) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, 's') + (readonly ? '.monitor' : ''), r));
    servers.push(server);
  }
  app = await _electron.launch({
    executablePath: process.env.FLOWGATE_TEST_ELECTRON,
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(dir, 's.monitor'),
      '--control',
      path.join(dir, 's'),
    ],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(dir, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const until = async (fn, what) => {
    for (let i = 0; i < 100; i++) {
      const result = await fn();
      if (result) return result;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw Error('Timeout: ' + what);
  };
  const p = await until(
    () => app.windows().find((w) => w.url() === 'flowgate://app/index.html'),
    'main desktop window',
  );
  await p.setViewportSize({ width: 1280, height: 760 });
  await p
    .locator('.brand')
    .evaluate((e) => (e.textContent = 'FlowGate · SYNTHETIC DECISION LOG STATES'));
  await p.click('#decisionLogTab');
  const empty = () => p.locator('#logEmpty').innerText();
  await until(async () => /does not provide a decision log/.test(await empty()), 'unsupported');
  variant = 'forbidden';
  await until(async () => /Permission denied/.test(await empty()), 'forbidden');
  variant = 'empty';
  await p.selectOption('#logRange', '1h');
  await until(async () => /No stored records match/.test(await empty()), 'filtered empty');
  await p.selectOption('#logRange', 'any');
  await until(
    async () => /No firewall decisions recorded yet.*not active/.test(await empty()),
    'empty log',
  );
  await p.screenshot({ path: path.join(dir, 'empty.png') });
  variant = 'degraded';
  await p.selectOption('#logDirection', 'outgoing');
  await until(async () => (await p.locator('#logRows tr').count()) === 6, 'records');
  assert.match(await p.locator('#logRows tr.log-gap').innerText(), /Records lost · 4 dropped/);
  assert.match(await p.locator('#logStatus').innerText(), /Logging degraded · 4 records dropped/);
  await p.click('#logRows tr[data-id="syn-12"]');
  await until(
    async () => /User decision/.test(await p.locator('#logDetails').innerText()),
    'details',
  );
  const details = await p.locator('#logDetails').innerText();
  assert.match(details, /Delivery\s+Not observed by FlowGate/);
  assert.doesNotMatch(details, /Delivered/);
  // A missing final in a loaded page must not become evidence of absent history.
  await p.click('#logRows tr[data-id="syn-7"]');
  await until(
    async () => /Linked outcomes require a newer daemon/.test(await p.locator('#logDetails').innerText()),
    'unloaded outcome',
  );
  assert.doesNotMatch(await p.locator('#logDetails').innerText(), /outcome was not recorded/i);
  // Decision-time snapshot vs current inventory (edit/delete are not in the lab fixture).
  await p.click('#logRows tr[data-id="syn-9"]');
  await until(
    async () => /current version 4/.test(await p.locator('#logDetails').innerText()),
    'edited rule',
  );
  const edited = await p.locator('#logDetails').innerText();
  assert.match(edited, /Version\s+2/);
  assert.match(edited, /View current rule/);
  await p.click('#logRows tr[data-id="syn-8"]');
  await until(
    async () => /no longer exists/.test(await p.locator('#logDetails').innerText()),
    'deleted rule',
  );
  await p.click('#logRows tr[data-id="syn-12"]');
  await until(
    async () => /User decision/.test(await p.locator('#logDetails').innerText()),
    'reselect',
  );
  await p.screenshot({ path: path.join(dir, 'degraded.png') });
  await p.setViewportSize({ width: 860, height: 600 });
  await p.waitForTimeout(500);
  await p.screenshot({ path: path.join(dir, 'degraded-narrow.png') });
  // Long names, IPv6, paged/filtered history and unavailable outcomes are fixtures.
  navigation = Array.from({ length: 180 }, (_, i) => {
    const r = record(i + 1, i % 2 ? 'block' : 'allow', 'user');
    r.application.name = 'SYNTHETIC long application — full name remains in details';
    r.flow.family = 'ipv6';
    r.flow.local = '[2001:db8:abcd:1234:5678:90ab:cdef:1234]:49152';
    r.flow.remote = '[2001:db8:ffff:abcd:5678:90ab:cdef:9876]:443';
    return r;
  });
  navigation[178].generation = navigation[179].generation = 'earlier-daemon';
  navigation[0].request_id = navigation[179].request_id;
  navigation[178].kind = 'pending';
  navigation[178].request_id = navigation[179].request_id;
  navigation[177].kind = 'pending'; // no final with this request ID is loaded
  for (const i of [177, 178]) {
    navigation[i].decision = {
      ...navigation[i].decision,
      action: 'pending',
      source: 'default_ask',
      scope: null,
    };
    navigation[i].verdict = { state: 'held', detail: '' };
  }
  variant = 'navigation';
  await p.setViewportSize({ width: 1280, height: 760 });
  await p.click('#logClear');
  await until(
    async () => (await p.locator('#logRows tr').count()) === 100,
    'navigation first page',
  );
  const openOutcome = () => p.getByRole('button', { name: 'Open recorded outcome', exact: true });
  const detail = () => p.locator('#logDetails').innerText();
  const shown = (id) => until(async () => (await detail()).includes('Record ID\n' + id), 'shown ' + id);
  const checkCopy = async (name, expected, result = 'Copied') => {
    const sentinel = 'seed for ' + name;
    await app.evaluate(({ clipboard }, value) => clipboard.writeText(value), sentinel);
    const button = await p.getByRole('button', { name, exact: true }).elementHandle();
    await button.click();
    await until(async () => (await button.textContent()) === result, result + ' for ' + name);
    const value = await app.evaluate(({ clipboard }) => clipboard.readText());
    if (typeof expected === 'function') expected(JSON.parse(value));
    else assert.equal(value, expected ?? sentinel);
  };

  await p.click('#logRows tr[data-id="syn-179"]');
  await until(async () => /Linked outcomes require a newer daemon/.test(await detail()), 'legacy explanation');
  assert.equal(await p.locator('#logRows tr[data-id="syn-180"]').count(), 1, 'matching final loaded on legacy daemon');
  assert.equal(await openOutcome().count(), 0);
  await p.click('#logRows tr[data-id="syn-180"]');
  await checkCopy('Copy record', (r) => assert.equal(r.id, 'syn-180'));
  await checkCopy('Copy local endpoint', navigation[179].flow.local);
  await checkCopy('Copy remote endpoint', navigation[179].flow.remote);
  assert.deepEqual(outcomeRequests, []);
  console.log('PASS legacy browsing and copying with a loaded matching final and no outcome link');
  outcomeCapability = true;
  await until(() => p.evaluate(async () => (await window.flowgate.decisionLog()).outcomeLookup), 'outcome capability');
  await p.click('#logRows tr[data-id="syn-178"]');
  await p.getByRole('button', { name: 'Open recorded outcome' }).click();
  await until(
    async () => /No recorded outcome available\./.test(await p.locator('#logDetails').innerText()),
    'missing outcome',
  );
  assert.doesNotMatch(await p.locator('#logDetails').innerText(), /outcome was not recorded/);
  await p.click('#logRows tr[data-id="syn-179"]');
  await until(
    async () => await p.getByRole('button', { name: 'Open recorded outcome' }).count(),
    'known outcome link',
  );
  missingId = 'syn-180';
  await p.getByRole('button', { name: 'Open recorded outcome' }).click();
  await until(
    async () => /No recorded outcome available\./.test(await p.locator('#logDetails').innerText()),
    'authoritative not_found',
  );
  missingId = '';
  await p.click('#logRows tr[data-id="syn-180"]');
  await until(
    async () => /Copy remote endpoint/.test(await p.locator('#logDetails').innerText()),
    'endpoint copy',
  );
  await checkCopy('Copy remote endpoint', navigation[179].flow.remote);
  await p.getByRole('button', { name: 'Only this application' }).click();
  await until(
    async () => await p.locator('#logApplication').isVisible(),
    'application filter label',
  );
  assert.match(await p.locator('#logApplication').innerText(), /^Application:/);
  assert.match(await p.locator('#logLive').innerText(), /filtered/);
  await p.click('#logApplication');
  await until(async () => !(await p.locator('#logClear').isVisible()), 'remove application filter');
  await p.click('#logOlder');
  await until(async () => (await p.locator('#logRows tr').count()) === 180, 'older page');
  await p.locator('#logRows tr[data-id="syn-150"]').scrollIntoViewIfNeeded();
  await p.click('#logRows tr[data-id="syn-150"]');
  const top = () => p.locator('#logScroll').evaluate((e) => e.scrollTop);
  const beforeTop = await top();
  await p.waitForTimeout(1300);
  assert.equal(await top(), beforeTop, 'selection and polling preserve scroll');
  const anchorY = () =>
    p.locator('#logRows tr[data-id="syn-150"]').evaluate((e) => e.getBoundingClientRect().top);
  const beforeY = await anchorY();
  navigation.push(record(181, 'allow', 'rule'));
  await until(async () => (await p.locator('#logRows tr').count()) === 181, 'live insertion');
  assert.equal(await anchorY(), beforeY, 'arrival preserves visible row offset');
  assert.equal(
    await p.locator('#logRows tr[aria-selected="true"]').getAttribute('data-id'),
    'syn-150',
  );
  await p.locator('#logTable').focus();
  await p.keyboard.press('ArrowDown');
  assert.equal(
    await p.locator('#logRows tr[aria-selected="true"]').getAttribute('data-id'),
    'syn-149',
  );
  await p.keyboard.press('Enter');
  assert.equal(await p.evaluate(() => document.activeElement.id), 'logDetails');
  await p.keyboard.press('Escape');
  assert.equal(await p.evaluate(() => document.activeElement.id), 'logTable');
  await p.click('#logLive');
  navigation.push(record(182, 'block', 'user'));
  await until(async () => await p.locator('#logNew').isVisible(), 'paused arrival indicator');
  await p.click('#logNew');
  await until(
    async () => (await p.locator('#logRows tr').first().getAttribute('data-id')) === 'syn-182',
    'jump latest',
  );
  assert.equal(await top(), 0);
  assert.match(await p.locator('#logLive').innerText(), /Paused/, 'jump does not silently resume');
  await p.selectOption('#logDirection', 'outgoing');
  await until(
    async () => /filtered/.test(await p.locator('#logLive').innerText()),
    'paused filtered state',
  );
  await p.click('#logRows tr[data-id="syn-180"]');
  await until(
    async () => /2001:db8:ffff/.test(await p.locator('#logDetails').innerText()),
    'full IPv6 detail',
  );
  await p.screenshot({ path: path.join(dir, 'navigation-normal.png') });
  await p.setViewportSize({ width: 860, height: 600 });
  await p.waitForTimeout(300);
  const columns = await p.locator('#logTable th').evaluateAll((xs) =>
    xs.slice(0, 4).map((e) => ({
      text: e.textContent,
      width: e.getBoundingClientRect().width,
      right: e.getBoundingClientRect().right,
    })),
  );
  assert.deepEqual(
    columns.map((x) => x.text),
    ['Time', 'Application', 'Decision', 'Source'],
  );
  const edge = await p.locator('#logScroll').evaluate((e) => e.getBoundingClientRect().right - 15);
  assert(
    columns.every((x) => x.width >= 70 && x.right <= edge),
    'essential columns visible at narrow size',
  );
  await p.screenshot({ path: path.join(dir, 'navigation-narrow.png') });
  await p.click('#logClear');
  await until(async () => !(await p.locator('#logClear').isVisible()), 'clear filters');
  for (let i = 183; i <= 532; i++) {
    const pending = i % 5 === 0;
    const r = record(i, pending ? 'pending' : 'block', pending ? 'default_ask' : 'user');
    if (pending) r.kind = 'pending';
    navigation.push(r);
  }
  await p.selectOption('#logAction', 'pending');
  const origin = p.locator('#logRows tr[data-id="syn-179"]');
  await origin.click();
  const anchor = await top();
  assert(anchor > 0, 'pending row is below the fold');
  const rows = () => p.locator('#logRows tr').evaluateAll((rs) => rs.map((r) => r.dataset.id));
  const pendingRows = await rows();
  assert(!pendingRows.includes('syn-180'));
  await p.getByRole('button', { name: 'Open recorded outcome' }).click();
  await until(async () => /Record ID\s+syn-180\b/.test(await p.locator('#logDetails').innerText()), 'cross-page outcome');
  assert.equal(await p.locator('#logAction').inputValue(), 'pending');
  assert.deepEqual(await rows(), pendingRows);
  assert.equal(await top(), anchor);
  assert.equal(await origin.getAttribute('aria-selected'), 'true');
  const historicalCopy = (r) => {
    assert.equal(r.id, 'syn-180');
    assert.equal(r.generation, 'earlier-daemon');
  };
  const copies = [
    ['Copy record', historicalCopy],
    ['Copy local endpoint', navigation[179].flow.local],
    ['Copy remote endpoint', navigation[179].flow.remote],
  ];
  const copyOutcome = async (name, expected, result) => {
    const before = outcomeRequests.length;
    await checkCopy(name, expected, result);
    assert.deepEqual(outcomeRequests.slice(before), ['syn-179']);
  };
  for (const [name, expected] of copies) await copyOutcome(name, expected);

  const back = () => p.getByRole('button', { name: 'Back to pending record' }).click();
  const duplicate = { ...navigation[179], id: 'ambiguous-final' };
  for (const failure of ['pending hidden', 'final hidden', 'unavailable', 'ambiguous']) {
    const setFailure = (active) => {
      if (failure === 'pending hidden') missingId = active ? 'syn-179' : '';
      if (failure === 'final hidden') missingId = active ? 'syn-180' : '';
      if (failure === 'unavailable') outcomeError = active ? 'unavailable' : '';
      if (failure === 'ambiguous') {
        if (active) navigation.push(duplicate);
        else navigation.pop();
      }
    };
    await back();
    await shown('syn-179');
    setFailure(true);
    await openOutcome().click();
    await until(async () => /No recorded outcome available|Outcome lookup failed/.test(await detail()), 'failed open');
    assert.equal(await p.getByRole('button', { name: 'Copy record', exact: true }).count(), 0);

    setFailure(false);
    await back();
    await shown('syn-179');
    await openOutcome().click();
    await shown('syn-180');
    setFailure(true);
    for (const [name] of copies) await copyOutcome(name, undefined, 'Copy unavailable');
    setFailure(false);
  }
  await back();
  await shown('syn-179');
  await openOutcome().click();
  await shown('syn-180');
  outcomeCapability = false;
  await until(() => p.evaluate(async () => !(await window.flowgate.decisionLog()).outcomeLookup), 'older daemon after opening');
  const beforeDowngradeCopies = outcomeRequests.length;
  for (const [name] of copies) await checkCopy(name, undefined, 'Copy unavailable');
  assert.equal(outcomeRequests.length, beforeDowngradeCopies);
  await back();
  await shown('syn-179');
  assert.equal(await top(), anchor);
  console.log('PASS historical linked copies and clipboard preservation on hidden, unavailable and ambiguous outcomes');
  console.log('PASS cross-page outcome with Pending selected, 350 newer events and preserved scroll');
  console.log(
    'PASS SYNTHETIC navigation: missing/known/unavailable outcomes, copy IPv6, filters, paging, anchor, keyboard, pause/latest; ' +
      dir,
  );
  console.log(
    'PASS SYNTHETIC decision-log states (unsupported, forbidden, empty, filtered, degraded+gap, rule edited/deleted since decision) ' +
      dir,
  );
  await p.setViewportSize({ width: 1280, height: 760 });
  const display = await app.evaluate(({ screen }) => screen.getPrimaryDisplay());
  console.log(`Desktop ${display.size.width}x${display.size.height} at ${display.scaleFactor * 100}%`);
  const laterBlock = {
    ...record(3002, 'block', 'identity_changed'), request_id: undefined,
    related_request_id: 'earlier-request',
  };
  const aggregation = {
    observations: 15, first_seen: '2026-11-22T18:03:12.012Z',
    last_seen: '2026-11-22T18:03:12.123Z', window_ms: 5000,
  };
  const gap = {
    id: 'evidence-gap', sequence: '3000', kind: 'gap',
    gap: { dropped: 0, reason: 'Fixture gap' },
  };
  evidence = [laterBlock, { ...record(3001, 'block', 'capacity'), aggregation }, gap];
  variant = 'evidence';
  await p.click('#logClear');
  await p.click('#logRows tr[data-id="syn-3002"]');
  await shown('syn-3002');
  assert.match(await detail(), /Related request ID\s+earlier-request/);
  assert.equal(await openOutcome().count(), 0);
  await checkCopy('Copy record', (r) => {
    assert.equal(r.related_request_id, 'earlier-request');
    assert.equal(r.request_id, '');
  });
  await p.screenshot({ path: path.join(dir, 'evidence-related-request.png') });
  await p.click('#logRows tr[data-id="syn-3001"]');
  await shown('syn-3001');
  assert.match(await detail(), /Aggregated observations\s+Observations\s+15\s+Window\s+5000 ms/i);
  const timestamp = (label) => p.locator(`#logDetails dt:text-is("${label}") + dd`);
  const firstSeen = timestamp('First seen');
  const lastSeen = timestamp('Last seen');
  assert.match(await firstSeen.innerText(), /:\d{2}:12\.012$/);
  assert.match(await lastSeen.innerText(), /:\d{2}:12\.123$/);
  assert.equal(await firstSeen.getAttribute('title'), aggregation.first_seen);
  assert.equal(await lastSeen.getAttribute('title'), aggregation.last_seen);
  await checkCopy('Copy record', (r) => assert.deepEqual(r.aggregation, aggregation));
  await p.screenshot({ path: path.join(dir, 'evidence-aggregation.png') });
  await p.click('#logRows tr[data-id="evidence-gap"]');
  await shown('evidence-gap');
  assert.match(await detail(), /Dropped\s+0/);
  assert.match(await p.locator('#logRows .log-gap').innerText(), /0 dropped/);
  await checkCopy('Copy record', (r) => assert.equal(r.gap.dropped, 0));

  variant = 'evidence-self';
  await until(async () => /Your decisions only/.test(await p.locator('#logStatus').innerText()), 'self evidence');
  await p.click('#logRows tr[data-id="evidence-gap"]');
  await shown('evidence-gap');
  assert.match(await detail(), /Dropped\s+Count withheld/);
  assert.match(await p.locator('#logRows .log-gap').innerText(), /Count withheld/);
  await checkCopy('Copy record', (r) => assert.equal(Object.hasOwn(r.gap, 'dropped'), false));
  await p.screenshot({ path: path.join(dir, 'evidence-withheld-count.png') });

  variant = 'filter-race';
  await until(async () => (await rows()).includes('syn-4000'), 'race seed');
  if ((await p.locator('#logLive').getAttribute('aria-pressed')) === 'false') await p.click('#logLive');
  raceArmed = true;
  await until(() => heldRecovery, 'unfiltered recovery request held');
  await p.selectOption('#logDirection', 'outgoing');
  await until(async () => (await rows()).join() === 'syn-4001', 'outgoing-only page');
  assert.equal(heldRecovery.destroyed, false, 'obsolete reply must still be in flight');
  const obsolete = { ...record(5000, 'allow', 'user') };
  obsolete.flow.direction = 'incoming';
  heldRecovery.end(JSON.stringify({
    ...base(false), decision_log: { ...page(), records: [obsolete], next_before: '5000' },
  }) + '\n');
  await p.waitForTimeout(1200); // Renderer polling interval is one second.
  assert.deepEqual(await rows(), ['syn-4001']);
  assert.equal(await p.locator('#logOlder').isVisible(), false);
  await p.screenshot({ path: path.join(dir, 'outgoing-after-delayed-page.png') });
  console.log('PASS evidence detail and clipboard JSON; outgoing-only filter ignored a delayed incoming recovery page');
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  servers.forEach((s) => s.close());
  if (preferences) fs.writeFileSync(prefPath, preferences);
  else fs.rmSync(prefPath, { force: true });
}
