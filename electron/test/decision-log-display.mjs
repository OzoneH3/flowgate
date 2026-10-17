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
  ],
  permissions: {
    role: 'administrator',
    policy_scope: 'machine',
    observation_scope: 'machine',
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
const servers = [];
let app;
try {
  for (const readonly of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', (b) => {
        const q = JSON.parse(b);
        let r = base(readonly);
        if (q.operation === 'decision-log')
          r =
            variant === 'forbidden'
              ? { ...r, error: 'SYNTHETIC denial', error_code: 'forbidden' }
              : { ...r, decision_log: page() };
        if (q.operation === 'decision-log-get')
          r = { ...r, decision_record: page().records.find((x) => x.id === q.decision_id) };
        s.end(JSON.stringify(r) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, 's') + (readonly ? '.monitor' : ''), r));
    servers.push(server);
  }
  app = await _electron.launch({
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
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 760 });
  await p
    .locator('.brand')
    .evaluate((e) => (e.textContent = 'FlowGate · SYNTHETIC DECISION LOG STATES'));
  await p.click('#decisionLogTab');
  const empty = () => p.locator('#logEmpty').innerText();
  const until = async (fn, what) => {
    for (let i = 0; i < 100; i++) {
      if (await fn()) return;
      await p.waitForTimeout(100);
    }
    throw Error('Timeout: ' + what);
  };
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
  assert.match(await p.locator('#logRows tr.log-gap').innerText(), /Records lost: 4/);
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
  await until(async () => /Outcome not loaded/.test(await p.locator('#logDetails').innerText()), 'unloaded outcome');
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
  console.log(
    'PASS SYNTHETIC decision-log states (unsupported, forbidden, empty, filtered, degraded+gap, rule edited/deleted since decision) ' +
      dir,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  servers.forEach((s) => s.close());
}
