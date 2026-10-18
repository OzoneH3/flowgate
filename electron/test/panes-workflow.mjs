// Labelled synthetic process-policy presentation only. Not enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/panes-synthetic-'));
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
const application = {
  key: 'synthetic',
  revision: 'r',
  name: 'SYNTHETIC Native app',
  executable: '/synthetic/no-installed-icon',
};
const fixtureProcess = (pid) => ({
  id: pid + ':123',
  pid,
  start_ticks: '123',
  uid: 1000,
  application,
  executable: application.executable,
});
const p = fixtureProcess(101),
  q = fixtureProcess(102);
const target = (pid) => ({
  instance_id: (pid === 101 ? 'a' : 'b').repeat(32),
  session: 'g',
  boot_id: 'fixture',
  pid,
  start_ticks: '123',
  uid: 1000,
  netns: 'net:[1]',
  mountns: 'mnt:[2]',
  pidns: 'pid:[3]',
  executable: application.executable,
  revision: 'r',
});
const rule = (id, process, action) => ({
  id,
  version: 1,
  schema: process ? 3 : 2,
  executable: application.executable,
  created: new Date().toISOString(),
  action,
  priority: 100,
  disabled: false,
  expires: '0001-01-01T00:00:00Z',
  filter: {
    application: application.key,
    revision: 'r',
    uid: 1000,
    direction: 'incoming',
    protocol: 'tcp',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
    ...(process ? { process } : {}),
  },
});
const appRule = rule('application-rule', undefined, 'allow'),
  processRule = rule('process-rule', target(101), 'block');
let disconnected = false;
let observationSequence = 0;
let exited = false,
  mutations = 0,
  sequence = 0;
const collected = new Date().toISOString();
const ref = (r) => ({
  id: r.id,
  version: String(r.version),
  action: r.action,
  priority: r.priority,
  scope: r.filter,
  disabled: r.disabled,
  expired: false,
  active: !r.filter.process || !exited,
  expires: r.expires,
  target_scope: r.filter.process ? 'process' : 'application',
  target_state: r.filter.process && exited ? 'inactive' : 'active',
  target_reason: exited ? 'Process exited' : 'Pinned fixture',
});
const dir = (d, r = []) => ({
  direction: d,
  configured: r.length ? (r[0].active ? 'scoped' : 'inactive_only') : 'absent',
  reason: 'SYNTHETIC backend classification',
  rules: r,
  active_rules: r.filter((r) => r.active).length,
  disabled_rules: 0,
  expired_rules: 0,
  potential_overlapping_actions: false,
  configured_default: { known: false, reason: 'Unavailable' },
  runtime_default: { known: false, reason: 'Stopped' },
  enforcement: { state: 'stopped', covered: false, reason: 'Monitoring only' },
});
function activity() {
  const processes = exited ? { [q.id]: q } : { [p.id]: p, [q.id]: q };
  return {
    sequence: ++observationSequence,
    collected: new Date().toISOString(),
    complete: true,
    processes,
    rows: Object.values(processes)
      .map((p) => ({
        id: 'socket-' + p.pid,
        owners: [p.id],
        ownership_category: 'visible-holder',
        state: 'Established',
        direction: 'Unknown',
        initiation: { state: 'unknown', source: 'synthetic', reason: 'Synthetic layout fixture' },
        socket: {
          protocol: 'tcp',
          local: '[::1]:44001',
          remote: '[2001:db8::1]:50000',
          uid: 1000,
          state: 1,
        },
        traffic: {
          available: true,
          partial: false,
          state: 'measured',
          since: 'synthetic-baseline',
          definition: 'tcp-transport-payload',
          uploaded: observationSequence * 200,
          downloaded: observationSequence * 400,
          upload_bps: 200,
          download_bps: 400,
          reason: 'SYNTHETIC display rates — not collector evidence',
        },
      }))
      .concat(exited ? [] : extraRows()),
  };
}
// SYNTHETIC: known outgoing initiation, shared holders and unidentified ownership.
function extraRows() {
  const base = (id, owners, category, local, remote, initiation, extra = {}) => ({
    id,
    owners,
    ownership_category: category,
    state: 'Established',
    direction: 'Unknown',
    initiation,
    socket: { protocol: 'tcp', local, remote, uid: 1000, state: 1 },
    traffic: {
      available: true,
      partial: false,
      state: 'measured',
      since: 'synthetic-baseline',
      definition: 'tcp-transport-payload',
      uploaded: observationSequence * 200,
      downloaded: observationSequence * 400,
      upload_bps: 200,
      download_bps: 400,
      reason: 'SYNTHETIC display rates — not collector evidence',
    },
    ...extra,
  });
  return [
    base('socket-out', [p.id], 'visible-holder', '[::1]:44002', '[2001:db8::2]:443', {
      state: 'known',
      direction: 'outgoing',
      source: 'synthetic',
      reason: 'SYNTHETIC initiated by this process',
    }),
    base(
      'socket-shared',
      [p.id, q.id],
      'shared',
      '[::1]:44003',
      '[2001:db8::3]:443',
      { state: 'unknown', source: 'synthetic', reason: 'SYNTHETIC shared holders' },
      { display_application: application },
    ),
    base('socket-unknown', [], 'unknown', '[::1]:44004', '[2001:db8::4]:80', {
      state: 'unknown',
      source: 'synthetic',
      reason: 'SYNTHETIC no holder',
    }),
  ];
}
function view() {
  const a = activity(),
    incoming = dir('incoming', [ref(appRule)]),
    outgoing = dir('outgoing');
  return {
    snapshot: {
      generation: 'g',
      token: exited ? 'exit' : 'live',
      sequence: String(++sequence),
      evaluated_at: new Date().toISOString(),
      meaning: 'SYNTHETIC current policy',
    },
    activity_sequence: exited ? '2' : '1',
    activity_collected: a.collected,
    activity_available: true,
    complete: true,
    applications: [
      {
        ref: 'appref',
        identity: { key: application.key, revision: 'r', uid: 1000 },
        process_ids: Object.keys(a.processes),
        incoming,
        outgoing,
      },
    ],
    processes: [p, q].map((p) => ({
      ref: 'ref-' + p.pid,
      process_id: p.id,
      application_ref: 'appref',
      target: target(p.pid),
      state: p.pid === 101 && exited ? 'inactive' : 'active',
      reason:
        p.pid === 101 && exited
          ? 'Process exited; old target cannot rebind'
          : 'SYNTHETIC pinned instance',
      precedence: 'matching-process-before-application',
      incoming: dir('incoming', p.pid === 101 ? [ref(processRule)] : []),
      outgoing,
      application_incoming: incoming,
      application_outgoing: outgoing,
    })),
    rows: a.rows.map((r) => ({
      row_id: r.id,
      status:
        r.owners.length === 1 ? 'observed_native' : r.owners.length ? 'shared' : 'unattributed',
      application_ref: 'appref',
      reason: 'SYNTHETIC',
      decision_authority: false,
    })),
  };
}
const handler = (monitor) => (s) =>
  s.once('data', (raw) => {
    if (disconnected) {
      s.destroy();
      return;
    }
    const req = JSON.parse(raw),
      result = {
        version: 1,
        generation: 'g',
        mode: monitor ? 'host-monitor' : 'daemon-monitor',
        read_only: monitor,
        server_time: new Date().toISOString(),
        capabilities: [
          'explicit-administrator-v1',
          'policy-explanations-v1',
          'process-instance-rules-v1',
          'observed-rule-create-v1',
          'conditional-rule-delete-v1',
        ],
        permissions: {
          role: 'administrator',
          observation_scope: 'machine',
          policy_scope: 'machine',
          can_manage_rules: true,
          can_decide: false,
        },
        events: [],
        rules: [appRule, processRule],
        rule_states: {
          'application-rule': {
            target_scope: 'application',
            state: 'active',
            reason: 'Application',
          },
          'process-rule': {
            target_scope: 'process',
            state: exited ? 'inactive' : 'active',
            reason: exited ? 'Process exited' : 'Live',
          },
        },
        enforcement: { state: 'stopped' },
        activity: activity(),
      };
    if (req.operation === 'policy-view') result.policy_view = view();
    else if (req.operation !== 'list') mutations++;
    s.end(JSON.stringify(result) + '\n');
  });
const server = net.createServer(handler(false)),
  observer = net.createServer(handler(true));
const endpoint = path.join(run, 's');
await new Promise((r) => server.listen(endpoint, r));
await new Promise((r) => observer.listen(endpoint + '.monitor', r));
let app;
const wait = async (fn) => {
  for (let end = Date.now() + 15000; Date.now() < end;) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout ' + fn);
};
try {
  fs.writeFileSync(prefs, '{}');
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
    env: {
      ...process.env,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const page = await app.firstWindow(),
    errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  const shot = (name, p = page) => p.screenshot({ path: path.join(run, name + '.png') });
  await page.setViewportSize({ width: 1280, height: 656 });
  await wait(async () => (await page.locator('#rows tr[data-id^="app:"]').count()) > 0);
  await page.click('#expand');
  await page.locator('#rows tr[data-id^="process:"] .name').first().click();
  await shot('01-main-before');
  const processRow = page.locator('#rows tr[data-id^="process:"]').first();
  await processRow.locator('.name').dblclick();
  assert.equal(
    await page.locator('#rows tr[data-id^="socket-"]').count(),
    3,
    'double click collapses selected process only',
  );
  await processRow.locator('.name').dblclick();
  assert.equal(
    await page.locator('#rows tr[data-id^="socket-"]').count(),
    5,
    'double click expands children',
  );
  await page.locator('#infoPaneControls summary').click();
  await page.locator('[data-undock=info]').click();

  const pane = async (kind) => {
    await wait(async () => app.windows().some((p) => p.url().includes('pane=' + kind)));
    const p = app.windows().find((p) => p.url().includes('pane=' + kind));
    await p.locator('#paneUnits').waitFor();
    return p;
  };
  const info = await pane('info');
  info.on('pageerror', (e) => errors.push(String(e)));
  await page.locator('#trafficGraph .pane-menu summary').click();
  await page.locator('[data-undock=chart]').click();
  const chart = await pane('chart');
  chart.on('pageerror', (e) => errors.push(String(e)));
  assert.equal(app.windows().length, 3);
  await info.selectOption('#paneUnits', 'Mbit');
  await wait(async () => (await page.locator('#displayUnits').inputValue()) === 'Mbit');
  await chart.selectOption('#paneSource', 'udp');
  await wait(async () => (await info.locator('#paneSource').inputValue()) === 'udp');
  await chart.selectOption('#paneSource', 'tcp');
  await page.locator('#rows tr[data-id^="process:"] .name').last().click();
  await wait(async () => /102/.test(await info.locator('#selectedName').innerText()));
  await shot('02-main-detached');
  await shot('03-info-detached', info);
  await shot('04-chart-detached', chart);
  assert.equal(await info.evaluate(() => typeof window.flowgate.ruleSave), 'undefined');
  await info.locator('[data-focus="cell:process:incoming"]').click();
  await wait(async () => (await page.locator('.quick-popup').count()) > 0);
  assert.equal(await info.locator('.quick-popup').count(), 0);
  assert.equal(mutations, 0);
  await shot('05-main-rule-owner');
  await page.keyboard.press('Escape');
  await page.locator('#floatingRuleStatus > header button').click();
  await chart.locator('[data-series=download]').click();
  assert.equal(await chart.locator('[data-series=download]').getAttribute('aria-pressed'), 'false');
  await wait(async () => {
    const g = await page.evaluate(async () =>
      window.flowgate.graph({
        id: (await window.flowgate.paneSnapshot()).presentation.selection,
        seconds: 600,
      }),
    );
    return g.points.length >= 8;
  });
  await page.evaluate(() => window.flowgate.paneUpdate({ chart: { seconds: 5 } }));
  await chart.locator('#trafficCanvas').focus();
  await chart.keyboard.press('-');
  await chart.keyboard.press('ArrowLeft');
  await wait(async () => await chart.locator('#graphSample').isVisible());
  await chart.locator('#graphPause').click();
  await wait(
    async () => (await chart.locator('#graphPause').getAttribute('aria-pressed')) === 'true',
  );
  await chart.keyboard.press('PageUp');
  await wait(
    async () =>
      (await page.evaluate(() => window.flowgate.paneSnapshot())).presentation.chart.end !==
      undefined,
  );
  await chart.locator('#graphLive').click();
  disconnected = true;
  await wait(
    async () => !(await page.evaluate(() => window.flowgate.snapshot())).observation.connected,
  );
  assert.match(await info.locator('#paneEnforcement').innerText(), /disconnected/);
  disconnected = false;
  await wait(
    async () => (await page.evaluate(() => window.flowgate.snapshot())).observation.connected,
  );
  const history = await page.evaluate(async () =>
    window.flowgate.graph({
      id: (await window.flowgate.paneSnapshot()).presentation.selection,
      seconds: 600,
    }),
  );
  assert(
    history.points.some((p) => p.breakBefore),
    'reconnect remains a gap',
  );
  const mainID = await app.evaluate(
    ({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().find((w) => w.webContents.getURL().includes('index.html')).id,
  );
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).hide(), mainID);
  await wait(
    async () =>
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().every((w) => !w.isVisible()),
      ),
  );
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).show(), mainID);
  await wait(
    async () =>
      await app.evaluate(({ BrowserWindow }) =>
        BrowserWindow.getAllWindows().every((w) => w.isVisible()),
      ),
  );
  await info.locator('#dockPane').click();
  await wait(async () => app.windows().length === 2);
  assert.equal(await page.locator('#infoRules').isVisible(), true);
  await chart.locator('#closePane').click();
  await wait(async () => app.windows().length === 1);
  await page.locator('.toolbar-window-menu summary').click();
  await page.locator('.toolbar-window-menu [data-pane=chart]').click();
  await wait(async () => await page.locator('#trafficGraph').isVisible());
  assert.equal(
    await page.locator('#graphValues [data-series=download]').getAttribute('aria-pressed'),
    'false',
  );
  await page.setViewportSize({ width: 860, height: 600 });
  await shot('06-narrow-redocked');
  assert.deepEqual(errors, []);
  assert.equal(mutations, 0);
  console.log(
    JSON.stringify(
      { run, synthetic: true, windowsFinal: app.windows().length, mutations, errors },
      null,
      2,
    ),
  );
} catch (e) {
  if (app) {
    const p = await app.firstWindow();
    await p.screenshot({ path: path.join(run, 'failure.png') }).catch(() => {});
    console.error(await p.locator('body').innerText());
  }
  throw e;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  server.close();
  observer.close();
  if (old) fs.writeFileSync(prefs, old);
  else if (fs.existsSync(prefs)) fs.unlinkSync(prefs);
}
