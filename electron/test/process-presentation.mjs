// Labelled synthetic process-policy presentation only. Not enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/pp-'));
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
    sequence: exited ? 2 : 1,
    collected,
    complete: true,
    processes,
    rows: Object.values(processes).map((p) => ({
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
      traffic: { available: false, reason: 'SYNTHETIC — no measured traffic' },
    })),
  };
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
      status: 'observed_native',
      application_ref: 'appref',
      reason: 'SYNTHETIC',
      decision_authority: false,
    })),
  };
}
const handler = (monitor) => (s) =>
  s.once('data', (raw) => {
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
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 1280, height: 656 });
  await wait(() => page.locator('#rows tr[data-id^="app:"]').count());
  await page.click('#expand');
  await page.locator('#rows tr[data-id^="process:"][data-id$=":101:123"] .name').click();
  await wait(() =>
    page
      .locator('.activity-rule')
      .count()
      .then((n) => n === 2),
  );
  assert.match(await page.locator('#infoRules').innerText(), /This process/);
  assert.match(await page.locator('#infoRules').innerText(), /Application fallback/);
  await page.screenshot({ path: path.join(run, 'synthetic-process-normal.png') });
  await page.locator('.sidebar-process-policy[data-direction=incoming]').click();
  assert.equal(await page.getByLabel('Rule target', { exact: true }).inputValue(), 'process');
  await page.getByLabel('Rule to create or change', { exact: true }).selectOption('new');
  await page.getByText('All addresses and ports for this protocol', { exact: true }).check();
  await page.locator('.quick-allow').click();
  await wait(() => page.locator('#ruleEditor').isVisible());
  assert.match(await page.locator('#editorApplication').innerText(), /This process/);
  await page.click('#editorMode');
  await page.selectOption('#createScope', 'custom');
  await page.fill('#editAddress', '2001:db8::123');
  await page.locator('#editAddress').evaluate((e) => e.setSelectionRange(2, 6));
  await page.waitForTimeout(1700);
  assert.equal(await page.inputValue('#editAddress'), '2001:db8::123');
  assert.equal(await page.locator('#editAddress').evaluate((e) => e.selectionStart), 2);
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'editAddress');
  exited = true;
  await wait(() => page.locator('#saveRule').isDisabled());
  await wait(() =>
    page
      .locator('#editorFeedback')
      .innerText()
      .then((t) => t.includes('no longer available')),
  );
  assert.equal(await page.inputValue('#editAddress'), '2001:db8::123');
  assert(await page.locator('#previewRule').isDisabled());
  await page.click('#closeEditor');
  await page.keyboard.press('Escape');
  await wait(() =>
    page
      .locator('#infoRules')
      .innerText()
      .then((t) => t.includes('Process exited')),
  );
  await page.setViewportSize({ width: 860, height: 600 });
  await page.screenshot({ path: path.join(run, 'synthetic-exited-narrow.png') });
  await page.click('#rulesTab');
  await wait(() =>
    page
      .locator('#ruleRows tr[data-id="process-rule"]')
      .innerText()
      .then((t) => t.includes('Inactive target')),
  );
  assert.equal(mutations, 0);
  console.log(
    'PASS synthetic process/app grouping, default target, input/focus polling, exit/draft preservation, normal/narrow; no mutations. ' +
      run,
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
