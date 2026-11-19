// Native Electron presentation with synthetic Unix peers. Daemon eligibility is tested in Go.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '../..');
const dir = fs.mkdtempSync(path.join(root, '.workspace/elig-'));
const endpoint = path.join(dir, 's');
const generation = 'rules-fixture';
const appIdentity = { key: 'fixture-app', revision: 'current', name: 'Rule fixture', executable: '/fixture/app', kind: 'native' };
const processID = '101:123';
const start = Date.now();
const expiry = new Date(start + 120_000).toISOString();
const permanent = '0001-01-01T00:00:00Z';
const iso = (time) => new Date(time).toISOString();
const makeRule = (id, action, direction, port) => ({
  id, action, version: 1, schema: 2, priority: 100, executable: appIdentity.executable,
  created: iso(start - 100_000), expires: permanent, disabled: false, follows_updates: true,
  filter: { application: appIdentity.key, revision: appIdentity.revision, uid: 1000,
    direction, protocol: '*', remote_address: '*', remote_port: port },
});
const ask = makeRule('ask', 'ask', 'incoming', 0);
const old = makeRule('older-allow', 'allow', 'outgoing', 3389);
const control = makeRule('different-scope', 'allow', 'outgoing', 3390);
const temporary = { ...old, id: 'temporary-deny', action: 'block', disabled: true,
  created: iso(start - 10_000), expires: expiry, filter: { ...old.filter, revision: 'previous' } };
const rules = [ask, old, temporary, control];
const remembered = { ...makeRule('remembered-choice', 'block', 'incoming', 0), disabled: true };
const scopedIncoming = makeRule('scoped-incoming-control', 'allow', 'incoming', 443);
let retainedAsk = false;
let compatibility = true;
let expired = false;
let sequence = 0;
const enforcement = { state: 'stopped', covered: false, reason: 'Fixture monitoring' };

function direction(direction, selected, time, applicationRule = null) {
  const refs = selected.map((r) => ({
    id: r.id, version: String(r.version), action: r.action, priority: r.priority, expires: r.expires,
    scope: r.filter, disabled: r.disabled, expired: r.expires === expiry && time >= Date.parse(expiry),
    active: !r.disabled, kind: r === ask || r === remembered ? 'application' : 'scoped',
  }));
  return {
    direction, configured: applicationRule ? 'uniform' : 'scoped', action: applicationRule?.action,
    reason: 'Fixture rule summary', rules: refs, active_rules: refs.filter((r) => r.active).length,
    disabled_rules: refs.filter((r) => r.disabled).length, expired_rules: refs.filter((r) => r.expired).length,
    potential_overlapping_actions: false, configured_default: { known: true, action: 'ask', reason: 'Fixture' },
    runtime_default: { known: false, reason: 'Monitoring' }, enforcement,
    application_rule: refs.find((r) => r.id === applicationRule?.id) ?? null,
    scoped_rules: refs.filter((r) => r.kind === 'scoped').length,
  };
}

let observedActivity;
function receive(readOnly) {
  return (socket) => socket.once('data', (data) => {
    const request = JSON.parse(data);
    const time = Date.now() + (expired ? 180_000 : 0);
    const now = iso(time);
    if (readOnly || !observedActivity) observedActivity = {
      sequence: ++sequence, collected: now, complete: true,
      processes: { [processID]: { id: processID, pid: 101, start_ticks: '123', uid: 1000,
        application: appIdentity, executable: appIdentity.executable } },
      rows: [{ id: 'fixture-socket', owners: [processID], ownership_category: 'visible-holder',
        state: 'Established', direction: 'Unknown',
        socket: { protocol: 'tcp', local: '192.0.2.1:55000', remote: '192.0.2.2:3389', uid: 1000, state: 1 } }],
    };
    const activity = observedActivity;
    const response = {
      version: 1, generation, read_only: readOnly, mode: readOnly ? 'host-monitor' : 'daemon-monitor',
      server_time: now, activity, enforcement, rules: retainedAsk ? [...rules, remembered, scopedIncoming] : rules, events: [],
      capabilities: ['explicit-administrator-v1', 'stored-ask-v1',
        ...(compatibility ? [] : ['policy-explanations-v1', 'application-policy-v1'])],
      permissions: { role: 'administrator', observation_scope: 'machine', policy_scope: 'machine',
        can_manage_rules: !readOnly, can_decide: false },
    };
    if (request.operation === 'policy-view') response.policy_view = {
      snapshot: { generation, token: retainedAsk ? 'retained-' + remembered.action : expired ? 'after' : 'before', sequence: String(++sequence),
        evaluated_at: now, valid_until: expired ? undefined : expiry, meaning: 'Fixture' },
      activity_sequence: String(activity.sequence), activity_collected: activity.collected,
      activity_available: true, complete: true,
      rule_eligibility: Object.fromEntries(rules.map((r) => [r.id, { version: '1', masked: r === old && !expired }])),
      applications: [{ ref: 'fixture', identity: { key: appIdentity.key, revision: appIdentity.revision, uid: 1000 },
        process_ids: [processID], incoming: retainedAsk
          ? direction('incoming', [ask, remembered, scopedIncoming], time, remembered)
          : direction('incoming', [ask], time, ask),
        outgoing: direction('outgoing', expired ? [old, temporary, control] : [temporary, control], time) }],
      rows: [{ row_id: 'fixture-socket', status: 'observed_native', reason: 'Fixture',
        application_ref: 'fixture', decision_authority: false }],
    };
    socket.end(JSON.stringify(response) + '\n');
  });
}

const servers = [net.createServer(receive(false)), net.createServer(receive(true))];
await Promise.all(servers.map((server, i) => new Promise((resolve) => server.listen(endpoint + (i ? '.monitor' : ''), resolve))));
const wait = async (description, fn) => {
  for (let i = 0; i < 120; i++) {
    const value = await fn();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw Error('Timed out: ' + description);
};
let desktop;
try {
  desktop = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', path.join(root, 'electron'),
      '--observer', endpoint + '.monitor', '--control', endpoint],
    env: { ...process.env, TMPDIR: path.join(root, '.workspace/tmp'), XDG_CACHE_HOME: path.join(dir, 'cache') },
  });
  const page = await wait('main window', () => desktop.windows().find((w) => w.url() === 'flowgate://app/index.html'));
  await page.setViewportSize({ width: 1280, height: 850 });
  const popup = page.locator('.quick-popup');
  const cell = (d) => page.locator('#infoRules [data-focus="cell:application:' + d + '"]');
  const state = (id) => page.locator('#ruleRows tr[data-id="' + id + '"] td:last-child');
  const popupState = (id) => popup.locator('[data-rule-id="' + id + '"] .rule-enabled-state');
  const label = (locator, text) => wait(text, async () => await locator.count() === 1 && await locator.innerText() === text);
  const snapshot = () => page.evaluate(() => window.flowgate.snapshot());
  const select = () => page.locator('#rows tr[data-id^="app:"] .name').first().click();
  await select();
  await cell('incoming').click();
  await label(popup.locator('.qs-row .rule-enabled-state'), 'Enabled (stored)');
  assert.match(await popup.innerText(), /Ask/);
  await cell('outgoing').click();
  await label(popupState(old.id), 'Enabled (stored)');
  assert.doesNotMatch(await popup.innerText(), /Masked by newer rule/);
  await page.click('#rulesTab');
  await label(state(ask.id), 'Enabled (stored)');
  await label(state(old.id), 'Enabled (stored)');
  await label(state(temporary.id), 'Disabled');
  console.log('Compatibility popup and Rules: Ask / Enabled (stored), older Allow / Enabled (stored), temporary Deny / Disabled');

  compatibility = false;
  await wait('authoritative policy', async () => !!(await snapshot()).control.policy?.rule_eligibility);
  await label(state(ask.id), 'Enabled');
  await label(state(old.id), 'Masked by newer rule');
  await label(state(control.id), 'Enabled');
  await page.click('#activityTab');
  await select();
  await cell('incoming').click();
  await wait('authoritative Ask', async () => /Enabled Ask/.test(await popup.innerText()));
  await cell('outgoing').click();
  await label(popupState(old.id), 'Masked by newer rule');
  await label(popupState(control.id), 'Enabled');
  console.log('Before expiry, popup and Rules: Ask / Enabled, older Allow / Masked by newer rule, different scope / Enabled');

  expired = true;
  await label(popupState(old.id), 'Enabled');
  await label(popupState(temporary.id), 'Expired');
  await label(popupState(control.id), 'Enabled');
  assert.equal(await popup.count(), 1, 'popup stayed open through refresh');
  await page.click('#rulesTab');
  await label(state(old.id), 'Enabled');
  await label(state(temporary.id), 'Expired');
  await label(state(control.id), 'Enabled');
  console.log('After expiry, open popup refreshed: older Allow / Enabled, temporary Deny / Expired, different scope / Enabled');

  expired = false;
  await label(state(old.id), 'Masked by newer rule');
  await page.locator('#ruleRows tr[data-id="older-allow"]').click();
  await wait('selected rule masking', async () => /Masked by newer rule/.test(await page.locator('#ruleInfo').innerText()));
  expired = true;
  await label(state(old.id), 'Enabled');
  await label(state(temporary.id), 'Expired');
  await label(state(control.id), 'Enabled');
  await wait('selected rule restored', async () => /Rule state\s+Enabled/.test(await page.locator('#ruleInfo').innerText()));
  console.log('Open Rules inventory and selected detail also refreshed from Masked by newer rule to Enabled');

  retainedAsk = true;
  await wait('fixture shows retained Ask', async () => (await snapshot()).control.policy?.snapshot?.token === 'retained-block');
  await page.click('#activityTab');
  await select();
  await cell('incoming').click();
  await label(popupState(ask.id), 'Enabled');
  await label(popup.locator('.qs-scoped').filter({ has: page.locator('[data-rule-id="ask"]') }).locator('h4'),
    'Additional whole-application rules (1)');
  await label(popup.locator('.qs-scoped').filter({ has: page.locator('[data-rule-id="scoped-incoming-control"]') }).locator('h4'),
    'Scoped rules (1)');
  const canonical = popup.locator('[data-focus="qs:remembered-choice:enabled"]');
  assert.equal(await canonical.count(), 1);
  assert.equal(await canonical.isChecked(), false);
  assert.equal(await popup.locator('.qs-block.current').count(), 1);
  remembered.action = 'allow';
  await wait('refreshed canonical Allow', async () => await popup.locator('.qs-allow.current').count() === 1);
  await label(popupState(ask.id), 'Enabled');
  await label(popup.locator('.qs-scoped').filter({ has: page.locator('[data-rule-id="ask"]') }).locator('h4'),
    'Additional whole-application rules (1)');
  assert.equal(await canonical.isChecked(), false);
  console.log('Open popup: restored Ask / Enabled under Additional whole-application rules; disabled Block and Allow remain canonical');
} finally {
  if (desktop) {
    await desktop.evaluate(({ app }) => app.exit()).catch(() => {});
    await desktop.close().catch(() => {});
  }
  for (const server of servers) server.close();
}
