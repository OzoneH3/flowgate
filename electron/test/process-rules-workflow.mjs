// Real released held namespace fixture, exclusively assigned to this UI driver.
// Does not start/stop fixture; owner cleans only after explicit DONE.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const endpoint = process.env.FLOWGATE_TEST_ENDPOINT;
if (!endpoint?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'))
  throw Error('Disposable workspace endpoint required');
const run = fs.mkdtempSync(path.join(root, '.workspace/process-rules-real-'));
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
let app;
const wait = async (fn) => {
  for (let end = Date.now() + 20000; Date.now() < end;) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timeout: ' + fn);
};
const query = () =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(endpoint);
    let b = '';
    s.on('connect', () => s.write('{"version":1,"operation":"list"}\n'));
    s.on('data', (c) => {
      b += c;
      if (b.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(b));
      }
    });
    s.on('error', reject);
  });
const launch = async (ro = false) =>
  _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      endpoint + '.monitor',
      '--control',
      ro ? endpoint + '.monitor' : endpoint,
      '--width',
      '1280',
      '--height',
      '656',
    ],
    env: {
      ...process.env,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
try {
  fs.writeFileSync(prefs, '{}');
  app = await launch();
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 656 });
  const snapshot = () => p.evaluate(() => window.flowgate.snapshot());
  await wait(async () => {
    const s = await snapshot();
    return (
      s.control.connected &&
      s.control.policy?.processes?.length >= 2 &&
      s.observation.activity?.rows.length
    );
  });
  let initial = await snapshot();
  if (initial.control.rules.length) {
    assert.equal(
      process.env.FLOWGATE_TEST_RESET,
      '1',
      'Explicit reset required for own prior fixture rules',
    );
    await p.click('#rulesTab');
    for (const rule of initial.control.rules) {
      await p.locator(`#ruleRows tr[data-id="${rule.id}"]`).click();
      await p.click('#deleteRule');
      await p.click('#confirmYes');
      await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === rule.id));
    }
    await p.click('#activityTab');
    initial = await snapshot();
  }
  assert(initial.control.capabilities.includes('process-instance-rules-v1'));
  assert.equal(initial.control.rules.length, 0);
  const groups = new Map();
  for (const target of initial.control.policy.processes.filter((x) => x.state === 'active')) {
    const key = target.application_ref;
    groups.set(key, [...(groups.get(key) || []), target]);
  }
  const pair = [...groups.values()].find((g) => g.length >= 2);
  assert(pair, 'Two supported same-application fixture processes required');
  const a = pair.find((p) => p.process_id === process.env.FLOWGATE_TARGET_PROCESS_ID) || pair[0],
    b = pair.find((p) => p.process_id !== a.process_id);
  const select = async (id) => {
    await p.click('#expand');
    await p.locator(`#rows tr[data-id^="process:"][data-id$=":${id}"] .name`).click();
    await wait(
      async () =>
        (await p.locator('.sidebar-process-policy').first().innerText()) !== 'Unavailable',
    );
  };
  const quick = async (scope, action) => {
    await p.locator('.sidebar-process-policy[data-direction=incoming]').click();
    assert.equal(await p.getByLabel('Rule target', { exact: true }).inputValue(), 'process');
    if (scope === 'application')
      await p.getByLabel('Rule target', { exact: true }).selectOption(scope);
    await p.getByLabel('Rule to create or change', { exact: true }).selectOption('new');
    await p.getByLabel('Quick rule protocol', { exact: true }).selectOption('udp');
    await p.getByLabel('Quick rule expiry', { exact: true }).selectOption('permanent');
    await p.getByText('All addresses and ports for this protocol', { exact: true }).check();
    await p.locator(`.quick-${action}`).click();
    await wait(() => p.locator('#ruleEditor').isVisible());
  };
  const save = async () => {
    await p.click('#previewRule');
    await wait(() => p.locator('#saveRule').isEnabled());
    await p.click('#saveRule');
    await wait(() => p.locator('#ruleEditor').isHidden());
  };
  await select(a.process_id);
  await quick('process', 'allow');
  assert.match(await p.locator('#editorApplication').innerText(), /This process/);
  await p.click('#previewRule');
  await wait(() => p.locator('#saveRule').isEnabled());
  await p.screenshot({ path: path.join(run, 'process-preview.png') });
  await p.click('#saveRule');
  await wait(() => p.locator('#ruleEditor').isHidden());
  await wait(async () => (await snapshot()).control.rules.length === 1);
  const processRule = (await snapshot()).control.rules[0];
  assert(processRule.filter.process);
  assert.equal(processRule.filter.process.pid, a.target.pid);
  assert.equal(processRule.schema, 3);
  await select(b.process_id);
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 0),
  );
  assert.match(await p.locator('#infoRules').innerText(), /No explicit firewall rules/);
  await p.locator('#rows tr[data-id^="app:"] .name').first().click();
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 0),
  );
  await select(a.process_id);
  await quick('application', 'block');
  assert.match(await p.locator('#editorApplication').innerText(), /Application/);
  await save();
  await wait(async () => (await snapshot()).control.rules.length === 2);
  const applicationRule = (await snapshot()).control.rules.find((r) => !r.filter.process);
  assert(applicationRule);
  await select(b.process_id);
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 1),
  );
  assert.equal(await p.locator(`.activity-rule[data-rule-id="${processRule.id}"]`).count(), 0);
  await select(a.process_id);
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 2),
  );
  await p.keyboard.press('Escape');
  await p.screenshot({ path: path.join(run, 'process-with-application-normal.png') });
  const card = () => p.locator(`.activity-rule[data-rule-id="${processRule.id}"]`);
  await card().getByRole('button', { name: 'Quick set', exact: true }).click();
  await p.locator('.quick-block').click();
  await save();
  await wait(
    async () =>
      (await snapshot()).control.rules.find((r) => r.id === processRule.id)?.action === 'block',
  );
  let updated = (await snapshot()).control.rules.find((r) => r.id === processRule.id);
  assert.deepEqual(updated.filter.process, processRule.filter.process);
  assert.equal(
    (await snapshot()).control.rules.find((r) => r.id === applicationRule.id).version,
    applicationRule.version,
  );
  await card().getByRole('button', { name: 'Disable…', exact: true }).click();
  await save();
  await wait(() =>
    card()
      .innerText()
      .then((t) => t.includes('Disabled')),
  );
  await card().getByRole('button', { name: 'Enable…', exact: true }).click();
  await save();
  await wait(() =>
    card()
      .innerText()
      .then((t) => t.includes('Enabled')),
  );
  await card().getByRole('button', { name: 'Delete…', exact: true }).click();
  await p.click('#confirmYes');
  await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === processRule.id));
  assert((await snapshot()).control.rules.some((r) => r.id === applicationRule.id));
  // Recreate one owned rule, then leave a draft open while owner-command exits target.
  await wait(
    async () =>
      !(await snapshot()).control.policy.processes.find(
        (x) => x.process_id === a.process_id && x.state === 'active',
      )?.incoming.rules.length,
  );
  await quick('process', 'allow');
  await save();
  await wait(async () => (await snapshot()).control.rules.length === 2);
  const finalRule = (await snapshot()).control.rules.find((r) => r.filter.process);
  await quick('process', 'block');
  await p.click('#editorMode');
  await p.selectOption('#createScope', 'custom');
  await p.fill('#editAddress', '2001:db8::123');
  await p.locator('#editAddress').evaluate((e) => {
    e.focus();
    e.setSelectionRange(2, 6);
  });
  await p.waitForTimeout(1700);
  assert.equal(await p.locator('#editAddress').evaluate((e) => e.selectionStart), 2);
  assert.equal(await p.evaluate(() => document.activeElement?.id), 'editAddress');
  const commandFile = process.env.FLOWGATE_EXIT_COMMAND_FILE,
    command = process.env.FLOWGATE_EXIT_COMMAND;
  assert(
    commandFile?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'),
    'Owned exit command file required',
  );
  assert(command, 'Exact owner-provided exit command required');
  fs.writeFileSync(commandFile, command + '\n');
  await wait(
    async () => (await snapshot()).control.rule_states?.[finalRule.id]?.state === 'inactive',
  );
  await wait(() => p.locator('#previewRule').isDisabled());
  assert(await p.locator('#saveRule').isDisabled());
  assert.equal(await p.inputValue('#editAddress'), '2001:db8::123');
  await p.click('#closeEditor');
  await p.keyboard.press('Escape');
  await wait(() =>
    p
      .locator('#infoRules')
      .innerText()
      .then((t) => /inactive|exited/i.test(t)),
  );
  await p.screenshot({ path: path.join(run, 'process-exited-normal.png') });
  await p.setViewportSize({ width: 860, height: 600 });
  await p.screenshot({ path: path.join(run, 'process-exited-narrow.png') });
  const before = await query();
  await app.evaluate(({ app }) => app.exit());
  await app.close().catch(() => {});
  app = undefined;
  const after = await query();
  assert.equal(after.generation, before.generation);
  assert.equal(after.enforcement.state, 'stopped');
  fs.writeFileSync(
    path.join(run, 'result.json'),
    JSON.stringify(
      {
        backend: process.env.FLOWGATE_TEST_BACKEND_SHA,
        generation: after.generation,
        target: a,
        sibling: b,
        processRule: finalRule,
        applicationRule,
        remaining: after.rules.length,
        enforcement: after.enforcement.state,
        evidence:
          'Real sandboxed Wayland + isolated daemon/native process CRUD/exit. Receiver evidence supplied separately by backend owner.',
      },
      null,
      2,
    ),
  );
  console.log(
    'PASS real two-process distinct policy, app fallback, explicit target, exact edit/disable/enable/delete, exit/stale draft, polling focus, normal/narrow, independent daemon survives. ' +
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
  if (old) fs.writeFileSync(prefs, old);
  else if (fs.existsSync(prefs)) fs.unlinkSync(prefs);
}
