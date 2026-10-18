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
const run = fs.mkdtempSync(path.join(root, '.workspace/activity-rules-real-'));
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
  app.process().stderr.on('data', (b) => fs.appendFileSync(path.join(run, 'electron.log'), b));
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 656 });
  const snapshot = () => p.evaluate(() => window.flowgate.snapshot());
  await wait(async () => !!(await snapshot()).control.policy);
  let initial = await snapshot();
  assert(initial.control.capabilities.includes('activity-initiation-v1'));
  if (initial.control.rules.length) {
    assert.equal(
      process.env.FLOWGATE_TEST_RESET,
      '1',
      'Explicit reset required for test-owned prior rules',
    );
    await p.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
    for (const r of initial.control.rules) {
      await wait(() => p.locator(`.activity-rule[data-rule-id="${r.id}"]`).count());
      await p
        .locator(`.activity-rule[data-rule-id="${r.id}"]`)
        .getByRole('button', { name: 'Delete…' })
        .click();
      await p.click('#confirmYes');
      await wait(async () => !(await snapshot()).control.rules.some((x) => x.id === r.id));
    }
    initial = await snapshot();
  }
  assert.equal(initial.control.rules.length, 0);
  assert.equal(initial.control.events.length, 0);
  await p.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
  await wait(() => p.locator('#infoRules').isVisible());
  await wait(() =>
    p
      .locator('#infoRules')
      .innerText()
      .then((t) => /No explicit firewall rules/.test(t)),
  );
  const rowSelector = '#rows tr[data-id^="app:"]';
  const appID = await p.locator(rowSelector).first().getAttribute('data-id');
  async function quick(direction, action) {
    await p.locator(`#infoRules .sidebar-policy[data-direction="${direction}"]`).click();
    await p.getByLabel('Rule to create or change', { exact: true }).selectOption('new');
    await p.getByLabel('Quick rule protocol', { exact: true }).selectOption('tcp');
    await p.getByText('All addresses and ports for this protocol', { exact: true }).check();
    await p.locator(`.activity-quick .quick-${action}`).click();
    await wait(() => p.locator('#ruleEditor').isVisible());
    assert.match(await p.locator('#editorApplication').innerText(), new RegExp(direction));
    assert.equal(await p.locator('#editProtocol').inputValue(), 'tcp');
    assert(await p.locator('#ruleEditor').evaluate((e) => e.classList.contains('quick-editor')));
  }
  async function save() {
    await p.click('#previewRule');
    await wait(() => p.locator('#saveRule').isEnabled());
    await p.click('#saveRule');
    await wait(() => p.locator('#ruleEditor').isHidden());
    assert(await p.locator('#activityView').isVisible());
  }
  await quick('incoming', 'allow');
  await p.click('#previewRule');
  await wait(() => p.locator('#saveRule').isEnabled());
  await p.screenshot({ path: path.join(run, 'first-incoming-preview.png') });
  await p.click('#saveRule');
  await wait(() => p.locator('#ruleEditor').isHidden());
  await wait(async () => (await snapshot()).control.rules.length === 1);
  const first = (await snapshot()).control.rules[0];
  assert.equal(first.action, 'allow');
  assert.equal(first.filter.direction, 'incoming');
  assert.equal((await snapshot()).control.events.length, 0);
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 1),
  );
  assert(
    await p
      .locator(`.activity-rule[data-rule-id="${first.id}"]`)
      .evaluate((e) => e.classList.contains('recently-saved')),
  );
  // Add another, differently scoped incoming rule through Advanced from Activity.
  await p.locator('#infoRules .sidebar-policy[data-direction="incoming"]').click();
  await p.getByLabel('Rule to create or change', { exact: true }).selectOption('new');
  await p.locator('.activity-quick-actions button').filter({ hasText: 'Advanced' }).click();
  await wait(() => p.locator('#ruleEditor').isVisible());
  await p.selectOption('#createScope', 'custom');
  await p.fill('#editAddress', '127.0.0.1');
  await p.uncheck('#anyLocal');
  await p.fill('#editLocal', '44001');
  await p.selectOption('#editAction', 'block');
  await save();
  await wait(async () => (await snapshot()).control.rules.length === 2);
  const second = (await snapshot()).control.rules.find((r) => r.id !== first.id);
  await quick('outgoing', 'block');
  await save();
  await wait(async () => (await snapshot()).control.rules.length === 3);
  const third = (await snapshot()).control.rules.find((r) => r.filter.direction === 'outgoing');
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 3),
  );
  // Same complete application inventory for a process and for a unique-holder connection.
  await p.click('#expand');
  await wait(() =>
    p
      .locator('.connection-incoming')
      .count()
      .then((n) => n >= 2),
  );
  assert((await p.locator('.connection-outgoing').count()) >= 2);
  assert((await p.locator('.connection-neutral').count()) >= 1);
  const directionSnapshot = (await snapshot()).observation.activity.rows;
  await p.locator('#rows tr[data-id^="process:"]').first().locator('.name').click();
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 3),
  );
  assert.match(await p.locator('.activity-policy-context').innerText(), /all process instances/);
  await p.locator('.connection-incoming').first().locator('..').click();
  await wait(() =>
    p
      .locator('.activity-rule')
      .count()
      .then((n) => n === 3),
  );
  assert.match(await p.locator('.activity-policy-context').innerText(), /historical verdict/);
  await p.locator(`#rows tr[data-id="${appID}"] .name`).click();
  await p.screenshot({ path: path.join(run, 'rules-and-expanded-directions-normal.png') });
  // Quick edit changes one rule, preserves scope and expiry; other versions unchanged.
  const card = () => p.locator(`.activity-rule[data-rule-id="${first.id}"]`);
  await card().getByRole('button', { name: 'Quick set', exact: true }).click();
  await p.locator('.activity-quick .quick-block').click();
  await save();
  await wait(
    async () => (await snapshot()).control.rules.find((r) => r.id === first.id)?.action === 'block',
  );
  let current = (await snapshot()).control.rules.find((r) => r.id === first.id);
  assert.deepEqual(current.filter, first.filter);
  assert.equal(current.expires, first.expires);
  assert.equal(
    (await snapshot()).control.rules.find((r) => r.id === second.id).version,
    second.version,
  );
  await card().getByRole('button', { name: 'Disable…', exact: true }).click();
  await save();
  await wait(
    async () => (await snapshot()).control.rules.find((r) => r.id === first.id)?.disabled === true,
  );
  assert.match(await card().innerText(), /Disabled/);
  assert.equal(
    (await snapshot()).control.rules.find((r) => r.id === first.id).expires,
    first.expires,
  );
  await card().getByRole('button', { name: 'Enable…', exact: true }).click();
  await save();
  await wait(
    async () => (await snapshot()).control.rules.find((r) => r.id === first.id)?.disabled === false,
  );
  await p
    .locator(`.activity-rule[data-rule-id="${second.id}"]`)
    .getByRole('button', { name: 'Delete…' })
    .click();
  await p.click('#confirmYes');
  await wait(async () => (await snapshot()).control.rules.length === 2);
  assert((await snapshot()).control.rules.some((r) => r.id === first.id));
  assert((await snapshot()).control.rules.some((r) => r.id === third.id));
  // Preserve an unfinished draft, focus and selection through ordinary polling.
  await card().getByRole('button', { name: 'Advanced', exact: true }).click();
  await p.uncheck('#anyAddress');
  await p.fill('#editAddress', '2001:db8::123');
  await p.focus('#editAddress');
  await p.evaluate(() => document.querySelector('#editAddress').setSelectionRange(2, 9));
  await p.waitForTimeout(2300);
  assert.equal(await p.inputValue('#editAddress'), '2001:db8::123');
  assert.equal(await p.evaluate(() => document.querySelector('#editAddress').selectionStart), 2);
  await p.click('#closeEditor');
  if (await p.getByRole('button', { name: 'Close quick setter', exact: true }).count())
    await p.getByRole('button', { name: 'Close quick setter', exact: true }).click();
  await p.locator('.info-scroll').evaluate((e) => (e.scrollTop = 0));
  await p.setViewportSize({ width: 860, height: 600 });
  await p.screenshot({ path: path.join(run, 'rules-directions-narrow.png') });
  const beforeExit = await query();
  await app.evaluate(({ app }) => app.quit());
  await app.close();
  app = undefined;
  const afterExit = await query();
  assert.equal(afterExit.generation, beforeExit.generation);
  assert.equal(afterExit.enforcement.state, 'stopped');
  assert.equal(afterExit.rules.length, 2);
  app = await launch(true);
  const ro = await app.firstWindow();
  await ro.waitForSelector('#rows tr');
  await ro.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
  const error = await ro.evaluate(async (id) => {
    try {
      await window.flowgate.ruleDraft({ id });
      return '';
    } catch (e) {
      return String(e);
    }
  }, first.id);
  assert.match(error, /read.only|unavailable/i);
  assert.equal(await ro.locator('.activity-rule-actions').count(), 0);
  await ro.screenshot({ path: path.join(run, 'read-only.png') });
  fs.writeFileSync(
    path.join(run, 'result.json'),
    JSON.stringify(
      {
        backend: process.env.FLOWGATE_TEST_BACKEND_SHA,
        generation: initial.control.generation,
        first,
        second,
        third,
        remainingRules: afterExit.rules.length,
        knownIncoming: directionSnapshot.filter((r) => r.initiation?.direction === 'incoming')
          .length,
        knownOutgoing: directionSnapshot.filter((r) => r.initiation?.direction === 'outgoing')
          .length,
        enforcement: 'stopped',
        real: 'actual released daemon, native namespace TCP sockets and real rule operations; no intercepted verdicts',
      },
      null,
      2,
    ),
  );
  console.log(
    'PASS real Activity rule inventory/first create/multiple scopes/quick edit/disable/enable/conditional delete,knownTCP4/6directions,readonly,inputpolling,GUIexit; ' +
      run,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.quit()).catch(() => {});
    await app.close().catch(() => {});
  }
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
