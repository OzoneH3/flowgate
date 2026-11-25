// Real isolated Go daemon/native socket, initially empty policy and no pending event.
// Lost acknowledgement is a labelled transport fault, not simulated backend creation.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/creation-ui-'));
const binary = process.env.FLOWGATE_TEST_DAEMON;
if (!binary || !path.isAbsolute(binary))
  throw Error('FLOWGATE_TEST_DAEMON must name released creation binary');
fs.copyFileSync(binary, path.join(run, 'flowgate'));
fs.chmodSync(path.join(run, 'flowgate'), 0o755);
const log = fs.openSync(path.join(run, 'fixture.log'), 'w');
const fixture = spawn('scripts/lab.sh', ['python3', 'electron/test/policy-daemon.py', run], {
  cwd: root,
  env: { ...process.env, FLOWGATE_EMPTY_POLICY: '1' },
  stdio: ['pipe', log, log],
  detached: true,
});
fs.closeSync(log);
const wait = async (fn) => {
  for (let i = 0; i < 200; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('timeout ' + fn);
};
const prefs = path.join(root, 'build/desktop-session/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : null;
let app,
  proxy,
  drop = false,
  holdPreview = false,
  releasePreview,
  saves = 0;
async function launch(readOnly = false) {
  return _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'api/s.monitor'),
      '--control',
      path.join(run, readOnly ? 'api/s.monitor' : 'proxy'),
    ],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
}
try {
  fs.writeFileSync(prefs, '{}');
  await wait(() => fs.existsSync(path.join(run, 'ready')));
  proxy = net.createServer((client) => {
    let q = '';
    client.on('data', (b) => {
      q += b;
      if (!q.includes('\n')) return;
      client.removeAllListeners('data');
      const req = JSON.parse(q),
        isSave = req.operation === 'observed-rule-save';
      if (isSave) saves++;
      const shouldDrop = drop && isSave;
      const shouldHold = holdPreview && req.operation === 'observed-rule-preview';
      if (shouldHold) holdPreview = false;
      const upstream = net.createConnection(path.join(run, 'api/s'));
      upstream.on('connect', () => upstream.write(q));
      let reply = '';
      upstream.on('data', (b) => {
        reply += b;
        if (reply.includes('\n')) {
          if (shouldDrop) {
            drop = false;
            client.destroy();
          } else if (shouldHold) {
            releasePreview = () => client.end(reply);
          } else client.end(reply);
          upstream.destroy();
        }
      });
      upstream.on('error', () => client.destroy());
      client.on('close', () => upstream.destroy());
    });
  });
  await new Promise((r) => proxy.listen(path.join(run, 'proxy'), r));
  app = await launch();
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 896 });
  const snapshot = () => p.evaluate(() => window.flowgate.snapshot());
  await wait(async () => !!(await snapshot()).control.policy);
  assert((await snapshot()).control.capabilities.includes('observed-rule-create-v1'));
  assert.equal((await snapshot()).control.rules.length, 0);
  assert.equal((await snapshot()).control.events.length, 0);
  await p.locator('.brand').evaluate((e) => (e.textContent = 'FlowGate · ISOLATED CREATION'));
  async function open(direction) {
    await p.click('#activityTab');
    await p.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
    await p.locator(`#infoRules .sidebar-policy[data-direction="${direction}"]`).click();
    await wait(() => p.locator('.quick-popup').isVisible());
    if (await p.locator('[data-focus=qs-new]').count()) await p.click('[data-focus=qs-new]');
    await p.click('[data-focus=qs-advanced]');
    await p.waitForTimeout(100);
    if (!(await p.locator('#ruleEditor').isVisible()))
      console.log('OPEN FEEDBACK', await p.locator('#feedback').innerText());
    await wait(() => p.locator('#ruleEditor').isVisible());
    assert(await p.locator('#saveRule').isDisabled());
    await p.selectOption('#createScope', 'application');
  }
  async function preview() {
    await wait(() => p.locator('#saveRule').isEnabled());
    assert.match(await p.locator('#editorApplication').innerText(), /Verified/);
  }
  await open('incoming');
  await p.selectOption('#editAction', 'allow');
  await preview();
  assert.match(
    await p.locator('#scopeSummary').innerText(),
    /Allow incoming TCP connections.*any remote address/,
  );
  assert.match(await p.locator('#previewValidity').innerText(), /valid for \d+s/);
  assert(await p.locator('#editAddress').isDisabled());
  assert(await p.locator('#anyAddress').isChecked());
  await p.screenshot({ path: path.join(run, 'first-rule-preview.png') });
  holdPreview = true;
  await p.selectOption('#editAction', 'block');
  await wait(() => releasePreview);
  assert(await p.locator('#saveRule').isDisabled());
  await p.selectOption('#editAction', 'allow');
  assert(await p.locator('#saveRule').isDisabled());
  releasePreview();
  await preview();
  assert.match(await p.locator('#scopeSummary').innerText(), /Allow incoming TCP connections/);
  assert.equal(saves, 0, 'automatic preview never submits a save');
  await p.locator('#editAction').focus();
  await p.waitForTimeout(1600);
  assert.equal(await p.evaluate(() => document.activeElement.id), 'editAction');
  assert.equal(await p.locator('#editAction').inputValue(), 'allow');
  await p.setViewportSize({ width: 860, height: 600 });
  await p.screenshot({ path: path.join(run, 'first-rule-preview-narrow.png') });
  await p.setViewportSize({ width: 1280, height: 896 });
  console.log('Waiting for actual 30-second preview expiry in isolated daemon…');
  await p.waitForTimeout(31000);
  assert(await p.locator('#saveRule').isDisabled());
  assert.equal(await p.locator('#editAction').inputValue(), 'allow');
  assert.equal(await p.locator('#createScope').inputValue(), 'application');
  assert.equal(await p.locator('#previewRule').innerText(), 'Refresh preview');
  assert.match(await p.locator('#previewValidity').innerText(), /draft kept/);
  await p.click('#previewRule');
  await preview();
  await p.click('#saveRule');
  await wait(async () => (await snapshot()).control.rules.length === 1);
  const incoming = (await snapshot()).control.rules[0];
  assert.equal(incoming.filter.direction, 'incoming');
  assert.equal(incoming.action, 'allow');
  assert.equal((await snapshot()).control.events.length, 0);
  await wait(async () =>
    (await snapshot()).control.policy?.applications.some((a) =>
      a.incoming.rules.some((r) => r.id === incoming.id),
    ),
  );
  assert(await p.locator('#activityView').isVisible());
  await p.click('#rulesTab');
  assert(await p.locator('#rulesView').isVisible());
  assert.equal(
    await p.locator('#ruleRows tr[aria-selected=true]').getAttribute('data-id'),
    incoming.id,
  );
  await p.click('#editRule');
  await wait(() => p.locator('#ruleEditor').isVisible());
  await p.selectOption('#editAction', 'block');
  await wait(() => p.locator('#saveRule').isEnabled());
  await p.click('#saveRule');
  await wait(
    async () =>
      (await snapshot()).control.rules.find((r) => r.id === incoming.id)?.action === 'block',
  );
  const edited = (await snapshot()).control.rules.find((r) => r.id === incoming.id);
  assert.equal(edited.expires, incoming.expires);
  assert(edited.version > incoming.version);
  await open('outgoing');
  await p.selectOption('#createScope', 'custom');
  await p.uncheck('#anyAddress');
  await p.fill('#editAddress', '127.0.0.1');
  await p.uncheck('#anyRemote');
  await p.fill('#editRemote', '443');
  await preview();
  await p.click('#saveRule');
  await wait(async () => (await snapshot()).control.rules.length === 2);
  const outgoing = (await snapshot()).control.rules.find((r) => r.filter.direction === 'outgoing');
  assert.equal(outgoing.filter.remote_port, 443);
  await p.click('#rulesTab');
  await p.locator(`#ruleRows tr[data-id="${incoming.id}"]`).click();
  await p.click('#deleteRule');
  await p.click('#confirmYes');
  await wait(async () => !(await snapshot()).control.rules.some((r) => r.id === incoming.id));
  // One real save commits; proxy drops only its acknowledgement. Reconcile sends list, never save.
  await open('incoming');
  await p.selectOption('#editProtocol', 'udp');
  await p.selectOption('#editAction', 'allow');
  await preview();
  const count = saves;
  drop = true;
  await p.click('#saveRule');
  await wait(() => p.locator('#reconcileRule').isVisible());
  assert.equal(saves, count + 1);
  assert(await p.locator('#saveRule').isDisabled());
  await p.click('#reconcileRule');
  await wait(() => p.locator('#ruleEditor').isHidden());
  assert.equal(saves, count + 1);
  assert.equal((await snapshot()).control.rules.length, 2);
  await p.screenshot({ path: path.join(run, 'created-rules.png') });
  await p.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
  await p.locator('[data-focus="add-rule"]').click();
  await p.locator('#ruleEditor').waitFor();
  await p.selectOption('#createScope', 'custom');
  assert(await p.locator('#anyAddress').isChecked(), 'custom scope preserves Any address for port-only rules');
  await wait(async () => /Specify an address or port/.test(await p.locator('#editorFeedback').innerText()));
  assert(await p.locator('#saveRule').isDisabled(), 'custom scope still needs an endpoint constraint');
  const saveBorder = () => p.locator('#saveRule').evaluate((button) => {
    const [red, green] = getComputedStyle(button).borderTopColor.match(/\d+/g).map(Number);
    return green > red ? 'green' : 'red';
  });
  assert.equal(await saveBorder(), 'red');
  await p.uncheck('#anyLocal');
  await p.fill('#editLocal', '5');
  await preview();
  assert.equal(await saveBorder(), 'green');
  assert.match(await p.locator('#scopeSummary').innerText(), /any remote address.*local port 5/);
  await p.click('#saveRule');
  await wait(() => p.locator('#ruleEditor').isHidden());
  const portOnly = (await snapshot()).control.rules.find((r) => r.filter.local_port === 5);
  assert.equal(portOnly?.filter.direction, 'incoming');
  assert.equal(portOnly.filter.remote_address, '*');
  assert.equal(portOnly.filter.remote_port || 0, 0);
  await app.evaluate(({ app }) => app.exit());
  await app.close();
  app = await launch(true);
  const ro = await app.firstWindow();
  await wait(() => ro.locator('.policy-cell').count());
  await ro.locator('#rows tr[data-id^="app:"]').first().locator('.name').click();
  assert.equal(await ro.locator('.activity-rule-actions').count(), 0);
  const denied = await ro.evaluate(async () => {
    const s = await window.flowgate.snapshot(),
      r = s.observation.activity.rows[0];
    try {
      await window.flowgate.ruleDraft({
        observed: {
          generation: s.control.generation,
          row_id: r.id,
          process_id: r.owners[0],
          direction: 'incoming',
        },
      });
      return false;
    } catch {
      return true;
    }
  });
  assert(denied);
  console.log(
    'PASS real isolated first incoming/outgoing creation, authoritative policy appearance, edit+conditional delete, actual preview expiry, field/focus preservation, readonly denial. Lost-ACK transport fault reconciled real save with no replay. ' +
      run,
  );
} catch (error) {
  console.error('Original workflow failure:', error);
  if (app && app.windows().length) {
    const page = await app.firstWindow();
    console.log('UI failure:', await page.locator('body').innerText());
    await page.screenshot({ path: path.join(run, 'failure.png') });
  }
  throw error;
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  proxy?.close();
  fixture.stdin.end('\n');
  for (let i = 0; i < 60 && fixture.exitCode === null; i++)
    await new Promise((r) => setTimeout(r, 100));
  if (fixture.exitCode === null) process.kill(-fixture.pid, 'SIGTERM');
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
