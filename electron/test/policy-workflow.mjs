// Real isolated Go daemon, seeded test rule. No host rules or enforcement changes.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/policy-ui-'));
const binary = process.env.FLOWGATE_TEST_DAEMON;
const authoritative = process.env.FLOWGATE_TEST_POLICY === '1';
if (!binary || !path.isAbsolute(binary))
  throw Error('Set FLOWGATE_TEST_DAEMON to an existing daemon-monitor capable Go binary');
fs.copyFileSync(binary, path.join(run, 'flowgate'));
fs.chmodSync(path.join(run, 'flowgate'), 0o755);
const log = fs.openSync(path.join(run, 'fixture.log'), 'w');
const fixture = spawn('scripts/lab.sh', ['python3', 'electron/test/policy-daemon.py', run], {
  cwd: root,
  stdio: ['pipe', log, log],
  detached: true,
});
fs.closeSync(log);
const wait = async (fn) => {
  for (let i = 0; i < 150; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('timeout ' + fn);
};
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : null;
let app;
async function launch(readOnly = false) {
  return _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'api/s.monitor'),
      '--control',
      path.join(run, readOnly ? 'api/s.monitor' : 'api/s'),
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
  app = await launch();
  const p = await app.firstWindow();
  await p.setViewportSize({ width: 1280, height: 896 });
  await wait(() => p.locator('.policy-allow').count());
  const snap = () => p.evaluate(() => window.flowgate.snapshot());
  assert.equal((await snap()).control.enforcement.state, 'stopped');
  assert.equal((await snap()).control.permissions.can_decide, false);
  if (authoritative) {
    await wait(async () => !!(await snap()).control.policy);
    assert((await snap()).control.capabilities.includes('policy-explanations-v1'));
    assert.equal(
      (await snap()).control.policy.applications[0].incoming.enforcement.state,
      'stopped',
    );
  }
  await p.locator('.brand').evaluate((e) => (e.textContent = 'FlowGate · ISOLATED FIXTURE'));
  const before = (await snap()).control.rules[0];
  await p.locator('.policy-allow').first().click();
  assert.match(await p.locator('#infoRules').innerText(), /Stored rules · firewall stopped/);
  if (authoritative) {
    assert.match(await p.locator('#infoRules').innerText(), /Configured application policy/);
    await p.locator('.activity-policy-details summary').click();
    assert.match(await p.locator('#infoRules').innerText(), /Configured default: ask/);
    await p
      .locator('#infoRules .activity-rule-actions button')
      .filter({ hasText: 'Delete…' })
      .click();
    assert.match(
      await p.locator('#confirmText').innerText(),
      new RegExp('version ' + before.version),
    );
    await p.click('#confirmNo');
    await p.setViewportSize({ width: 860, height: 600 });
    await p.screenshot({ path: path.join(run, 'isolated-policy-narrow.png') });
    await p.setViewportSize({ width: 1280, height: 896 });
  }
  await p.screenshot({ path: path.join(run, 'isolated-policy-list.png') });
  await p.locator('.activity-rule-actions button').filter({ hasText: 'Advanced' }).first().click();
  await p.locator('#editAction').selectOption('block');
  await p.locator('#editAddress').focus();
  await p.waitForTimeout(1800);
  assert.equal(await p.locator('#editAction').inputValue(), 'block');
  assert.equal(await p.evaluate(() => document.activeElement.id), 'editAddress');
  await p.click('#previewRule');
  await wait(() => p.locator('#saveRule').isEnabled());
  await p.click('#saveRule');
  await wait(async () => (await snap()).control.rules[0].action === 'block');
  const after = (await snap()).control.rules[0];
  assert.equal(after.expires, before.expires);
  assert.equal(after.filter.application, before.filter.application);
  assert.equal(after.filter.uid, before.filter.uid);
  assert(after.version > before.version);
  if (await p.locator('#closeEditor').isVisible()) await p.click('#closeEditor');
  await wait(() => p.locator('.policy-block').count());
  if (authoritative)
    await wait(async () =>
      (await snap()).control.policy?.applications.some((a) =>
        a.incoming.rules.some((r) => r.action === 'block' && r.version === String(after.version)),
      ),
    );
  await p.screenshot({ path: path.join(run, 'isolated-saved-policy.png') });
  const denied = await p.evaluate(async () => {
    const s = await window.flowgate.snapshot();
    try {
      await window.flowgate.decide({
        generation: s.control.generation,
        id: 'not-actionable',
        action: 'allow',
        scope: 'once',
      });
      return false;
    } catch {
      return true;
    }
  });
  assert(denied);
  await app.evaluate(({ app }) => app.exit());
  await app.close();
  app = await launch(true);
  const ro = await app.firstWindow();
  await ro.locator('.brand').evaluate((e) => (e.textContent = 'FlowGate · READ-ONLY FIXTURE'));
  await wait(() => ro.locator('.policy-block').count());
  await ro.locator('.policy-block').first().click();
  assert.equal(await ro.locator('.activity-rule-actions').count(), 0);
  assert(
    await ro.evaluate(async () => {
      try {
        await window.flowgate.ruleDraft({ id: 'ui-service-fixture' });
        return false;
      } catch {
        return true;
      }
    }),
  );
  await ro.screenshot({ path: path.join(run, 'isolated-readonly-policy.png') });
  console.log('Authoritative batch verification: ' + authoritative);
  console.log(
    'PASS real isolated stopped daemon: Activity cell -> scoped list -> editor -> preview/save; version advances, identity/expiry preserved; decisions denied. Companion lists policy but hides Edit and rejects bridge draft. ' +
      run,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  fixture.stdin.end('\n');
  for (let i = 0; i < 60 && fixture.exitCode === null; i++)
    await new Promise((r) => setTimeout(r, 100));
  if (fixture.exitCode === null) process.kill(-fixture.pid, 'SIGTERM');
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
