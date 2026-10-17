// Real isolated Go daemon, seeded test rule. No host rules or enforcement changes.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/policy-ui-'));
const binary = process.env.FLOWGATE_TEST_DAEMON;
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
  const before = (await snap()).control.rules[0];
  await p.locator('.policy-allow').first().click();
  assert.match(await p.locator('#policyList').innerText(), /Stored policy only/);
  await p.screenshot({ path: path.join(run, 'isolated-policy-list.png') });
  await p.locator('#policyList button[data-rule-id]').first().click();
  await p.locator('#editAction').selectOption('block');
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
  await wait(() => ro.locator('.policy-block').count());
  await ro.locator('.policy-block').first().click();
  assert.equal(await ro.locator('#policyList button[data-rule-id]').count(), 0);
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
