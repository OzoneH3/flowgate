// SYNTHETIC lifecycle/layout fixture. No firewall, root daemon, BPF or receiver evidence.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { _electron } from 'playwright-core';
const root = path.resolve(import.meta.dirname, '../..'),
  dir = fs.mkdtempSync(path.join(root, '.workspace/evaluation-display-'));
let generation = 'synthetic-generation',
  permit = true,
  blocked = true,
  disconnected = false,
  drop = false;
const requests = [];
const e = {
  id: '',
  request_id: '',
  state: 'stopped',
  profile: 'incoming',
  duration_seconds: 300,
  cleanup: 'not_needed',
  stops_at: '',
  reason_code: 'stopped',
  reason: 'SYNTHETIC monitoring-only daemon',
  review:
    'SYNTHETIC backend review\nIncoming only; five minutes including startup. Existing stored rules apply. New unmatched incoming connections await a decision and may be blocked. Existing connections are not all disconnected. Automatic expiry or explicit Stop performs cleanup. Closing the GUI leaves the original deadline running.',
  unsupported_outgoing: 'SYNTHETIC: only incoming evaluation is supported.',
  readiness: { state: 'not_checked', checked_at: '', checks: [] },
};
const reply = (ro) => ({
  version: 1,
  generation,
  read_only: ro,
  mode: ro ? 'host-monitor' : 'daemon-monitor',
  backend_mode: 'daemon-monitor',
  server_time: new Date().toISOString(),
  capabilities: ['explicit-administrator-v1', 'daemon-evaluation-v1'],
  permissions: {
    role: 'administrator',
    observation_scope: 'machine',
    policy_scope: 'machine',
    can_manage_rules: !ro,
    can_decide: !ro && e.state === 'active',
    can_control_evaluation: permit && !ro,
  },
  evaluation: e,
  enforcement: { state: e.state, profile: 'incoming', stops_at: e.stops_at, detail: e.reason },
  activity: {
    sequence: 1,
    collected: new Date().toISOString(),
    complete: true,
    rows: [],
    processes: {},
  },
  events: [],
  rules: [],
});
const servers = [];
let app;
const pref = path.join(root, 'build/desktop-session/electron-preferences.json'),
  saved = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
try {
  for (const ro of [false, true]) {
    const server = net.createServer((s) =>
      s.once('data', (b) => {
        const q = JSON.parse(b);
        if (disconnected && !ro) {
          s.end();
          return;
        }
        let r = reply(ro);
        if (q.operation.startsWith('evaluation-')) {
          requests.push(q);
          if (q.generation !== generation) {
            r.error = 'generation changed';
            r.error_code = 'generation_conflict';
          } else if (q.operation !== 'evaluation-readiness' && (!permit || ro)) {
            r.error = 'SYNTHETIC denied';
            r.error_code = 'forbidden';
          } else if (q.operation === 'evaluation-readiness') {
            e.readiness.state = 'checking';
            setTimeout(() => {
              e.readiness = {
                state: blocked ? 'blocked' : 'ready',
                checked_at: new Date().toISOString(),
                checks: [
                  {
                    id: 'fixture',
                    status: blocked ? 'blocked' : 'ready',
                    code: blocked ? 'fixture_blocked' : 'fixture_ready',
                    detail: blocked
                      ? 'SYNTHETIC conflicting queue prevents activation.'
                      : 'SYNTHETIC readiness passed.',
                    next: blocked ? 'Resolve the fixture blocker, then check again.' : '',
                  },
                ],
              };
            }, 150);
          } else if (q.operation === 'evaluation-start') {
            e.id = 'fixture-session';
            e.request_id = q.request_id;
            e.state = 'starting';
            e.cleanup = 'pending';
            e.stops_at = new Date(Date.now() + 300000).toISOString();
            setTimeout(() => {
              e.state = 'active';
            }, 150);
          } else if (q.operation === 'evaluation-stop') {
            e.state = 'stopping';
            setTimeout(() => {
              e.state = 'stopped';
              e.cleanup = 'confirmed';
            }, 150);
          }
          if (drop) {
            s.end();
            return;
          }
        }
        s.end(JSON.stringify(r) + '\n');
      }),
    );
    await new Promise((r) => server.listen(path.join(dir, ro ? 'm' : 'c'), r));
    servers.push(server);
  }
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(dir, 'm'),
      '--control',
      path.join(dir, 'c'),
    ],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(dir, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const p = await app.firstWindow();
  const until = async (fn, label) => {
    for (let i = 0; i < 100; i++) {
      if (await fn()) return;
      await p.waitForTimeout(100);
    }
    throw Error('Timeout ' + label);
  };
  await p.setViewportSize({ width: 1280, height: 760 });
  await p.locator('.brand').evaluate((e) => (e.textContent = 'FlowGate · SYNTHETIC evaluation'));
  await p.click('#controlMenu > summary');
  await until(
    () => p.locator('#evalStatus').evaluate((e) => e.textContent === 'Check readiness'),
    'daemon controls',
  );
  assert.equal(requests.length, 0, 'no automatic readiness or activation');
  await p.click('#evalStatus');
  await until(
    () => p.locator('#evaluationStatus').evaluate((e) => e.textContent.includes('blocked')),
    'blocked',
  );
  assert(await p.locator('#evalStart').isDisabled());
  await p.click('#evaluationChecks > summary');
  assert.match(await p.locator('#evaluationCheckText').innerText(), /fixture_blocked/);
  await p.screenshot({ path: path.join(dir, 'blocked-normal.png') });
  blocked = false;
  await p.click('#evalStatus');
  await until(() => p.locator('#evalStart').isEnabled(), 'ready');
  await p.click('#evalStart');
  assert.match(await p.locator('#confirmText').innerText(), /SYNTHETIC backend review/);
  generation = 'new-generation';
  await p.waitForTimeout(1100);
  await p.click('#confirmYes');
  await until(
    () => p.locator('#evaluationStatus').evaluate((e) => e.textContent.includes('session changed')),
    'stale confirmation',
  );
  assert.equal(requests.filter((q) => q.operation === 'evaluation-start').length, 0);
  await p.click('#evalStart');
  await p.screenshot({ path: path.join(dir, 'review-normal.png') });
  await p.click('#confirmYes');
  await until(
    () =>
      p
        .locator('#controlMenu > summary')
        .evaluate((e) => /Firewall · 4:|Firewall · 5:/.test(e.textContent)),
    'active',
  );
  const deadline = e.stops_at;
  assert(await p.locator('#evalStart').isDisabled());
  await p.setViewportSize({ width: 860, height: 600 });
  await p.screenshot({ path: path.join(dir, 'active-narrow.png') });
  await p.locator('#evalStop').focus();
  await p.waitForTimeout(1100);
  assert.equal(await p.evaluate(() => document.activeElement.id), 'evalStop');
  drop = true;
  await p.click('#evalStop');
  drop = false;
  await until(
    () =>
      p.locator('#evaluationStatus').evaluate((e) => e.textContent.includes('firewall stopped')),
    'confirmed stop after lost acknowledgement',
  );
  assert.equal(requests.filter((q) => q.operation === 'evaluation-stop').length, 1);
  assert.equal(e.stops_at, deadline);
  permit = false;
  await p.waitForTimeout(1000);
  assert(await p.locator('#evalStart').isDisabled());
  disconnected = true;
  await until(
    () => p.locator('#evaluationStatus').evaluate((e) => e.textContent.includes('unknown')),
    'disconnected',
  );
  assert(await p.locator('#evalStop').isDisabled());
  disconnected = false;
  await p.waitForTimeout(1300);
  assert.equal(requests.filter((q) => q.operation === 'evaluation-start').length, 1);
  console.log(
    'PASS SYNTHETIC Wayland readiness/blockers/review/stale tokens/active/countdown/Stop/permissions/reconnect/focus ' +
      dir,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  servers.forEach((s) => s.close());
  if (saved) fs.writeFileSync(pref, saved);
  else fs.rmSync(pref, { force: true });
}
