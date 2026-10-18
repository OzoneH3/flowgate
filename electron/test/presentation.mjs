// SYNTHETIC state fixtures only. No enforcement, attribution or packet evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/presentation-'));
const application = {
  key: 'fixture',
  revision: 'r',
  name: 'SYNTHETIC Firefox',
  executable: '/usr/lib/firefox/firefox',
};
const process = { id: 'p', pid: 12345, uid: 1000, application, executable: application.executable };
const now = Date.now();
const rule = (id, action, extra = {}) => ({
  id,
  action,
  version: 0,
  filter: {
    application: 'fixture',
    revision: 'r',
    uid: 1000,
    direction: 'incoming',
    protocol: 'tcp',
    remote_address: '2001:db8::1',
    local_port: 443,
    remote_port: 0,
  },
  expires: '0001-01-01T00:00:00Z',
  disabled: false,
  ...extra,
});
let rules = [
  rule('a', 'allow'),
  rule('b', 'allow'),
  rule('c', 'block'),
  rule('d', 'allow', { disabled: true }),
  rule('e', 'block', { expires: new Date(now - 1000).toISOString() }),
];
let mutations = 0;
const servers = [];
for (const role of ['observer', 'control']) {
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw);
      if (q.operation !== 'list') mutations++;
      s.end(
        JSON.stringify({
          version: 1,
          generation: 'SYNTHETIC-' + role,
          mode: role === 'observer' ? 'host-monitor' : 'isolated-lab',
          read_only: true,
          server_time: new Date().toISOString(),
          rules: role === 'control' ? rules : [],
          events:
            role === 'control'
              ? [
                  {
                    id: 'fixture-request',
                    state: 'awaiting-decision',
                    deadline: new Date(now + 120000).toISOString(),
                    flow: {
                      direction: 'outgoing',
                      protocol: 'tcp',
                      local: '[::1]:40000',
                      remote: '[2001:db8::1]:443',
                    },
                    attribution: {
                      status: 'directly-associated',
                      reason: 'SYNTHETIC fixture, no real pending connection',
                      application,
                      owners: [process],
                      visibility_complete: true,
                    },
                    scope_previews: { once: 'SYNTHETIC scope; read-only fixture' },
                  },
                ]
              : [],
          activity:
            role === 'observer'
              ? {
                  sequence: 1,
                  collected: new Date().toISOString(),
                  complete: true,
                  issues: ['SYNTHETIC PRESENTATION FIXTURE'],
                  processes: { p: process },
                  rows: [
                    {
                      id: 'fixture-socket',
                      owners: ['p'],
                      state: 'Established',
                      socket: {
                        protocol: 'tcp',
                        local: '[::1]:40000',
                        remote: '[2001:db8::1]:443',
                        uid: 1000,
                        state: 1,
                      },
                      traffic: { available: false, reason: 'Synthetic fixture: no measurements' },
                    },
                  ],
                }
              : undefined,
        }) + '\n',
      );
    }),
  );
  await new Promise((r) => server.listen(path.join(run, role + '.sock'), r));
  servers.push(server);
}
const wait = async (fn) => {
  for (let i = 0; i < 100; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('timeout ' + fn);
};
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  old = fs.existsSync(prefs) ? fs.readFileSync(prefs) : null;
let app;
try {
  fs.writeFileSync(prefs, '{}');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 'observer.sock'),
      '--control',
      path.join(run, 'control.sock'),
    ],
    cwd: root,
    env: {
      ...globalThis.process.env,
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 1280, height: 896 });
  await wait(async () =>
    (
      await page
        .locator('#rows tr[data-id^="app:"] .status-slot[data-direction=incoming]')
        .first()
        .getAttribute('aria-label')
    ).includes('Mixed'),
  );
  const row = page.locator('#rows tr[data-id^="app:"]').first();
  await row.locator('.policy-cell').first().click();
  await wait(() => page.locator('.quick-popup').isVisible());
  await page.keyboard.press('Escape');
  await wait(() => page.locator('.rule-details summary').isVisible());
  await page.locator('.rule-details summary').click();
  assert.equal(await page.locator('#infoRules .activity-rule').count(), 5);
  assert.match(await page.locator('#infoRules').innerText(), /Deny[\s\S]*Expired/);
  assert.match(await page.locator('#infoRules').innerText(), /Allow[\s\S]*Disabled/);
  await wait(() => row.locator('img').count());
  await page.screenshot({ path: path.join(run, 'synthetic-scoped-rules.png') });
  await page.keyboard.press('Escape');
  // No new Activity sequence: only control inventory changes. Selection must survive.
  rules = [rule('new', 'block')];
  await wait(async () => (await row.locator('.status-slot.tone-block').count()) === 1);
  assert.equal(await row.getAttribute('aria-selected'), 'true');
  await page.click('#requestsTab');
  await page.locator('#requestRows tr').first().click();
  await page.locator('.open-prompt').click();
  await wait(() => app.windows().some((p) => p !== page));
  const permission = app.windows().find((p) => p !== page);
  await wait(() => permission.locator('.route-application img').count());
  assert(await permission.locator('#allow').isDisabled());
  await permission.screenshot({ path: path.join(run, 'synthetic-installed-icon-prompt.png') });
  await permission.evaluate(() => window.flowgate.dismissPrompt());
  await page.click('#activityTab');
  await page.setViewportSize({ width: 860, height: 600 });
  await page.screenshot({ path: path.join(run, 'synthetic-narrow.png') });
  servers[1].close();
  await wait(async () => (await page.locator('.status-slot.tone-block').count()) === 0);
  assert.equal(await page.locator('.status-slot.tone-block').count(), 0);
  assert.equal(mutations, 0);
  console.log(
    'PASS synthetic multiple scoped rules, disabled/expired/permanent, control-only update/selection, installed prompt icon/read-only controls, disconnect clears stale indicators; no mutations. ' +
      run,
  );
} finally {
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  for (const server of servers) server.close();
  if (old) fs.writeFileSync(prefs, old);
  else fs.rmSync(prefs, { force: true });
}
