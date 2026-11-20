// Verify that a live queue warning stays above the panes and clears in place.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/queue-health-'));
const endpoint = path.join(run, 'api');
let queueState = 'pressure';
const server = net.createServer((socket) => socket.once('data', () => {
  const now = new Date().toISOString();
  socket.end(JSON.stringify({
    version: 1, generation: 'fixture', server_time: now,
    mode: 'daemon-monitor', capabilities: ['explicit-administrator-v1'],
    permissions: {
      role: 'administrator', observation_scope: 'machine', policy_scope: 'machine',
      can_manage_rules: false, can_decide: false,
    },
    read_only: false,
    enforcement: { state: 'active', profile: 'both' },
    queue_health: { state: queueState, sampled_at: now },
    events: [], rules: [],
  }) + '\n');
}));
await new Promise((resolve) => server.listen(endpoint, resolve));
let app;
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', path.join(root, 'electron'),
      '--observer', endpoint, '--control', endpoint],
    env: { ...process.env, XDG_CACHE_HOME: path.join(run, 'cache') },
  });
  const page = await app.firstWindow();
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows().find((window) => window.getTitle() === 'FlowGate')?.show(),
  );
  await page.setViewportSize({ width: 1280, height: 656 });
  const badge = page.locator('.toolbar > #queueHealth');
  await badge.waitFor({ state: 'visible', timeout: 10000 });
  assert.equal(await badge.textContent(), 'Queue pressure / errors');
  assert.match(await badge.getAttribute('title'), /Recent queue rejections/);
  const info = page.locator('#activityView > aside > h2');
  const infoTop = (await info.boundingBox()).y;
  await page.screenshot({ path: path.join(run, 'warning.png') });
  queueState = 'ready';
  await badge.waitFor({ state: 'hidden', timeout: 10000 });
  assert.equal((await info.boundingBox()).y, infoTop);
  console.log('PASS queue warning shown and cleared in place on Wayland', run);
} finally {
  if (app) await app.evaluate(({ app }) => app.exit()).catch(() => {});
  server.close();
}
