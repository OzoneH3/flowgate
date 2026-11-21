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
    queue_health: {
      state: queueState, sampled_at: now,
      counter_units: { deadline_rejections: 'packets', netlink_overflow_notifications: 'notifications' },
      sessions: [{
        generation: 'a'.repeat(32), queue: 101, direction: 'both', started_at: now,
        last_issue_at: now, counters: { deadline_rejections: '3', netlink_overflow_notifications: '2' },
        gauges: { retained_packets: 1 }, saturated: false,
      }],
    },
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
  const udp = page.locator('#extendedBadge');
  await badge.waitFor({ state: 'visible', timeout: 10000 });
  assert.equal(await badge.textContent(), 'Queue pressure / errors');
  assert.equal(await badge.getAttribute('title'), 'Open queue diagnostics');
  const udpBounds = await udp.boundingBox();
  assert.ok((await badge.boundingBox()).x >= udpBounds.x + udpBounds.width);
  const tabs = page.locator('.tabs');
  const tabsTop = (await tabs.boundingBox()).y;
  await badge.click();
  const diagnostics = page.getByRole('dialog', { name: 'Queue diagnostics' });
  await diagnostics.waitFor({ state: 'visible' });
  const text = await diagnostics.textContent();
  assert.match(text, /Queue 101 · both/);
  assert.match(text, /Last issue:/);
  assert.match(text, /Packet decision deadline elapsed: 3 packets/);
  assert.match(text, /Kernel queue overflow notifications: 2 notifications/);
  assert.match(text, /Recorded totals since this queue started/);
  queueState = 'ready';
  await badge.waitFor({ state: 'hidden', timeout: 10000 });
  assert.equal(await diagnostics.textContent(), text, 'the captured warning stays readable after recovery');
  await diagnostics.getByRole('button', { name: 'Close' }).click();
  await diagnostics.waitFor({ state: 'hidden' });
  assert.equal((await tabs.boundingBox()).y, tabsTop);
  console.log('PASS queue diagnostics open after UDP and remain readable after recovery on Wayland', run);
} finally {
  if (app) await app.evaluate(({ app }) => app.exit()).catch(() => {});
  server.close();
}
