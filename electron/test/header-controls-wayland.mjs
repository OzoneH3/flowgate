// Exercise the About dialog and collector controls against a private synthetic daemon.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/header-ui-'));
const endpoint = path.join(run, 'api');
const gui = path.join(run, 'electron');
const revision = 'ab'.repeat(20);
fs.cpSync(path.join(root, 'electron/dist'), path.join(gui, 'dist'), { recursive: true });
fs.copyFileSync(path.join(root, 'electron/package.json'), path.join(gui, 'package.json'));
fs.writeFileSync(path.join(run, 'matched-manifest.json'), JSON.stringify({
  source: revision,
  version: '0.1.0-rc.7',
  built_at: '2026-11-20T09:30:00Z',
  files: {
    'electron/dist/main.cjs': crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(gui, 'dist/main.cjs'))).digest('hex'),
  },
}));

let udp = 'disabled';
let partial = false;
let activityAvailable = true;
const operations = [];
const serve = (readonly) => net.createServer((socket) => socket.once('data', (data) => {
  const { operation } = JSON.parse(data);
  if (!readonly && ['traffic-start', 'traffic-stop'].includes(operation)) {
    operations.push(operation);
    udp = operation === 'traffic-start' ? 'active' : 'disabled';
    partial = false;
  }
  const now = new Date().toISOString();
  socket.end(JSON.stringify({
    version: 1, generation: 'fixture', server_time: now,
    mode: readonly ? 'host-monitor' : 'daemon-monitor',
    backend_mode: 'daemon-monitor',
    capabilities: ['explicit-administrator-v1', 'continuous-firewall-v1',
      'daemon-evaluation-v1', 'daemon-udp-monitor-v1'],
    permissions: {
      role: 'administrator', observation_scope: 'machine', policy_scope: 'machine',
      can_manage_rules: false, can_decide: false, can_control_traffic: !readonly,
      can_view_measurements: true,
    },
    read_only: readonly,
    enforcement: { state: 'active', profile: 'both' },
    protection: {
      id: 'a'.repeat(32), request_id: '', gui_required: false, state: 'active',
      desired_mode: 'both', profile: 'both', cleanup: 'pending', readiness: { state: 'ready' },
      reason: 'Both directions are being protected.',
    },
    build: { source: revision, modified: false },
    traffic_monitor: {
      state: udp, available: true, partial, scope: 'machine',
      generation: 'collector', reason_code: udp, reason: 'Test collector.',
    },
    ...(readonly && activityAvailable
      ? { activity: { sequence: 1, collected: now, complete: false, processes: {}, rows: [] } }
      : {}),
    events: [], rules: [],
  }) + '\n');
}));
const control = serve(false), observer = serve(true);
await new Promise((resolve) => control.listen(endpoint, resolve));
await new Promise((resolve) => observer.listen(endpoint + '.monitor', resolve));

let app;
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', gui, '--observer', endpoint + '.monitor', '--control', endpoint],
    env: { ...process.env, XDG_CACHE_HOME: path.join(run, 'cache') },
  });
  const page = await app.firstWindow();
  page.setDefaultTimeout(10000);
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows().find((window) => window.getTitle() === 'FlowGate')?.show(),
  );
  const firewallBadge = page.locator('#firewallMenuStatus[aria-label="Firewall: Both"]');
  await firewallBadge.waitFor();
  assert.equal(await page.locator('.toolbar').getByText(revision.slice(0, 7)).count(), 0);
  assert.equal(await page.locator('.toolbar').getByText('Activity · machine', { exact: false }).count(), 0);
  await page.locator('#footerSummary').getByText('Partial visibility', { exact: false }).waitFor();
  assert.match(await page.locator('#info').textContent(), /Machine · current network namespace.*Partial visibility/s);
  const help = page.locator('#helpMenu > summary');
  const helpOpen = () => help.evaluate((node) => node.parentElement.open);
  await help.hover();
  await page.mouse.down();
  assert.equal(await helpOpen(), true, 'Help opens before mouse-up');
  await page.mouse.up();
  assert.equal(await helpOpen(), true, 'mouse-up does not toggle Help again');
  await page.mouse.down();
  assert.equal(await helpOpen(), false, 'a second press closes Help');
  await page.mouse.up();
  await help.press('Enter');
  assert.equal(await helpOpen(), true, 'keyboard activation still opens Help');
  const settings = page.locator('.toolbar > #settingsMenu');
  const settingsLabel = settings.locator(':scope > summary');
  assert.equal(await settingsLabel.textContent(), 'Settings');
  await settingsLabel.hover();
  await page.mouse.down();
  assert.equal(await helpOpen(), false, 'pressing another heading closes the previous menu');
  assert.equal(await settings.evaluate((node) => node.open), true);
  await page.mouse.up();
  assert.equal(await settings.locator('.desktop-menu').count(), 0);
  for (const id of ['activitySource', 'displayUnits', 'decisionTimeoutSeconds', 'defaultPriority', 'keepInTray'])
    await settings.locator('#' + id).waitFor({ state: 'visible' });
  await help.click();
  const iconsRow = await page.getByRole('button', { name: 'Icons and symbols' }).boundingBox();
  const aboutRow = await page.getByRole('button', { name: 'About FlowGate' }).boundingBox();
  assert.equal(iconsRow.x, aboutRow.x);
  assert.equal(iconsRow.width, aboutRow.width);
  assert.ok(aboutRow.y >= iconsRow.y + iconsRow.height);
  await page.getByRole('button', { name: 'About FlowGate' }).click();
  await page.locator('#aboutBuild').getByText('Version: 0.1.0-rc.7', { exact: false }).waitFor();
  const about = await page.locator('#aboutBuild').textContent();
  assert.ok(about.includes('GUI revision: ' + revision));
  assert.ok(about.includes('Daemon build: ' + revision));
  await page.locator('#aboutFlowGate').getByRole('button', { name: 'Close' }).click();

  await help.click();
  await page.getByRole('button', { name: 'Icons and symbols' }).click();
  const guide = page.getByRole('dialog', { name: 'Icons and symbols' });
  await guide.waitFor({ state: 'visible' });
  assert.equal(await guide.getByRole('heading', { name: 'Connection observations' }).count(), 1);
  assert.equal(await guide.locator('.status-slot:not(.upload-configured) svg').count(), 5);
  assert.doesNotMatch(await guide.textContent(), /Quota/i);
  assert.equal(await guide.locator('.blocker-glyph.tone-allow').textContent(), '✓');
  assert.match(await guide.textContent(), /Partial coverage/);
  await page.waitForFunction(() =>
    [...document.querySelectorAll('#iconGuide img')].every((icon) => icon.naturalWidth > 0),
  );
  await guide.screenshot({ path: path.join(run, 'icons-and-symbols.png') });
  await page.keyboard.press('Escape');
  await guide.waitFor({ state: 'hidden' });
  await page.waitForFunction(() => document.activeElement === document.querySelector('#helpMenu > summary'));

  await firewallBadge.hover();
  await page.mouse.down();
  assert.equal(await page.locator('#controlMenu').evaluate((node) => node.open), true);
  await page.mouse.up();
  assert.equal(await page.locator('#controlMenu > summary').textContent(), 'FW: Both');
  const open = (id) => page.locator('.toolbar > #' + id).evaluate((node) => node.open);
  const udpMenu = page.locator('#extendedBadge');
  await udpMenu.press('Enter');
  assert.equal(await open('monitoringMenu'), true, 'keyboard opens the UDP menu');
  assert.equal(await open('controlMenu'), false, 'keyboard closes the previous menu');
  await page.keyboard.press('Escape');
  assert.equal(await open('monitoringMenu'), false, 'Escape closes the UDP menu');
  assert.equal(await udpMenu.evaluate((node) => document.activeElement === node), true);
  await page.locator('#extendedBadge').click();
  assert.equal(await open('controlMenu'), false);
  assert.equal(await open('settingsMenu'), false);
  await page.locator('#extendedEnable').click();
  await page.locator('#confirmation').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#confirmTitle').textContent(), 'Start UDP monitoring');
  assert.match(await page.locator('#confirmText').textContent(), /keeps running when you close the GUI/);
  assert.deepEqual(operations, []);
  await page.locator('#confirmYes').click();

  const udpBadge = page.locator('#extendedBadge[aria-label="UDP monitoring: On"]');
  await udpBadge.waitFor();
  const background = (button) => button.evaluate((node) => getComputedStyle(node).backgroundColor);
  await firewallBadge.hover();
  const hoverColor = await background(firewallBadge);
  assert.notEqual(await background(udpBadge), hoverColor);
  await udpBadge.hover();
  assert.equal(await background(udpBadge), hoverColor);
  partial = true;
  await page.locator('#extendedBadge[aria-label="UDP monitoring: On, partial coverage"]').waitFor();
  assert.equal(await udpMenu.textContent(), 'UDP: On (partial)');
  await page.setViewportSize({ width: 800, height: 550 });
  await page.locator('#firewallMenuStatus').click();
  const firewallPanel = await page.locator('#controlMenu > .menu-panel').boundingBox();
  assert.ok(firewallPanel.x >= 0 && firewallPanel.x + firewallPanel.width <= 800);
  await udpMenu.click();
  const udpPanel = await page.locator('#monitoringMenu > .menu-panel').boundingBox();
  assert.ok(udpPanel.x >= 0 && udpPanel.x + udpPanel.width <= 800);
  const udpDetails = page.locator('#extendedStatus');
  assert.ok(await udpDetails.evaluate((node) => parseFloat(getComputedStyle(node).fontSize) >= 14));
  assert.ok(await udpDetails.evaluate((node) => node.scrollHeight <= node.clientHeight));
  await page.locator('#extendedStop').click();
  await page.locator('#confirmation').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#confirmTitle').textContent(), 'Stop UDP monitoring');
  assert.match(await page.locator('#confirmText').textContent(), /live UDP rates will become unavailable/);
  await page.locator('#confirmNo').click();
  assert.deepEqual(operations, ['traffic-start']);
  await page.locator('#extendedBadge').click();
  await page.locator('#extendedStop').click();
  await page.locator('#confirmYes').click();
  await page.locator('#extendedBadge[aria-label="UDP monitoring: Off"]').waitFor();
  assert.deepEqual(operations, ['traffic-start', 'traffic-stop']);
  assert.equal(await page.locator('#controlMenu > summary').textContent(), 'FW: Both');
  activityAvailable = false;
  await page.locator('#footerSummary').getByText('Activity unavailable', { exact: false }).waitFor();
  assert.match(await page.locator('#info').textContent(), /Activity unavailable/);
  console.log('PASS Wayland icon guide, About, firewall labels, UDP confirmations and Activity status', run);
} finally {
  if (app) await app.evaluate(({ app }) => app.exit()).catch(() => {});
  control.close();
  observer.close();
}
