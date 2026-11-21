// After npm run build, run node test/permission-popup-layout.mjs on a display
// with at least 800 × 900 available. All requests use a private fixture socket.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { _electron } from 'playwright-core';

const electronDir = path.resolve(import.meta.dirname, '..');
const workspace = path.resolve(electronDir, '../.workspace');
await fs.mkdir(workspace, { recursive: true });
const run = await fs.mkdtemp(path.join(workspace, 'popup-layout-'));
const client = path.join(run, 'electron');
await fs.mkdir(client);
await fs.cp(path.join(electronDir, 'dist'), path.join(client, 'dist'), { recursive: true });
await fs.copyFile(path.join(electronDir, 'package.json'), path.join(client, 'package.json'));
const endpoint = path.join(run, 'api');
const observer = path.join(run, 'obs');
const config = path.join(run, 'config');
await fs.mkdir(path.join(config, 'flowgate'), { recursive: true });
// Exercise the original base layout with window-specific user overrides.
for (const slot of ['theme.css', 'popup-theme.css'])
  await fs.writeFile(path.join(config, 'flowgate', slot), '');
await fs.writeFile(path.join(config, 'flowgate', 'style.css'), ':root { --fixture-user-style: desktop; }');
await fs.writeFile(
  path.join(config, 'flowgate', 'desktop-layout.css'),
  ':root { --fixture-user-style: main; --desktop-toolbar-height: 47px; --desktop-sidebar-width: 300px; }',
);
await fs.writeFile(
  path.join(config, 'flowgate', 'pane.css'),
  ':root { --fixture-user-style: pane; } .detached-heading { height: 44px; min-height: 44px; }',
);
await fs.writeFile(
  path.join(config, 'flowgate', 'permission-popup.css'),
  ':root { --fixture-user-style: permission; }',
);
const zone = {
  state: 'known',
  zone: 'internet',
  revision: 'zones',
  source: 'fixture',
  reason: 'Test network',
};
const generation = 'fixture';
const start = Date.now();
const once = 'Only this held connection.';
const decisions = [];
function request(id, name, direction, seconds = 180) {
  const application = {
    name,
    key: id,
    kind: 'native',
    revision: 'rev',
    executable: '/fixture/' + id,
  };
  return {
    id,
    state: 'awaiting-decision',
    deadline: new Date(Date.now() + seconds * 1000).toISOString(),
    first_seen: new Date(start + (direction === 'outgoing' ? 0 : 1)).toISOString(),
    flow: {
      direction,
      protocol: 'tcp',
      local: '[2001:db8::1]:50123',
      remote: '[2001:db8::2]:443',
      network_scope: zone,
    },
    attribution: {
      status: 'directly-associated',
      visibility_complete: true,
      application,
      owners: [
        {
          pid: 4281,
          uid: 1000,
          start_ticks: '101',
          executable: application.executable,
          application,
        },
      ],
      permission_target: {
        kind: 'application',
        label: name,
        once,
        remember: 'This application',
        key_basis: 'verified executable',
      },
    },
    remembered_filter: {
      application: id,
      revision: 'rev',
      direction,
      uid: 1000,
      protocol: 'tcp',
      remote_address: '2001:db8::2',
      remote_port: 443,
    },
    scope_previews: {
      once,
      application: 'This application for one hour.',
      persistent: 'This application.',
      'for-a-while': 'This process instance.',
    },
  };
}
const first = request('atlas-sync', 'Atlas Sync', 'outgoing');
const second = request('long-client', 'Archive' + 'Synchronization'.repeat(10), 'incoming');
let events = [first, second];
let timeoutSeconds = 30;
let timeoutRevision = 1;
const timeoutEdits = [];
function reply(q) {
  const now = new Date().toISOString();
  const r = { version: 1, generation, server_time: now, mode: 'isolated-lab', read_only: false };
  if (q.operation === 'decision-timeout-status' || q.operation === 'decision-timeout-configure') {
    if (q.operation === 'decision-timeout-configure') {
      assert.equal(q.generation, generation);
      assert.equal(q.decision_timeout.expected_revision, String(timeoutRevision));
      timeoutEdits.push(q.decision_timeout.seconds);
      timeoutSeconds = q.decision_timeout.seconds;
      timeoutRevision++;
    }
    return { ...r, decision_timeout: { seconds: timeoutSeconds, revision: String(timeoutRevision) } };
  }
  if (q.operation === 'decide') {
    decisions.push(q);
    const event = events.find((e) => e.id === q.id);
    events = events.filter((e) => e.id !== q.id);
    return { ...r, decision: { ...event, state: q.action === 'allow' ? 'allowed' : 'blocked' } };
  }
  if (q.operation === 'decision-preview') {
    const e = events.find((e) => e.id === q.id);
    return {
      ...r,
      decision_preview: {
        ...q,
        event_id: e.id,
        token: 'review-' + q.action,
        expires_at: new Date(Date.now() + 30000).toISOString(),
        connection_network: zone,
        scope_preview: e.scope_previews[q.scope],
        summary: q.action + ' this application.',
        rule: {
          id: 'review',
          version: 1,
          action: q.action,
          created: now,
          expires: q.duration_seconds
            ? new Date(Date.now() + 1000 * q.duration_seconds).toISOString()
            : '0001-01-01T00:00:00Z',
          filter: {
            ...e.remembered_filter,
            protocol: '*',
            remote_address: '*',
            remote_port: 0,
            local_port: 0,
          },
        },
      },
    };
  }
  return {
    ...r,
    capabilities: [
      'decision-remember-fields-v1',
      'decision-for-a-while-v1',
      'decision-for-a-while-durations-v1',
      'network-zone-policy-v1',
      'decision-timeout-settings-v1',
    ],
    for_a_while_durations: [15, 60, 3600],
    network_zones: {
      model: 'configured-prefix-v1',
      revision: 'zones',
      local_prefixes: [],
      internet_prefixes: [],
      reason: 'Synthetic',
    },
    permissions: {
      role: 'administrator',
      policy_scope: 'machine',
      observation_scope: 'machine',
      can_manage_rules: true,
      can_manage_machine_rules: true,
      can_decide: true,
    },
    events,
    rules: [],
    activity: { sequence: 1, collected: now, complete: true, processes: {}, rows: [] },
  };
}
async function listen(pathname, respond) {
  const server = net.createServer((socket) => {
    let input = '';
    socket.setEncoding('utf8').on('data', (chunk) => {
      input += chunk;
      if (input.includes('\n')) socket.end(JSON.stringify(respond(JSON.parse(input))) + '\n');
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(pathname, resolve));
  return server;
}
const server = await listen(endpoint, reply);
const observerServer = await listen(observer, () => {
  const now = new Date().toISOString();
  const process = { ...first.attribution.owners[0], id: 'atlas-process' };
  return {
    version: 1,
    generation,
    server_time: now,
    mode: 'host-monitor',
    read_only: true,
    activity: {
      sequence: 1,
      collected: now,
      complete: true,
      processes: { [process.id]: process },
      rows: [{
        id: 'atlas-socket',
        owners: [process.id],
        ownership_category: 'visible-holder',
        state: 'Established',
        socket: { protocol: 'tcp', local: first.flow.local, remote: first.flow.remote, uid: process.uid, state: 1 },
        traffic: { available: false, reason: 'Synthetic observation' },
      }],
    },
  };
});

let app;
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      ...(process.env.WAYLAND_DISPLAY ? ['--ozone-platform=wayland'] : []),
      client, '--observer', observer, '--control', endpoint,
    ],
    env: {
      ...process.env,
      XDG_CONFIG_HOME: config,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      FLOWGATE_INSTALLED: '0',
    },
  });
  async function requestWindow(id) {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const page = app
        .windows()
        .find((p) => p.url() && new URL(p.url()).searchParams.get('request') === id);
      if (page) return page;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw Error('No permission window for ' + id + ': ' + app.windows().map((p) => p.url()));
  }
  const prompt = await requestWindow(first.id);
  prompt.setDefaultTimeout(8000);
  await prompt.waitForFunction(() => document.querySelector('#allow')?.disabled === false);
  const sheets = (page) =>
    page.evaluate(() => Array.from(document.styleSheets, (s) => new URL(s.href).pathname));
  const main = app.windows().find((p) => p.url().endsWith('/index.html'));
  main.setDefaultTimeout(12000);
  assert.deepEqual(await sheets(main), [
    '/style.css', '/tooltip.css', '/desktop-layout.css', '/theme.css', '/user-style.css', '/user-desktop-layout.css',
  ]);
  assert.deepEqual(await sheets(prompt), ['/permission-popup.css', '/tooltip.css', '/popup-theme.css', '/user-permission-popup.css']);
  const appliedStyle = (page) => page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue('--fixture-user-style').trim());
  assert.equal(await appliedStyle(main), 'main');
  assert.equal(await appliedStyle(prompt), 'permission');
  assert.equal(await main.locator('.toolbar').evaluate((el) => getComputedStyle(el).height), '47px');
  await main.locator('#toolsMenu > summary').click();
  await main.locator('#optionsMenu > summary').click();
  const timeout = main.getByRole('spinbutton', { name: 'Decision timeout (seconds)' });
  const saveTimeout = main.locator('#decisionTimeoutSave');
  await main.waitForFunction(() => document.querySelector('#decisionTimeoutSeconds')?.value === '30');
  assert(await saveTimeout.isDisabled());
  await timeout.fill('1');
  assert(await saveTimeout.isDisabled());
  await timeout.fill('61');
  assert(await saveTimeout.isDisabled());
  await timeout.fill('45');
  await saveTimeout.click();
  await main.waitForFunction(() => document.querySelector('#decisionTimeoutStatus')?.textContent === 'Saved for new requests.');
  assert.deepEqual(timeoutEdits, [45]);
  await main.locator('#decisionTimeoutRefresh').click();
  await main.waitForFunction(() => !document.querySelector('#decisionTimeoutSeconds')?.disabled);
  assert.equal(await timeout.inputValue(), '45');
  assert(parseInt(await prompt.locator('.expiry').textContent(), 10) > 60, 'an active request retains its own deadline');
  await main.screenshot({ path: path.join(run, 'permission-timeout.png') });
  await main.locator('#optionsMenu > summary').click();
  await main.locator('#toolsMenu > summary').click();
  const rateMode = main.locator('#rateMode');
  await rateMode.hover();
  const desktopTooltip = main.getByRole('tooltip');
  await desktopTooltip.waitFor();
  assert.match(await desktopTooltip.innerText(), /cumulative|rates|rate/i);
  await main.screenshot({ path: path.join(run, 'app-tooltip.png') });
  await main.keyboard.press('Escape');
  await desktopTooltip.waitFor({ state: 'hidden' });
  const appRow = main.locator('#rows tr[data-id^="app:"]').filter({ hasText: 'Atlas Sync' });
  const chart = main.locator('#trafficGraph');
  const table = main.locator('#activityView .table-scroll');
  const sidebar = main.locator('#activityDetails');
  const grip = main.locator('#activityView > .sidebar-grip');
  await appRow.waitFor();
  await sidebar.waitFor({ state: 'hidden' });
  await grip.waitFor({ state: 'hidden' });
  await chart.waitFor();
  const fillsPlot = (page, detached = false) => page.evaluate((detached) => {
    const canvas = document.querySelector('#trafficCanvas').getBoundingClientRect();
    const panel = document.querySelector(detached ? '#paneContent' : '#trafficGraph').getBoundingClientRect();
    const header = document.querySelector('.graph-heading').getBoundingClientRect();
    return Math.abs((detached ? panel.top : header.bottom) - canvas.top) <= 1
      && Math.abs(panel.bottom - canvas.bottom) <= 1
      && Math.abs(panel.width - canvas.width) <= 2;
  }, detached);
  const chartHeader = chart.locator('.graph-heading');
  const sample = chart.locator('#graphSample');
  const download = chartHeader.getByRole('button', { name: 'Toggle download series' });
  await download.waitFor();
  assert(await chartHeader.getByRole('button', { name: 'Toggle upload series' }).isVisible());
  assert(await fillsPlot(main));
  const measurement = chartHeader.locator('.graph-explanation summary');
  assert(await chartHeader.locator('#graphStatus').isHidden());
  await measurement.click();
  assert.match(await chartHeader.locator('#graphStatus').innerText(), /Live ·/);
  assert(await fillsPlot(main));
  await measurement.click();
  const downloadHelp = await download.getAttribute('title');
  assert(downloadHelp);
  await download.hover();
  await desktopTooltip.waitFor();
  assert.equal(await desktopTooltip.innerText(), downloadHelp);
  assert((await desktopTooltip.boundingBox()).width <= 350);
  await chart.locator('#trafficCanvas').hover();
  await desktopTooltip.waitFor({ state: 'hidden' });
  assert.equal(await download.getAttribute('title'), downloadHelp);
  await sample.waitFor();
  assert((await sample.boundingBox()).width <= 350);
  assert(await sample.getByRole('button', { name: 'Close' }).isHidden());
  await chart.screenshot({ path: path.join(run, 'chart-sample.png') });
  await chart.locator('#trafficCanvas').click();
  await sample.getByRole('button', { name: 'Close' }).click();
  await main.mouse.move(5, 5);
  await sample.waitFor({ state: 'hidden' });
  const chartWidth = (await chart.boundingBox()).width;
  const fullTableWidth = (await table.boundingBox()).width;
  assert.equal(chartWidth, fullTableWidth);
  await main.screenshot({ path: path.join(run, 'activity-overview.png') });
  await appRow.click();
  await sidebar.waitFor();
  await grip.waitFor();
  const rules = sidebar.getByRole('table', { name: 'Rules by type and initiation direction' });
  await rules.waitFor();
  assert.deepEqual(await rules.locator('th[scope="row"]').allTextContents(), [
    'Blocker',
    'Limit',
    'Priority',
  ]);
  assert.equal(await appRow.locator('.status-strip > .status-slot').count(), 5);
  assert.match(await sidebar.locator('#selectedName').getAttribute('data-label'), /Atlas Sync/i);
  assert.match(await sidebar.locator('#selectedName').innerText(), /Atlas Sync/i);
  const overviewTab = sidebar.getByRole('tab', { name: 'Overview', exact: true });
  const diagnosticsTab = sidebar.getByRole('tab', { name: 'Diagnostics' });
  assert.equal(await overviewTab.getAttribute('aria-selected'), 'true');
  assert.doesNotMatch(await sidebar.locator('#info').innerText(), /Application identity|Fast path/);
  await overviewTab.press('ArrowRight');
  assert.match(await sidebar.getByRole('tabpanel', { name: 'Diagnostics' }).innerText(), /Application identity/);
  await diagnosticsTab.press('Home');
  assert(await sidebar.getByRole('tabpanel', { name: 'Overview' }).isVisible());
  const sidebarWidth = () => sidebar.evaluate((el) => getComputedStyle(el).width);
  assert.equal(await sidebarWidth(), '300px');
  assert.equal((await chart.boundingBox()).width, chartWidth);
  assert((await chart.boundingBox()).y < (await table.boundingBox()).y);
  assert((await table.boundingBox()).width < fullTableWidth);
  await grip.press('ArrowLeft');
  assert.equal(await sidebarWidth(), '310px');
  await main.screenshot({ path: path.join(run, 'activity-selected.png') });
  const viewport = main.viewportSize() || await main.evaluate(() => ({ width: innerWidth, height: innerHeight }));
  await main.setViewportSize({ width: 800, height: 550 });
  const narrowChart = await chart.boundingBox();
  const narrowSidebar = await sidebar.boundingBox();
  assert(narrowSidebar.x + narrowSidebar.width <= 800);
  assert(narrowSidebar.y >= narrowChart.y + narrowChart.height);
  assert(await fillsPlot(main));
  await main.screenshot({ path: path.join(run, 'activity-narrow.png') });
  await main.setViewportSize(viewport);
  await chart.locator('.pane-close').click();
  await chart.waitFor({ state: 'hidden' });
  await sidebar.waitFor();
  const windowMenu = main.locator('.toolbar-window-menu');
  await windowMenu.locator('summary').click();
  await windowMenu.locator('[data-pane="chart"]').click();
  await chart.waitFor();
  await main.locator('#rows tr[data-id="overview"] .name').click();
  await sidebar.waitFor({ state: 'hidden' });
  await grip.waitFor({ state: 'hidden' });
  assert.equal((await table.boundingBox()).width, fullTableWidth);
  const shot = async (name) => {
    await prompt.evaluate(() => document.fonts.ready);
    await prompt.screenshot({ path: path.join(run, name + '.png') });
  };
  const bounds = (selector) => prompt.locator(selector).boundingBox();
  const active = () => prompt.evaluate(() => document.activeElement.id);
  async function tabTo(id) {
    for (let i = 0; i < 25; i++) {
      if ((await active()) === id) return;
      await prompt.keyboard.press('Tab');
    }
    assert.fail('Tab could not reach ' + id);
  }
  async function visibleActions() {
    for (const id of ['allow', 'block', 'allowForAWhile', 'blockForAWhile']) {
      assert(
        await prompt.locator('#' + id).evaluate((button) => {
          const r = button.getBoundingClientRect();
          return (
            r.top >= 0 &&
            r.bottom <= innerHeight &&
            r.left >= 0 &&
            r.right <= innerWidth &&
            button.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2))
          );
        }),
        id + ' is fully visible and clickable without scrolling',
      );
    }
  }
  const allow = prompt.getByRole('button', { name: '✓ Allow', exact: true });
  const ruleDuration = prompt.locator('#rememberDuration');
  const leaseDuration = prompt.getByRole('combobox', { name: 'For a while duration' });
  const allowTemporary = prompt.locator('#allowForAWhile');
  const denyTemporary = prompt.locator('#blockForAWhile');
  const native = await app.browserWindow(prompt);
  await native.evaluate((w) => w.focus());
  const heading = prompt.getByRole('heading', {
    name: first.attribution.application.name,
    level: 1,
  });
  assert(await heading.isVisible());
  assert(await allow.isEnabled());
  assert(await prompt.getByRole('button', { name: '× Deny', exact: true }).isEnabled());
  assert.equal(await prompt.locator('#promptPending').innerText(), 'Pending requests (2)');
  assert.match(await allow.getAttribute('title'), /Only this held connection/i);
  await allow.hover();
  const permissionTooltip = prompt.getByRole('tooltip');
  await permissionTooltip.waitFor();
  assert.match(await permissionTooltip.innerText(), /Only this held connection/i);
  await prompt.mouse.move(3, 3);
  await permissionTooltip.waitFor({ state: 'hidden' });
  assert.equal(await prompt.locator('#rememberToggle, #forAWhileToggle').count(), 0);
  assert.equal(await ruleDuration.inputValue(), 'once');
  assert(await prompt.locator('#rememberPanel').isVisible());
  assert((await bounds('#allowForAWhile')).y >= (await bounds('#allow')).y + (await bounds('#allow')).height);
  assert((await bounds('#blockForAWhile')).y >= (await bounds('#block')).y + (await bounds('#block')).height);
  assert((await bounds('#forAWhileDuration')).y >= (await bounds('#dismiss')).y + (await bounds('#dismiss')).height);
  assert(await allowTemporary.isEnabled());
  assert(await denyTemporary.isEnabled());
  const identity = await bounds('#requestIdentity'),
    peer = await bounds('#requestPeer');
  assert(peer.y >= identity.y + identity.height - 1);
  assert.equal(peer.y, (await bounds('#connectionHeader')).y);
  await visibleActions();
  await shot('default');
  const theme = path.join(config, 'flowgate', 'popup-theme.css');
  const reloadTheme = (version) => prompt.locator('link[href^="popup-theme.css"]').evaluate(
    (link, version) => new Promise((resolve, reject) => {
      link.onload = resolve;
      link.onerror = reject;
      link.setAttribute('href', 'popup-theme.css?' + version);
    }),
    version,
  );
  await fs.copyFile(path.join(electronDir, 'themes', 'signal-deck-popup.css'), theme);
  await reloadTheme('signal-deck');
  try {
    await prompt.waitForFunction(() => {
      const rect = (id) => document.getElementById(id).getBoundingClientRect();
      const below = (top, bottom) => rect(bottom).top >= rect(top).bottom
        && Math.abs(rect(bottom).left - rect(top).left) < 2;
      return rect('dismiss').top === rect('allow').top
        && below('allow', 'allowForAWhile')
        && below('block', 'blockForAWhile')
        && below('dismiss', 'forAWhileDuration');
    });
    await visibleActions();
    await shot('signal-deck');
  } finally {
    await fs.writeFile(theme, '');
    await reloadTheme('base');
  }
  const originalAllow = await allow.elementHandle();
  await shot('compact');

  await tabTo('cardCollapse');
  await prompt.keyboard.press('Enter');
  assert(await heading.isVisible());
  assert(await prompt.locator('#connectionFields').isHidden());
  await visibleActions();
  await prompt.keyboard.press('Enter');
  await tabTo('detailsToggle');
  await prompt.keyboard.press('Enter');
  assert.equal(await active(), 'detailsBack');
  assert(await prompt.getByRole('region', { name: 'Request details' }).isVisible());
  assert.equal(await prompt.locator('#scopePreview').textContent(), once);
  await prompt.keyboard.press('Enter');
  assert.equal(await active(), 'detailsToggle');

  await ruleDuration.selectOption('0');
  await prompt.waitForFunction(() => document.querySelector('#allow')?.disabled === false);
  await prompt.waitForFunction(() => innerHeight > 590);
  assert.match(await prompt.locator('#scopePreview').textContent(), /This application/);
  assert(await originalAllow.evaluate((node) => node === document.querySelector('#allow')));
  await visibleActions();
  await shot('expanded');

  // Only CSS enters the running popup. No reload or renderer/markup changes.
  // Exercise independently placed sections, including the expanded fieldset.
  const alternate = path.join(run, 'alternate.css');
  await fs.writeFile(
    alternate,
    `
    #promptBody #requestCard {
      grid-template-areas:
        "options     decisions"
        "remember    remember"
        "status      status"
        "connection  connection"
        "direction   destination"
        "identity    identity"
        "details     details"
        "network     network"
        "leaseNote   onceNote"
        "reconcile   future";
    }
  `,
  );
  const key = await native.evaluate(
    (w, css) => w.webContents.insertCSS(css),
    await fs.readFile(alternate, 'utf8'),
  );
  try {
    const actions = await bounds('#decisionActions'),
      options = await bounds('#decisionOptions');
    const panel = await bounds('#rememberPanel'),
      status = await bounds('.request-meta');
    assert(actions.x > options.x && actions.y === options.y);
    assert(panel.y >= actions.y + actions.height - 1 && panel.y + panel.height <= status.y + 1);
    assert(status.y < (await bounds('#connectionFields')).y);
    assert((await bounds('#requestPeer')).y < (await bounds('#requestIdentity')).y);
    assert(await originalAllow.evaluate((node) => node === document.querySelector('#allow')));
    assert.equal(await ruleDuration.inputValue(), '0');
    await shot('alternate');
  } finally {
    await native.evaluate((w, key) => w.webContents.removeInsertedCSS(key), key);
    await fs.unlink(alternate);
  }
  await ruleDuration.selectOption('once');
  await prompt.waitForFunction(() => !document.querySelector('#allow').disabled);
  await tabTo('allow');
  assert.equal(decisions.length, 0);
  await prompt.keyboard.press('Enter');
  assert.equal(await requestWindow(second.id), prompt);
  await prompt.waitForFunction(() => document.querySelector('#allow')?.disabled === false);
  assert.deepEqual(
    decisions.map(({ action, scope, id }) => ({ action, scope, id })),
    [{ action: 'allow', scope: 'once', id: first.id }],
  );
  assert.equal(await prompt.locator('#promptPending').innerText(), 'Pending requests (1)');
  assert.equal(await ruleDuration.inputValue(), 'once');
  assert.match(await prompt.locator('#connectionHeader').innerText(), /Incoming/);
  assert.equal(await prompt.locator('#requestPeer .nl-label').textContent(), 'From');
  const name = second.attribution.application.name;
  assert(await prompt.getByRole('heading', { level: 1, name, exact: true }).isVisible());

  // Chromium viewport emulation keeps the desktop work area unchanged.
  await ruleDuration.selectOption('once');
  await prompt.setViewportSize({ width: 360, height: 400 });
  await prompt.waitForFunction(() => innerWidth === 360 && innerHeight === 400);
  assert(
    await prompt
      .locator('#requestApplication strong')
      .evaluate(
        (label) =>
          label.scrollWidth <= label.clientWidth &&
          label.getBoundingClientRect().height > parseFloat(getComputedStyle(label).lineHeight),
      ),
  );
  assert(await prompt.locator('#promptBody').evaluate((el) => el.scrollWidth <= el.clientWidth));
  await visibleActions();
  await shot('long-compact');
  await ruleDuration.selectOption('0');
  await prompt.waitForFunction(() => !document.querySelector('#allow').disabled);
  await prompt.locator('#rememberDuration').scrollIntoViewIfNeeded();
  assert(await prompt.locator('#promptBody').evaluate((el) => el.scrollWidth <= el.clientWidth));
  assert.equal(decisions.length, 1);
  const third = request('third-client', 'Another queued application', 'outgoing', timeoutSeconds);
  events.push(third);
  await leaseDuration.selectOption('60');
  await tabTo('allowForAWhile');
  await prompt.keyboard.press('Enter');
  for (let i = 0; i < 40 && decisions.length < 2; i++)
    await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(decisions.length, 2);
  assert.equal(decisions[1].id, second.id);
  assert.equal(decisions[1].action, 'allow');
  assert.equal(decisions[1].scope, 'for-a-while');
  assert.equal(decisions[1].duration_seconds, 60);
  assert.equal(await requestWindow(third.id), prompt);
  await prompt.getByRole('heading', { level: 1, name: third.attribution.application.name }).waitFor();
  const nextCountdown = parseInt(await prompt.locator('.expiry').textContent(), 10);
  assert(nextCountdown > 0 && nextCountdown <= 45);
  await denyTemporary.waitFor();
  await prompt.waitForFunction(() => !document.querySelector('#blockForAWhile').disabled);
  assert.equal(await leaseDuration.inputValue(), '60');
  await denyTemporary.click();
  for (let i = 0; i < 40 && decisions.length < 3; i++)
    await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(decisions.length, 3);
  assert.equal(decisions[2].id, third.id);
  assert.equal(decisions[2].action, 'block');
  assert.equal(decisions[2].scope, 'for-a-while');
  assert.equal(decisions[2].duration_seconds, 60);
  const chartOpened = app.waitForEvent('window');
  await main.evaluate(() => window.flowgate.paneControl('chart', 'undock'));
  const detachedChart = await chartOpened;
  await detachedChart.waitForURL('flowgate://app/pane.html?pane=chart');
  const detachedHeader = detachedChart.locator('.detached-heading');
  await detachedHeader.getByRole('button', { name: 'Toggle upload series' }).waitFor();
  await detachedChart.setViewportSize({ width: 390, height: 300 });
  assert.equal(await detachedChart.locator('.graph-heading').count(), 1);
  assert(await fillsPlot(detachedChart, true));
  assert(await detachedHeader.locator('#dockPane').isVisible());
  await detachedHeader.getByRole('button', { name: 'Pause chart' }).click();
  assert.equal(await detachedHeader.locator('#graphPause').getAttribute('aria-pressed'), 'true');
  await detachedHeader.getByRole('button', { name: 'Return to live' }).click();
  assert.equal(await detachedHeader.locator('#graphPause').getAttribute('aria-pressed'), 'false');
  await detachedChart.screenshot({ path: path.join(run, 'chart-detached.png') });
  const paneOpened = app.waitForEvent('window');
  await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
  const pane = await paneOpened;
  await pane.waitForURL('flowgate://app/pane.html?pane=info');
  await pane.waitForLoadState('load');
  assert.deepEqual(await sheets(pane), [
    '/style.css', '/tooltip.css', '/pane.css', '/theme.css', '/user-style.css', '/user-pane.css',
  ]);
  assert.equal(await appliedStyle(pane), 'pane');
  assert.equal(
    await pane.locator('.detached-heading').evaluate((el) => getComputedStyle(el).height), '44px',
  );
  console.log(
    'PASS Activity chart and selection layout, native user styles, popup focus, previews, keyboard Allow Once, queue and long labels.',
    run,
  );
} finally {
  await app?.close();
  observerServer.close();
  server.close();
}
