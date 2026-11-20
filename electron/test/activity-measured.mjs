// SYNTHETIC Activity presentation fixture; actual sandboxed Electron, no enforcement.
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { _electron } from 'playwright-core';
const root = path.resolve(import.meta.dirname, '../..');
const stage = process.env.STAGE || 'before';
const evidence = path.join(
  process.env.FLOWGATE_VISUAL_EVIDENCE || path.join(root, '.workspace/activity-measured'),
  stage,
);
fs.mkdirSync(evidence, { recursive: true });
const run = fs.mkdtempSync(path.join(root, '.workspace/av-'));
const pref = path.join(root, 'build/desktop-session/electron-preferences.json');
const old = fs.existsSync(pref) ? fs.readFileSync(pref) : undefined;
let sequence = 1,
  empty = false,
  pending = false,
  app,
  collected = new Date().toISOString();
const names = [
  'Firefox',
  'Desktop file manager',
  'Terminal',
  'Document viewer',
  'Media player',
  'Background service',
  'Text editor',
  'Software update',
  'Network diagnostics',
  'Long application name with a deliberately descriptive executable path',
  'Build worker',
  'Local database',
  'Image viewer',
  'Notification service',
  'Unmeasured worker',
];
const processes = {};
const rows = names.map((name, i) => {
  const id = `${10000 + i}:fixture`;
  const executable =
    i === 0
      ? '/usr/lib/firefox/firefox'
      : `/synthetic/application/${i}/long/path/to/${name.replaceAll(' ', '-')}`;
  processes[id] = {
    id,
    pid: 10000 + i,
    uid: 1000,
    start_ticks: '1',
    executable,
    application: { key: 'fixture-' + i, revision: 'fixture', name, executable },
  };
  return {
    id: 's' + i,
    owners: [id],
    ownership: 'Unique visible holder',
    ownership_category: 'visible-holder',
    state: 'Established',
    direction: 'Unknown',
    evidence: 'SYNTHETIC display fixture',
    socket: {
      protocol: 'tcp',
      local: '[2001:db8:1234:5678::1]:40123',
      remote: '[2001:db8:abcd:1234::99]:443',
      uid: 1000,
      cookie: 'fixture' + i,
      netns: 'fixture',
      state: 1,
    },
    traffic: {
      state: i === 14 ? 'unavailable' : 'measured',
      available: i !== 14,
      partial: i === 5,
      definition: 'tcp-transport-payload',
      source: 'SYNTHETIC fixture',
      since: '2026-10-18T00:00:00Z',
      uploaded: sequence * (i + 1) * 1024,
      downloaded: sequence * (i + 1) * 4096,
      upload_bps: i === 3 ? 0 : (15 - i) * 1024,
      download_bps: i === 3 ? 0 : (15 - i) * 4096,
    },
  };
});
rows.push({
  ...rows[0],
  id: 'unknown',
  owners: [],
  ownership: 'No visible holder',
  ownership_category: 'inode-zero',
  traffic: { available: false, state: 'unavailable', reason: 'No measurement' },
});
const direction = (d, i) => {
  const type = i % 5,
    count = type === 0 ? 0 : type === 3 ? 2 : 1;
  return {
    direction: d,
    configured: ['absent', 'uniform', 'scoped', 'mixed', 'inactive_only'][type],
    action: 'block',
    reason: 'SYNTHETIC configured policy summary',
    rules: Array.from({ length: count }, (_, n) => ({
      id: 'ref-' + i + '-' + d + '-' + n,
      version: '1',
      action: n ? 'allow' : 'block',
      priority: 100,
      scope: {
        application: 'fixture-' + i,
        revision: 'fixture',
        uid: 1000,
        direction: d,
        protocol: 'tcp',
        remote_address: type === 1 ? '*' : '2001:db8::2',
        local_port: 0,
        remote_port: 443,
      },
      disabled: type === 4,
      expired: false,
      active: type !== 4,
      expires: '0001-01-01T00:00:00Z',
    })),
    active_rules: type === 4 ? 0 : count,
    disabled_rules: type === 4 ? count : 0,
    expired_rules: 0,
    potential_overlapping_actions: type === 3,
    configured_default: { known: false, reason: 'No default supplied' },
    runtime_default: { known: false, reason: 'Firewall stopped' },
    enforcement: { state: 'stopped', covered: false, reason: 'Monitoring only; firewall stopped' },
  };
};
const reply = () => ({
  version: 1,
  generation: 'synthetic-activity',
  mode: 'daemon-monitor',
  backend_mode: 'daemon-monitor',
  read_only: false,
  server_time: new Date().toISOString(),
  capabilities: ['explicit-administrator-v1', 'policy-explanations-v1'],
  permissions: {
    role: 'administrator',
    policy_scope: 'machine',
    observation_scope: 'machine',
    can_manage_rules: true,
    can_decide: false,
  },
  enforcement: { state: 'stopped', detail: 'SYNTHETIC fixture' },
  activity: { sequence, collected, complete: true, rows: empty ? [] : rows, processes },
  events: pending
    ? [
        {
          id: 'fixture-pending',
          state: 'awaiting-decision',
          deadline: new Date(Date.now() + 60000).toISOString(),
          flow: {
            direction: 'incoming',
            protocol: 'tcp',
            local: '[2001:db8::1]:44001',
            remote: '[2001:db8::2]:50000',
          },
          attribution: {
            status: 'attributed',
            reason: 'SYNTHETIC fixture',
            visibility_complete: true,
            application: processes['10000:fixture'].application,
            owners: [processes['10000:fixture']],
          },
          scope_previews: { once: 'SYNTHETIC: exact incoming TCP request only' },
        },
      ]
    : [],
  rules: [
    {
      id: 'fixture-rule',
      version: 1,
      schema: 2,
      created: '2026-10-18T00:00:00Z',
      expires: '0001-01-01T00:00:00Z',
      executable: processes['10000:fixture'].executable,
      filter: {
        application: 'fixture-0',
        revision: 'fixture',
        uid: 1000,
        direction: 'incoming',
        protocol: 'tcp',
        remote_address: '2001:db8::2',
        local_port: 44001,
        remote_port: 0,
      },
      priority: 100,
      action: 'allow',
      disabled: false,
    },
  ],
});
const handle = (ro) => (s) =>
  s.once('data', (b) => {
    const q = JSON.parse(b);
    let r = reply();
    if (ro) {
      r.mode = 'host-monitor';
      r.read_only = true;
    }
    if (q.operation === 'policy-view')
      r.policy_view = {
        snapshot: {
          generation: r.generation,
          token: 'fixture-token',
          sequence: String(sequence),
          evaluated_at: r.server_time,
          meaning: 'SYNTHETIC configured policy; not a historical verdict',
        },
        activity_sequence: String(sequence),
        activity_collected: r.activity.collected,
        activity_available: true,
        complete: true,
        applications: Object.values(processes).map((p, i) => ({
          ref: p.application.key,
          identity: { key: p.application.key, revision: 'fixture', uid: 1000 },
          process_ids: [p.id],
          incoming: direction('incoming', i),
          outgoing: direction('outgoing', i + 1),
        })),
        rows: rows.map((s, i) => ({
          row_id: s.id,
          status: i < names.length ? 'observed_native' : 'unavailable',
          reason: 'SYNTHETIC',
          application_ref: i < names.length ? 'fixture-' + i : '',
          decision_authority: false,
        })),
      };
    s.end(JSON.stringify(r) + '\n');
  });
const server = net.createServer(handle(false)),
  monitor = net.createServer(handle(true));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const timer = setInterval(() => {
  sequence++;
  collected = new Date().toISOString();
}, 2000);
try {
  await new Promise((r) => server.listen(path.join(run, 's'), r));
  await new Promise((r) => monitor.listen(path.join(run, 's.monitor'), r));
  fs.writeFileSync(pref, '{}');
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      path.join(run, 's.monitor'),
      '--control',
      path.join(run, 's'),
      '--width',
      '1280',
      '--height',
      '656',
    ],
    cwd: root,
    env: {
      ...process.env,
      WAYLAND_DISPLAY: 'wayland-0',
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const page = await app.firstWindow();
  await page.setViewportSize({ width: 1280, height: 656 });
  await page.waitForSelector('#rows tr');
  await sleep(1800);
  assert.equal(await page.locator('#rows tr[aria-selected=true]').getAttribute('data-id'), 'overview');
  await page.selectOption('#activitySource', 'udp');
  assert.equal(await page.locator('#graphSource').inputValue(), 'udp');
  assert.match(await page.locator('#rows tr').first().innerText(), /—/);
  await page.selectOption('#activitySource', 'tcp');
  await page.locator('#rows tr').filter({ hasText: 'Firefox' }).first().locator('.name').click();
  await sleep(1200);
  await page.evaluate(
    () =>
      (document.querySelector('#app > footer > span').textContent =
        'SYNTHETIC presentation fixture · no real traffic or rules'),
  );
  const metrics = await page.evaluate(() =>
    Object.fromEntries(
      [
        '.toolbar',
        '.tabs',
        '.filterbar',
        '#tree thead',
        '#rows tr',
        '#rows .application-icon',
        '#activityView > aside',
        '#trafficGraph',
      ].map((s) => {
        const e = document.querySelector(s),
          r = e.getBoundingClientRect(),
          c = getComputedStyle(e);
        return [
          s,
          {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
            background: c.backgroundColor,
            color: c.color,
            font: c.font,
            fontFamily: c.fontFamily,
          },
        ];
      }),
    ),
  );
  metrics.dpr = await page.evaluate(() => devicePixelRatio);
  assert.equal(await page.locator('#rows tr').filter({ hasText: 'Unidentified' }).count(), 1);
  if (fs.existsSync('/usr/lib/firefox/firefox'))
    assert(
      await page.locator('#rows tr').filter({ hasText: 'Firefox' }).first().locator('img').count(),
    );
  assert.match(await page.locator('#graphSource').textContent(), /UDP API/);
  assert.equal(await page.locator('#selectedExecutable').innerText(), '/usr/lib/firefox/firefox');
  await page.screenshot({ path: path.join(evidence, 'activity-normal.png') });
  for (const key of ['upload_bps', 'download_bps']) {
    await page.click('.col-' + key + ' button');
    assert.equal(await page.locator('.col-' + key).getAttribute('aria-sort'), 'descending');
    await page.click('.col-' + key + ' button');
    assert.equal(await page.locator('.col-' + key).getAttribute('aria-sort'), 'ascending');
  }
  await page.locator('#rows tr').filter({ hasText: 'Firefox' }).first().locator('.name').click();
  await page
    .locator('#rows tr')
    .filter({ hasText: 'Firefox' })
    .first()
    .locator('.policy-cell')
    .first()
    .focus();
  await page.keyboard.press('Enter');
  await page.waitForSelector('.activity-quick');
  await page.screenshot({ path: path.join(evidence, 'policy-normal.png') });
  await page.keyboard.press('Escape');
  await page.locator('#rows tr').filter({ hasText: 'Firefox' }).first().locator('.name').click();
  const selected = await page.locator('#rows tr[aria-selected=true]').getAttribute('data-id');
  await page.keyboard.press('ArrowDown');
  assert.notEqual(
    await page.locator('#rows tr[aria-selected=true]').getAttribute('data-id'),
    selected,
  );
  await page.keyboard.press('ArrowUp');
  assert.equal(
    await page.locator('#rows tr[aria-selected=true]').getAttribute('data-id'),
    selected,
  );
  await page.fill('#search', '2001:db8');
  assert((await page.locator('#rows tr').count()) >= 15);
  await page.fill('#search', '');
  await page.setViewportSize({ width: 860, height: 600 });
  await sleep(1200);
  metrics.narrow = await page.evaluate(() => ({
    header: document.querySelector('#tree thead').getBoundingClientRect().height,
    sidebar: document.querySelector('#activityView > aside').getBoundingClientRect().width,
    overflow:
      document.querySelector('#activityView .table-scroll').scrollWidth >
      document.querySelector('#activityView .table-scroll').clientWidth,
  }));
  await page.screenshot({ path: path.join(evidence, 'activity-narrow.png') });
  await page.fill('#search', 'does-not-exist');
  await sleep(200);
  await page.screenshot({ path: path.join(evidence, 'filtered-empty.png') });
  await page.fill('#search', '');
  await page.click('#expand');
  const scroller = page.locator('#activityView .table-scroll');
  await scroller.evaluate((e) => {
    e.scrollLeft = 150;
    e.scrollTop = 120;
  });
  await sleep(1200);
  assert.equal(await scroller.evaluate((e) => e.scrollLeft), 150);
  assert.equal(await scroller.evaluate((e) => e.scrollTop), 120);
  await scroller.evaluate((e) => {
    e.scrollLeft = 0;
    e.scrollTop = 0;
  });
  await page
    .locator('#rows tr')
    .filter({ hasText: 'Long application name' })
    .first()
    .locator('.name')
    .click();
  await page.screenshot({ path: path.join(evidence, 'long-path-narrow.png') });
  const grip = page.locator('#activityView .sidebar-grip');
  await grip.focus();
  const widthBefore = await page
    .locator('#activityView > aside')
    .evaluate((e) => e.getBoundingClientRect().width);
  await page.keyboard.press('ArrowLeft');
  assert.notEqual(
    await page.locator('#activityView > aside').evaluate((e) => e.getBoundingClientRect().width),
    widthBefore,
  );
  const edge = await page.locator('.col-name .column-grip').boundingBox();
  await page.mouse.move(edge.x + 2, edge.y + 4);
  await page.mouse.down();
  await page.mouse.move(edge.x + 22, edge.y + 4);
  await page.mouse.up();
  empty = true;
  await sleep(1200);
  await page.screenshot({ path: path.join(evidence, 'empty.png') });
  if (stage !== 'before') {
    assert.equal(metrics['#tree thead'].height, 40);
    assert.equal(metrics['#rows tr'].height, 24);
    assert.equal(metrics['#rows .application-icon'].width, 16);
    assert.equal(metrics['.filterbar'].height, 33);
    assert.equal(metrics.narrow.header, 40);
    assert(Math.abs(metrics.narrow.sidebar - 860 * 0.38) < 2);
    assert(metrics.narrow.overflow);
  }
  empty = false;
  await sleep(1200);
  await page.click('#rulesTab');
  await page.locator('#ruleRows tr').first().click();
  await page.click('#editRule');
  await page.waitForSelector('#ruleEditor');
  await page.fill('#editAddress', '2001:db8:1234:5678:abcd:ef01:2345:6789');
  await page.focus('#editAddress');
  await page.evaluate(() => document.querySelector('#editAddress').setSelectionRange(2, 12));
  await sleep(1200);
  assert.equal(await page.inputValue('#editAddress'), '2001:db8:1234:5678:abcd:ef01:2345:6789');
  assert.equal(await page.evaluate(() => document.querySelector('#editAddress').selectionStart), 2);
  await page.screenshot({ path: path.join(evidence, 'editor-narrow.png') });
  await page.click('#minimizeEditor');
  pending = true;
  await sleep(1200);
  await page.evaluate(() => window.flowgate.openPrompt('fixture-pending'));
  const prompt = await app
    .waitForEvent('window', { timeout: 3000 })
    .catch(() => app.windows().find((p) => p !== page));
  await prompt.waitForSelector('#allow');
  await prompt.screenshot({ path: path.join(evidence, 'prompt-synthetic.png') });
  await prompt.evaluate(() => window.flowgate.dismissPrompt());
  fs.writeFileSync(path.join(evidence, 'metrics.json'), JSON.stringify(metrics, null, 2));
  console.log(
    'PASS actual sandboxed Wayland synthetic Activity, rate sort toggle, IPv6 search, policy access; captures ' +
      evidence,
  );
} finally {
  clearInterval(timer);
  if (app) {
    await app.evaluate(({ app }) => app.exit()).catch(() => {});
    await app.close().catch(() => {});
  }
  server.close();
  monitor.close();
  if (old) fs.writeFileSync(pref, old);
  else fs.rmSync(pref, { force: true });
}
