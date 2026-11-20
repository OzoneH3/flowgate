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
function request(id, name, direction) {
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
    deadline: new Date(start + 180000).toISOString(),
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
    },
  };
}
const first = request('atlas-sync', 'Atlas Sync', 'outgoing');
const second = request('long-client', 'Archive' + 'Synchronization'.repeat(10), 'incoming');
let events = [first, second];
function reply(q) {
  const now = new Date().toISOString();
  const r = { version: 1, generation, server_time: now, mode: 'isolated-lab', read_only: false };
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
      'network-zone-policy-v1',
    ],
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
      can_decide: true,
    },
    events,
    rules: [],
    activity: { sequence: 1, collected: now, complete: true, processes: {}, rows: [] },
  };
}
const server = net.createServer((socket) => {
  let input = '';
  socket.setEncoding('utf8').on('data', (chunk) => {
    input += chunk;
    if (input.includes('\n')) socket.end(JSON.stringify(reply(JSON.parse(input))) + '\n');
  });
});
await new Promise((resolve, reject) => server.once('error', reject).listen(endpoint, resolve));

let app;
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [client, '--observer', endpoint, '--control', endpoint],
    env: {
      ...process.env,
      XDG_CONFIG_HOME: path.join(run, 'config'),
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
  assert.deepEqual(await sheets(main), ['/style.css']);
  assert.deepEqual(await sheets(prompt), ['/permission-popup.css']);
  const shot = async (name) => {
    await prompt.evaluate(() => document.fonts.ready);
    await prompt.screenshot({ path: path.join(run, name + '.png') });
  };
  const size = () => prompt.evaluate(() => ({ width: innerWidth, height: innerHeight }));
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
    for (const id of ['allow', 'block']) {
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
  const remember = prompt.getByRole('checkbox', { name: 'Remember', exact: true });
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
  assert.match(await allow.getAttribute('title'), /Only this held connection/);
  const identity = await bounds('#requestIdentity'),
    peer = await bounds('#requestPeer');
  assert(peer.y >= identity.y + identity.height - 1);
  assert.equal(peer.y, (await bounds('#connectionHeader')).y);
  assert.deepEqual(await size(), { width: 745, height: 590 });
  await visibleActions();
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

  const originalAllow = await allow.elementHandle();
  await tabTo('rememberToggle');
  await prompt.keyboard.press('Space');
  await prompt.waitForFunction(() => document.querySelector('#rememberPanel')?.hidden === false);
  await prompt.waitForFunction(() => document.querySelector('#allow')?.disabled === false);
  await prompt.waitForFunction(() => innerHeight > 590);
  assert.equal(await active(), 'rememberToggle');
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
    assert(await remember.isChecked());
    assert.equal(await active(), 'rememberToggle');
    await shot('alternate');
  } finally {
    await native.evaluate((w, key) => w.webContents.removeInsertedCSS(key), key);
    await fs.unlink(alternate);
  }
  await prompt.keyboard.press('Space');
  assert.equal(await remember.isChecked(), false);
  await prompt.waitForFunction(
    () => innerHeight === 590 && !document.querySelector('#allow').disabled,
  );
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
  assert.equal(await remember.isChecked(), false);
  assert.match(await prompt.locator('#connectionHeader').innerText(), /Incoming/);
  assert.equal(await prompt.locator('#requestPeer .nl-label').textContent(), 'From');
  const name = second.attribution.application.name;
  assert(await prompt.getByRole('heading', { level: 1, name, exact: true }).isVisible());

  // Chromium viewport emulation keeps the desktop work area unchanged.
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
  await remember.check();
  await prompt.waitForFunction(() => !document.querySelector('#allow').disabled);
  await prompt.locator('#rememberDuration').scrollIntoViewIfNeeded();
  assert(await prompt.locator('#promptBody').evaluate((el) => el.scrollWidth <= el.clientWidth));
  assert.equal(decisions.length, 1);
  console.log(
    'PASS native popup layout, temporary stylesheet, focus, previews, keyboard Allow Once, queue and long labels.',
    run,
  );
} finally {
  await app?.close();
  server.close();
}
