// Sandboxed native Electron + synthetic Unix API. No daemon, TC, firewall or traffic.
// Run from the repository root inside the documented capped user scope after npm run build.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
fs.mkdirSync(path.join(root, '.workspace/limiter-parity'), { recursive: true });
const dir = fs.mkdtempSync(path.join(root, '.workspace/limiter-parity/native-'));
const client = path.join(dir, 'client');
fs.mkdirSync(client + '/electron', { recursive: true });
fs.cpSync(root + '/electron/dist', client + '/electron/dist', { recursive: true });
fs.copyFileSync(root + '/electron/package.json', client + '/electron/package.json');
fs.mkdirSync(client + '/.workspace/tmp', { recursive: true });
const appIdentity = {
  key: 'synthetic-native-alpha',
  revision: 'synthetic-revision',
  kind: 'native',
  name: 'Synthetic alpha',
  executable: '/synthetic/alpha',
};
const process = {
  id: '42:100',
  pid: 42,
  start_ticks: '100',
  uid: 1000,
  application: appIdentity,
  executable: appIdentity.executable,
};
const requests = [],
  sockets = new Set(),
  servers = [];
let version = 1,
  caps = [],
  sequence = 1,
  generation = 'synthetic-gen',
  readOnly = false,
  refuse = false,
  drop = false,
  holdStatus = false;
const pendingStatus = [];
function status() {
  return {
    version,
    applied_version: version,
    enabled: caps.length > 0,
    interface: 'synthetic0',
    status: caps.length ? 'Partial' : 'Disabled',
    configured_caps: caps,
    coverage_valid_for_ms: 10000,
    kernel: {
      bindings: caps.map((c) => ({
        app: c.uid + ':' + c.application,
        covered: true,
        download: !!c.download_bits_per_second,
      })),
      covered_bindings: caps.length,
    },
  };
}
function reply(q, monitor) {
  const now = new Date().toISOString(),
    r = { version: 1, generation, read_only: monitor || readOnly, server_time: now };
  if (q.operation === 'list')
    return {
      ...r,
      mode: monitor ? 'host-monitor' : 'daemon-monitor',
      events: [],
      rules: [],
      capabilities: [
        'explicit-administrator-v1',
        'experimental-native-upload-v1',
        'experimental-native-download-v1',
      ],
      permissions: {
        role: 'administrator',
        observation_scope: 'machine',
        policy_scope: 'machine',
        can_manage_rules: false,
        can_manage_machine_rules: false,
        can_decide: false,
      },
      activity: {
        sequence: ++sequence,
        collected: now,
        complete: true,
        issues: [],
        inaccessible_processes: 0,
        processes: { [process.id]: process },
        rows: [
          {
            id: 'synthetic-socket',
            ownership: 'Visible descriptor holder',
            ownership_category: 'visible-holder',
            owners: [process.id],
            state: 'Established',
            direction: 'Outgoing',
            socket: {
              family: 2,
              protocol: 'tcp',
              local: '192.0.2.1:40001',
              remote: '198.51.100.1:443',
              state: 1,
              inode: 42,
              cookie: 'synthetic-cookie',
              uid: 1000,
              netns: 'net:[synthetic]',
            },
            traffic: { available: false, state: 'unavailable', reason: 'Synthetic UI fixture' },
          },
        ],
      },
    };
  if (q.operation === 'upload-status') return { ...r, upload_shaping: status() };
  if (q.operation === 'upload-configure') {
    if (monitor || readOnly)
      return { ...r, error_code: 'forbidden', error: 'Synthetic read-only controller' };
    if (refuse)
      return { ...r, error_code: 'synthetic_refusal', error: 'Synthetic configuration refusal' };
    if (q.generation !== generation || q.expected_version !== version)
      return { ...r, error_code: 'version_conflict', error: 'Configuration changed' };
    caps = structuredClone(q.upload_config.caps);
    version++;
    return drop ? null : { ...r, upload_shaping: status() };
  }
  return { ...r, error_code: 'unsupported', error: 'Synthetic operation unsupported' };
}
for (const [name, monitor] of [
  ['control.sock', false],
  ['monitor.sock', true],
]) {
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let input = '';
    socket.on('data', async (b) => {
      input += b;
      if (!input.includes('\n')) return;
      const q = JSON.parse(input.split('\n')[0]);
      requests.push({ socket: name, q });
      if (q.operation === 'upload-status' && holdStatus)
        await new Promise((resolve) => pendingStatus.push(resolve));
      const response = reply(q, monitor);
      if (response === null) return socket.destroy();
      socket.end(JSON.stringify(response) + '\n');
    });
  });
  await new Promise((resolve) => server.listen(dir + '/' + name, resolve));
  fs.chmodSync(dir + '/' + name, 0o600);
  servers.push(server);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, label = 'condition') => {
  for (let end = Date.now() + 15000; Date.now() < end;) {
    const value = await fn();
    if (value) return value;
    await sleep(100);
  }
  throw Error('Timeout: ' + label);
};
const writes = () => requests.filter((r) => r.q.operation === 'upload-configure');
const evidence = {
  scope: 'Native sandboxed Electron, synthetic API only. No shaping/enforcement/receiver proof.',
  run: dir,
  steps: [],
  errors: [],
  pass: false,
};
let app, page;
try {
  app = await _electron.launch({
    executablePath: root + '/electron/node_modules/electron/dist/electron',
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      client + '/electron',
      '--observer',
      dir + '/monitor.sock',
      '--control',
      dir + '/control.sock',
    ],
    env: {
      ...globalThis.process.env,
      TMPDIR: client + '/.workspace/tmp',
      XDG_CACHE_HOME: dir + '/cache',
    },
  });
  await app.firstWindow();
  page = await wait(
    () => app.windows().find((w) => w.url() === 'flowgate://app/index.html'),
    'main window',
  );
  page.on('pageerror', (e) => evidence.errors.push(String(e)));
  page.on('console', (m) => {
    if (m.type() === 'error') evidence.errors.push(m.text());
  });
  await app.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows().find(
      (w) => w.webContents.getURL() === 'flowgate://app/index.html',
    );
    w.show();
    w.restore();
    w.focus();
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  const slot = (direction) =>
    page
      .getByRole('button', {
        name: `${direction === 'upload' ? 'Upload' : 'Download'} limit for Synthetic alpha`,
        exact: true,
      })
      .first();
  await wait(async () => {
    if ((await slot('upload').count()) && (await slot('upload').isVisible())) return true;
    await page.locator('#expand').click();
    return false;
  }, 'native candidate');
  const popup = page.locator('#uploadLimitDialog');
  async function open(direction) {
    await slot(direction).click();
    await popup.waitFor();
    await wait(() => page.locator('#uploadSave').isEnabled(), 'reviewed configuration');
  }
  async function close() {
    await page.keyboard.press('Escape');
    await popup.waitFor({ state: 'detached' });
  }
  async function geometry(label) {
    const m = await popup.evaluate((d) => {
      const box = (e) => {
          const r = e.getBoundingClientRect();
          return { x: r.x, y: r.y, width: r.width, height: r.height };
        };
      return {
        popup: box(d),
        checkbox: box(d.querySelector('#uploadEnabled')),
        rate: box(d.querySelector('#uploadRate')),
        units: box(d.querySelector('#uploadUnits')),
        ok: box(d.querySelector('#uploadSave')),
        heading: d.querySelector('#uploadLimitTitle').textContent,
        scopes: [...d.querySelectorAll('#uploadZone label')].map((e) => e.textContent),
        focused: document.activeElement?.id,
        selection: [
          d.querySelector('#uploadRate').selectionStart,
          d.querySelector('#uploadRate').selectionEnd,
        ],
      };
    });
    assert(m.popup.width >= 360);
    assert(m.rate.height >= 34 && m.ok.height >= 34);
    assert(m.units.x >= m.rate.x + m.rate.width);
    assert(m.ok.y >= m.rate.y + m.rate.height);
    assert.equal(m.heading, 'Synthetic alpha');
    assert.deepEqual(m.scopes, ['Any', 'Internet', 'Local']);
    assert.equal(m.focused, 'uploadRate');
    assert.equal(m.selection[0], 0);
    assert.equal(m.selection[1], (await page.locator('#uploadRate').inputValue()).length);
    evidence.steps.push({ label, ...m });
    return m;
  }
  await open('upload');
  await geometry('upload initial');
  assert.equal(await page.locator('#uploadDetails').textContent(), 'Details');
  assert.deepEqual(await page.locator('#uploadUnits option').allTextContents(), [
    'B/s',
    'KB/s',
    'MB/s',
    'GB/s',
    'bit/s',
    'Kbit/s',
    'Mbit/s',
    'Gbit/s',
  ]);
  await page.screenshot({ path: dir + '/upload-1280.png' });
  await popup.screenshot({ path: dir + '/upload-popup.png' });
  await page.locator('#uploadUnits').focus();
  await page.keyboard.press('Space');
  await sleep(250);
  assert(await page.locator('#uploadUnits').evaluate((e) => e.matches(':open')));
  evidence.steps.push(
    await page.locator('#uploadUnits').evaluate((e) => {
      const p = getComputedStyle(e, '::picker(select)');
      return {
        label: 'units picker',
        open: e.matches(':open'),
        appearance: getComputedStyle(e).appearance,
        picker: {
          display: p.display,
          height: p.height,
          maxHeight: p.maxHeight,
          opacity: p.opacity,
          top: p.top,
          left: p.left,
        },
        options: [...e.options].map((o) => ({
          text: o.textContent,
          rect: o.getBoundingClientRect().toJSON(),
          visible: getComputedStyle(o).visibility,
        })),
      };
    }),
  );
  await page.screenshot({ path: dir + '/units-1280.png' });
  await page.keyboard.press('Escape');
  assert.equal(await popup.count(), 1, 'Escape closes only the open units picker first');
  await page.locator('#uploadRate').fill('12');
  await sleep(2500);
  assert.equal(await page.locator('#uploadRate').inputValue(), '12');
  assert.equal(writes().length, 0);
  await close();
  assert.equal(writes().length, 0);
  assert(await slot('upload').evaluate((e) => e === document.activeElement));
  await open('upload');
  await page.locator('.brand').click();
  await popup.waitFor({ state: 'detached' });
  assert.equal(writes().length, 0);
  holdStatus = true;
  await slot('upload').click();
  await popup.waitFor();
  await wait(() => pendingStatus.length > 0);
  await page.locator('#uploadEnabled').check();
  await page.locator('#uploadRate').fill('12');
  await page.locator('#uploadUnits').selectOption('KB/s');
  await page.locator('#uploadUnits').focus();
  holdStatus = false;
  for (const resolve of pendingStatus.splice(0)) resolve();
  await wait(() => page.locator('#uploadSave').isEnabled());
  assert.equal(await page.locator('#uploadRate').inputValue(), '1464.84375');
  assert(await page.locator('#uploadUnits').evaluate((e) => e === document.activeElement));
  assert.equal(writes().length, 0);
  evidence.steps.push({ label: 'delayed status preserves edited draft and units focus' });
  await close();
  await open('download');
  await geometry('download initial');
  await page.screenshot({ path: dir + '/download-1280.png' });
  await popup.screenshot({ path: dir + '/download-popup.png' });
  await page.locator('#uploadRate').fill('16');
  await page.locator('#uploadSave').click();
  await popup.waitFor({ state: 'detached' });
  assert.equal(writes().length, 1);
  assert.equal(caps[0].download_bits_per_second, 16000000);
  assert.equal(caps[0].bits_per_second, 0);
  await open('upload');
  await page.locator('#uploadUnits').selectOption('B/s');
  assert.equal(await page.locator('#uploadRate').inputValue(), '1000000');
  await page.locator('#uploadUnits').selectOption('KB/s');
  assert.equal(await page.locator('#uploadRate').inputValue(), '976.5625');
  await page.locator('#uploadUnits').selectOption('Mbit/s');
  assert.equal(await page.locator('#uploadRate').inputValue(), '8');
  await page.locator('#uploadRate').press('Enter');
  await popup.waitFor({ state: 'detached' });
  assert.equal(writes().length, 2);
  assert.equal(caps[0].bits_per_second, 8000000);
  assert.equal(caps[0].download_bits_per_second, 16000000);
  await open('download');
  await page.locator('#uploadRemove').click();
  await popup.waitFor({ state: 'detached' });
  assert.equal(writes().length, 3);
  assert.equal(caps[0].bits_per_second, 8000000);
  assert.equal(caps[0].download_bits_per_second, undefined);
  await open('upload');
  await page.locator('#uploadRate').fill('99999');
  await page.locator('#uploadSave').click();
  assert.equal(writes().length, 3);
  assert(await page.locator('#uploadDetailsBody').isVisible());
  assert.match(await page.locator('#uploadCoverage').textContent(), /1–1000/);
  await close();
  await open('upload');
  await page.locator('#uploadRate').fill('9');
  version++;
  await wait(() => page.locator('#uploadSave').isDisabled(), 'stale CAS locks save');
  assert.equal(await page.locator('#uploadRate').inputValue(), '9');
  assert.equal(writes().length, 3);
  await page.locator('#uploadDetails').click();
  await page.locator('#uploadRefresh').click();
  await wait(() => page.locator('#uploadSave').isEnabled());
  assert.equal(await page.locator('#uploadRate').inputValue(), '8');
  await close();
  await open('upload');
  refuse = true;
  await page.locator('#uploadSave').click();
  await wait(async () =>
    (await page.locator('#uploadCoverage').textContent()).includes(
      'Synthetic configuration refusal',
    ),
  );
  assert(await popup.isVisible());
  assert.equal(writes().length, 4);
  refuse = false;
  await close();
  await open('upload');
  drop = true;
  await page.locator('#uploadRate').fill('10');
  await page.locator('#uploadSave').click();
  await wait(async () =>
    (await page.locator('#uploadCoverage').textContent()).includes('no automatic retry'),
  );
  assert.equal(writes().length, 5);
  assert(await page.locator('#uploadSave').isDisabled());
  assert.equal(caps[0].bits_per_second, 10000000);
  await sleep(1600);
  assert.equal(writes().length, 5);
  drop = false;
  await page.locator('#uploadRefresh').click();
  await wait(() => page.locator('#uploadSave').isEnabled());
  assert.equal(await page.locator('#uploadRate').inputValue(), '10');
  assert.equal(writes().length, 5);
  await close();
  await open('upload');
  await page.locator('#uploadEnabled').uncheck();
  await page.locator('#uploadSave').click();
  await popup.waitFor({ state: 'detached' });
  assert.deepEqual(caps, []);
  assert.equal(writes().length, 6);
  await page.getByText('Synthetic alpha', { exact: true }).first().click();
  const infoUpload = page
    .locator('#infoRules')
    .getByRole('button', { name: 'Upload limit for Synthetic alpha', exact: true });
  const infoDownload = page
    .locator('#infoRules')
    .getByRole('button', { name: 'Download limit for Synthetic alpha', exact: true });
  for (const [direction, button] of [
    ['upload', infoUpload],
    ['download', infoDownload],
  ]) {
    await button.click();
    await popup.waitFor();
    await wait(() => page.locator('#uploadSave').isEnabled());
    await geometry(direction + ' Info View');
    await close();
  }
  await page.setViewportSize({ width: 800, height: 600 });
  await open('download');
  await geometry('download 800');
  await page.screenshot({ path: dir + '/download-800.png' });
  await page.locator('#uploadDetails').click();
  assert(await page.locator('#uploadDetailsBody summary').isVisible());
  assert.equal(await page.locator('#uploadDetailsBody details').getAttribute('open'), null);
  assert.doesNotMatch(await page.locator('#uploadDetailsBody').innerText(), /0 confirmed \/ 0 requested|UDP GSO/);
  assert.match(
    await page.locator('#uploadDetailsBody').innerText(),
    /Established TCP only/,
  );
  await page.locator('#uploadDetailsBody summary').click();
  assert.match(await page.locator('#uploadDetailsBody').innerText(), /UDP GSO/);
  await page.locator('#uploadDetailsBody summary').click();
  await page.setViewportSize({ width: 360, height: 240 });
  await sleep(200);
  const bounds = await popup.boundingBox();
  assert(
    bounds.x >= 0 &&
      bounds.y >= 0 &&
      bounds.x + bounds.width <= 360 &&
      bounds.y + bounds.height <= 240,
  );
  evidence.steps.push({ label: 'expanded 360x240', bounds });
  await page.screenshot({ path: dir + '/expanded-360.png' });
  await close();
  await page.setViewportSize({ width: 1280, height: 720 });
  await open('upload');
  readOnly = true;
  await page.locator('#uploadDetails').click();
  await page.locator('#uploadRefresh').click();
  await wait(() => page.locator('#uploadSave').isDisabled(), 'read-only');
  assert(await page.locator('#uploadRemove').isDisabled());
  assert.equal(writes().length, 6);
  await close();
  assert.equal(evidence.errors.length, 0);
  evidence.pass = true;
} catch (e) {
  evidence.error = String(e);
  if (page) {
    evidence.body = await page.locator('body').innerText();
    await page.screenshot({ path: dir + '/failure.png' });
  }
  throw e;
} finally {
  if (app) await app.close();
  for (const socket of sockets) socket.destroy();
  for (const server of servers) await new Promise((r) => server.close(r));
  evidence.requests = requests;
  fs.writeFileSync(dir + '/evidence.json', JSON.stringify(evidence, null, 2));
  console.log(
    dir,
    JSON.stringify({
      pass: evidence.pass,
      error: evidence.error,
      errors: evidence.errors,
      steps: evidence.steps,
    }),
  );
}
