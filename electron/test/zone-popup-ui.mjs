// Sandboxed native Electron + synthetic Unix API. No daemon, TC, firewall or traffic.
// Run from the repository root inside the documented capped user scope after npm run build.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
fs.mkdirSync(path.join(root, '.workspace/zone-popup'), { recursive: true });
const dir = fs.mkdtempSync(path.join(root, '.workspace/zone-popup/native-'));
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
        'experimental-traffic-priority-v1',
        'experimental-zone-shaping-v1',
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
        name: `${direction === 'priority' ? 'Traffic priority' : direction === 'upload' ? 'Upload limit' : 'Download limit'} for Synthetic alpha`,
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
    await wait(() => page.locator('#uploadZone').isEnabled(), 'reviewed configuration');
  }
  async function close() {
    await page.keyboard.press('Escape');
    await popup.waitFor({ state: 'detached' });
  }
  const zone = (name) => page.locator('#uploadZone').selectOption(name);
  const own = (scope) => caps.find(c => (c.scope || 'all') === scope);
  async function saveRate(direction, scope, rate) {
    await open(direction); await zone(scope);
    await page.locator('#uploadRate').fill(rate);
    await page.locator('#uploadSave').click();
    await popup.waitFor({state:'detached'});
  }
  await open('upload');
  assert.equal(await page.locator('#uploadZone').inputValue(),'all');
  const before=await popup.boundingBox();
  await page.locator('#uploadRate').fill('17');
  await zone('internet'); await page.locator('#uploadRate').fill('4');
  await zone('local'); await page.locator('#uploadRate').fill('7');
  await zone('internet'); assert.equal(await page.locator('#uploadRate').inputValue(),'4');
  await zone('all'); assert.equal(await page.locator('#uploadRate').inputValue(),'17');
  await sleep(2000); assert.equal(await page.locator('#uploadRate').inputValue(),'17');
  assert.deepEqual(await popup.boundingBox(),before); assert.equal(writes().length,0);
  await close(); assert.equal(writes().length,0);
  evidence.steps.push({label:'zone drafts survive switches and refresh; cancel is mutation-free; placement stable',bounds:before});
  await saveRate('upload','all','12');
  await saveRate('download','all','20');
  await saveRate('upload','internet','4');
  await saveRate('download','internet','6');
  await saveRate('upload','local','8');
  await saveRate('download','local','9');
  assert.equal(own('all').bits_per_second,12000000);assert.equal(own('all').download_bits_per_second,20000000);
  assert.equal(own('internet').bits_per_second,4000000);assert.equal(own('internet').download_bits_per_second,6000000);
  assert.equal(own('local').bits_per_second,8000000);assert.equal(own('local').download_bits_per_second,9000000);
  await open('upload'); await zone('internet');
  assert.equal(await page.locator('#uploadRate').inputValue(),'4');
  assert.equal(await page.locator('#uploadZoneHint').textContent(),'All applies');
  await popup.screenshot({path:dir+'/internet-upload-popup.png'});await page.screenshot({path:dir+'/internet-upload-native.png'});
  await page.locator('#uploadRate').fill('5');await page.locator('#uploadRate').press('Enter');await popup.waitFor({state:'detached'});
  await open('download');await zone('local');await popup.screenshot({path:dir+'/local-download-popup.png'});await close();
  await open('priority');await page.locator('#priorityLevel').selectOption('high');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});
  await open('priority');await zone('internet');await page.locator('#priorityLevel').selectOption('normal');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});
  assert.equal(own('internet').traffic_priority,'normal');assert.equal(own('all').traffic_priority,'high');
  await open('priority');await zone('internet');await popup.screenshot({path:dir+'/internet-priority-popup.png'});
  await page.locator('#uploadRemove').click();await popup.waitFor({state:'detached'});
  assert.equal(own('internet').traffic_priority,undefined);assert.equal(own('all').traffic_priority,'high');
  await open('upload');await zone('internet');await page.locator('#uploadRemove').click();await popup.waitFor({state:'detached'});
  assert.equal(own('internet').bits_per_second,0);assert.equal(own('internet').download_bits_per_second,6000000);
  assert.equal(own('local').bits_per_second,8000000);assert.equal(own('all').bits_per_second,12000000);
  evidence.steps.push({label:'create both directions in three scopes; edit/Enter; explicit Normal then Delete; delete Internet UL preserves Internet DL, Local and All',caps:structuredClone(caps)});
  await page.getByText('Synthetic alpha',{exact:true}).first().click();
  const infoButton=page.locator('#infoRules').getByRole('button',{name:'Download limit for Synthetic alpha',exact:true});
  await infoButton.click();await popup.waitFor();await wait(()=>page.locator('#uploadZone').isEnabled());await zone('local');
  assert.equal(await page.locator('#uploadRate').inputValue(),'9');await popup.screenshot({path:dir+'/info-local-popup.png'});await close();
  await page.locator('#infoPaneControls summary').click();await page.locator('[data-undock="info"]').click();
  const detached=await wait(()=>app.windows().find(w=>w.url().includes('pane.html')&&w.url().includes('info')),'detached Info');
  await detached.getByRole('button',{name:'Download limit for Synthetic alpha',exact:true}).click();
  const detachedPopup=detached.locator('#uploadLimitDialog');await detachedPopup.waitFor();await wait(()=>detached.locator('#uploadZone').isEnabled());
  await detached.locator('#uploadZone').selectOption('local');assert.equal(await detached.locator('#uploadRate').inputValue(),'9');
  await detachedPopup.screenshot({path:dir+'/detached-info-local-popup.png'});await detached.screenshot({path:dir+'/detached-info-native.png'});
  await detached.locator('#uploadRate').fill('10');await detached.locator('#uploadSave').click();await detachedPopup.waitFor({state:'detached'});
  assert.equal(own('local').download_bits_per_second,10000000);assert.equal(own('internet').download_bits_per_second,6000000);assert.equal(own('all').download_bits_per_second,20000000);
  await detached.locator('#dockPane').click();evidence.steps.push({label:'detached Info own Local DL edit preserves Internet and All'});
  const count=writes().length;
  await open('upload');await zone('local');await page.locator('#uploadRate').fill('7');version++;
  await wait(()=>page.locator('#uploadSave').isDisabled(),'stale scope edit');assert.equal(await page.locator('#uploadRate').inputValue(),'7');await close();assert.equal(writes().length,count);
  assert(writes().every(r=>r.q.upload_config.schema===3));
  assert.equal(evidence.errors.length,0);evidence.steps.push({label:'Info consistency and stale scope draft; schema3 writes only'});evidence.pass=true;
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
