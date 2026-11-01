// Sandboxed native Electron + synthetic Unix API. No daemon, TC, firewall or traffic.
// Run from the repository root inside the documented capped user scope after npm run build.
import { createRequire } from 'node:module';
const { _electron } = createRequire('/home/flowgate-user/Apps/flowgate/electron/node_modules/')('playwright-core');
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = '/home/flowgate-user/Apps/flowgate';
const GUI = '/home/flowgate-user/Apps/flowgate/.workspace/automatic-zone-releases/93eaa868ec2a1f98c0b66b27a682e2f332a23746';
fs.mkdirSync(path.join(root, '.workspace/cgui'), { recursive: true });
const dir = fs.mkdtempSync(path.join(root, '.workspace/cgui/run-'));
const client = path.join(dir, 'client');
fs.mkdirSync(client + '/electron', { recursive: true });
fs.cpSync('/home/flowgate-user/Apps/flowgate/.workspace/acceptance-corrections/electron/dist', client + '/electron/dist', { recursive: true });
fs.copyFileSync(GUI + '/electron/package.json', client + '/electron/package.json');
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
      network_zones: {model:'automatic-peer-v1',revision:'synthetic-zones',local_prefixes:[],internet_prefixes:[],reason:'Synthetic UI classification definition'},
      events: [],
      rules: [],
      capabilities: [
        'explicit-administrator-v1',
        'experimental-native-upload-v1',
        'experimental-native-download-v1',
        'experimental-traffic-priority-v1',
        'experimental-zone-shaping-v1',
        'network-zone-policy-v1',
        'automatic-network-zones-v1',
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
  scope: 'Native sandboxed correction GUI built separately from 93eaa868, synthetic API only. Request/stored-result of zone priority inheritance; no shaping/enforcement/receiver proof.',
  run: dir,
  steps: [],
  errors: [],
  pass: false,
};
let app, page;
try {
  app = await _electron.launch({
    executablePath: GUI + '/runtime/electron',
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
        // 93eaa868 paintAvailability() relabels slots as '<kind> for <row>'.
        name: `${direction} for Synthetic alpha`,
        exact: true,
      })
      .first();
  await wait(async () => {
    if ((await slot('upload').count()) && (await slot('upload').isVisible())) return true;
    await page.locator('#expand').click();
    return false;
  }, 'native candidate').catch(async (e) => {
    evidence.slot_labels = await page.locator('button[aria-label*="Synthetic alpha"]').evaluateAll(bs => bs.map(b => b.getAttribute('aria-label')));
    throw e;
  });
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

  // Expected (intended spec): a rate save never changes priority inheritance; opening the
  // Priority popup in a zone without its own priority and confirming unchanged must not
  // silently create an explicit override. Observations are recorded, not asserted, so
  // every case is captured; the verdicts are computed afterwards.
  const obs = {};
  const lastWrite = () => structuredClone(writes().at(-1)?.q?.upload_config?.caps);
  // Setup: All networks High via the real popup.
  await open('priority'); await page.locator('#priorityLevel').selectOption('high');
  await page.locator('#uploadSave').click(); await popup.waitFor({state:'detached'});
  obs.setup = { all: own('all') };
  // Case 1: Local UL rate save only.
  await saveRate('upload', 'local', '4');
  obs.rate_save_local = { request_caps: lastWrite(), stored_local: own('local'), stored_all: own('all') };
  // Case 2: Internet priority popup, untouched, OK.
  await open('priority'); await zone('internet');
  obs.internet_popup_preselected = await page.locator('#priorityLevel').inputValue();
  obs.internet_popup_hint = await page.locator('#uploadLimitDialog').innerText();
  const before2 = writes().length;
  obs.internet_save_enabled = await page.locator('#uploadSave').isEnabled();
  if (obs.internet_save_enabled) { await page.locator('#uploadSave').click(); await popup.waitFor({state:'detached'}); } else await close();
  obs.untouched_ok_internet = { wrote: writes().length > before2, request_caps: lastWrite(), stored_internet: own('internet') ?? null, stored_all: own('all') };
  // Case 3: Local (has own rate, no own priority) priority popup, untouched, OK.
  await open('priority'); await zone('local');
  obs.local_popup_preselected = await page.locator('#priorityLevel').inputValue();
  const before3 = writes().length;
  obs.local_save_enabled = await page.locator('#uploadSave').isEnabled();
  if (obs.local_save_enabled) { await page.locator('#uploadSave').click(); await popup.waitFor({state:'detached'}); } else await close();
  obs.untouched_ok_local = { wrote: writes().length > before3, stored_local: own('local'), stored_all: own('all') };
  // Case 4: Local DL rate save after case 3 keeps whatever priority is stored.
  await saveRate('download', 'local', '6');
  obs.dl_rate_save_local = { stored_local: own('local') };
  obs.expect_preselect_inherited = obs.internet_popup_preselected === 'inherit' && obs.local_popup_preselected === 'inherit';
  const verdict = {
    preselects_inherited: obs.expect_preselect_inherited,
    rate_save_preserves_inheritance: obs.rate_save_local.stored_local?.traffic_priority === undefined && obs.rate_save_local.stored_all?.traffic_priority === 'high',
    untouched_priority_ok_preserves_inheritance_internet: !obs.untouched_ok_internet.wrote || obs.untouched_ok_internet.stored_internet === null || obs.untouched_ok_internet.stored_internet.traffic_priority === undefined,
    untouched_priority_ok_preserves_inheritance_local: !obs.untouched_ok_local.wrote || obs.untouched_ok_local.stored_local?.traffic_priority === undefined,
    later_rate_save_keeps_stored_priority: obs.dl_rate_save_local.stored_local?.traffic_priority === obs.untouched_ok_local.stored_local?.traffic_priority,
    schema3_only: writes().every(r => r.q.upload_config.schema === 3),
  };
  assert.equal(obs.internet_save_enabled,true);
  assert.equal(obs.untouched_ok_internet.wrote,false);
  assert.equal(obs.untouched_ok_local.wrote,false);
  assert.match(obs.internet_popup_hint,/Inherited: High/);
  await open('priority');await zone('all');await page.locator('#priorityLevel').selectOption('low');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});
  await open('priority');await zone('local');assert.equal(await page.locator('#priorityLevel').inputValue(),'inherit');assert.match(await page.locator('#uploadZoneHint').innerText(),/Inherited: Low/);
  const lowWrites=writes().length;await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});assert.equal(writes().length,lowWrites);
  const rates=()=>[own('local')?.bits_per_second,own('local')?.download_bits_per_second];const originalRates=rates();
  await open('priority');await zone('local');await page.locator('#priorityLevel').selectOption('normal');const changed=writes().length;await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});assert.equal(writes().length,changed+1);assert.equal(own('local').traffic_priority,'normal');assert.deepEqual(rates(),originalRates);
  await open('priority');await zone('local');assert.equal(await page.locator('#priorityLevel').inputValue(),'normal');assert.match(await page.locator('#uploadZoneHint').innerText(),/Override: Normal/);await page.locator('#uploadRemove').click();await popup.waitFor({state:'detached'});assert.equal(own('local').traffic_priority,undefined);assert.deepEqual(rates(),originalRates);
  await open('priority');await zone('local');assert.equal(await page.locator('#priorityLevel').inputValue(),'inherit');await page.locator('#priorityLevel').selectOption('low');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});assert.equal(own('local').traffic_priority,'low');assert.deepEqual(rates(),originalRates);
  verdict.low_inherited_untouched_zero_writes=true;verdict.explicit_normal_and_delete_preserve_rates=true;await open('priority');await zone('all');await page.locator('#priorityLevel').selectOption('high');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});assert.equal(own('local').traffic_priority,'low');assert.deepEqual(rates(),originalRates);
  await open('priority');await zone('local');assert.equal(await page.locator('#priorityLevel').inputValue(),'low');await page.locator('#priorityLevel').selectOption('inherit');await page.locator('#uploadSave').click();await popup.waitFor({state:'detached'});assert.equal(own('local').traffic_priority,undefined);assert.deepEqual(rates(),originalRates);
  verdict.explicit_equal_discoverable_and_stable_after_all_change=true;verdict.inherited_selection_removes_override=true;
  evidence.observations = obs; evidence.verdict = verdict;
  evidence.steps.push({label:'zone priority inheritance request/stored-result', verdict});
  evidence.pass = Object.values(verdict).every(Boolean);
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
