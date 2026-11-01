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
fs.mkdirSync(path.join(root, '.workspace/acceptance-gui-not-running'), { recursive: true });
const dir = fs.mkdtempSync(path.join(root, '.workspace/acceptance-gui-not-running/run-'));
const client = path.join(dir, 'client');
fs.mkdirSync(client + '/electron', { recursive: true });
fs.cpSync(GUI + '/electron/dist', client + '/electron/dist', { recursive: true });
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
const savedRules = [{ id: 'user:synthetic-beta-allow', version: 1, action: 'allow', priority: 100, created: '2026-11-01T10:00:00Z', executable: '/synthetic/beta', filter: { application: 'synthetic-native-beta', revision: 'synthetic-beta-revision', uid: 1000, direction: 'outgoing', protocol: 'udp' } }];
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
      rules: savedRules,
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
  scope: 'Native sandboxed exact 93eaa868 GUI bundle, synthetic API only. Not running group + selection across refreshes; no daemon.',
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


  const obs = { checks: {} };
  const rowsText = async () => page.locator('#rows tr').evaluateAll(trs => trs.map(t => ({ id: t.dataset.id, text: t.innerText.split('\n').map(x => x.trim()).filter(x => x && !/^[▷◢▽◿▸▾]$/.test(x))[0] || '', sel: t.getAttribute('aria-selected') })));
  await wait(async () => (await rowsText()).some(r => r.text.startsWith('Not running (1)')), 'Not running group');
  await page.locator('#expand').click();
  await wait(async () => (await rowsText()).some(r => r.text.startsWith('beta')), 'inactive beta row');
  let rows = await rowsText(); obs.initial_rows = rows;
  const gi = rows.findIndex(r => r.text.startsWith('Not running (1)')), bi = rows.findIndex(r => r.text.startsWith('beta')), ai = rows.findIndex(r => r.text.startsWith('Synthetic alpha'));
  obs.checks.group_separate_and_after_running = gi > ai && bi > gi && await page.locator('#rows tr').nth(gi).isVisible();
  const betaId = rows[bi].id, alphaId = rows[ai].id; obs.ids = { betaId, alphaId, groupId: rows[gi].id };
  const sel = async (id) => (await rowsText()).find(r => r.id === id)?.sel === 'true';
  const settle = async (n) => { for (let i = 0; i < n; i++) { await page.locator('#refreshNow').click(); await sleep(700); } };
  await page.locator('#rows tr[data-id="'+betaId+'"]').click();
  obs.checks.beta_selected = await sel(betaId);
  obs.beta_info = await page.locator('#selectedName').innerText();
  const seq0 = sequence; await settle(4); obs.list_polls_during_refresh = sequence - seq0;
  obs.checks.beta_selection_survives_refreshes = await sel(betaId) && (await page.locator('#selectedName').innerText()) === obs.beta_info;
  rows = await rowsText(); obs.checks.group_still_separate_after_refresh = rows.some(r => r.text.startsWith('Not running (1)')) && rows.findIndex(r => r.text.startsWith('Not running (1)')) > rows.findIndex(r => r.id === alphaId);
  await page.locator('#rows tr[data-id="'+alphaId+'"]').click();
  obs.checks.alpha_selected = await sel(alphaId);
  await settle(3);
  obs.checks.alpha_selection_survives_refreshes = await sel(alphaId) && !(await sel(betaId));
  obs.checks.refreshes_actually_polled = obs.list_polls_during_refresh >= 2;
  await page.screenshot({ path: dir + '/not-running.png' });
  evidence.observations = obs; evidence.steps.push({ label: 'Not running group + selection stability', checks: obs.checks });
  evidence.pass = Object.values(obs.checks).every(Boolean) && evidence.errors.length === 0;
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
