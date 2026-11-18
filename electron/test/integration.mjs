import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const root = process.cwd(),
  require = createRequire(path.join(root, 'electron/package.json')),
  { _electron } = require('playwright-core');
const run = fs.mkdtempSync(path.join(root, '.workspace/integrated-'));
let app, lab, fixture;
const log = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn) {
  let error;
  for (let end = Date.now() + 20000; Date.now() < end;) {
    try {
      let v = await fn();
      if (v) return v;
    } catch (e) {
      error = e;
    }
    await sleep(80);
  }
  throw Error('Timeout ' + String(error || fn));
}
function start(bin, args, name) {
  let p = spawn(bin, args, {
    cwd: root,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      TMPDIR: path.join(root, '.workspace/tmp'),
      PYTHONDONTWRITEBYTECODE: '1',
    },
  });
  let text = '';
  p.stdout.on('data', (b) => (text += b));
  p.stderr.on('data', (b) => (text += b));
  p.output = () => text;
  p.on('exit', () => fs.writeFileSync(path.join(run, name + '.log'), text));
  return p;
}
function command(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    let s = net.createConnection(path.join(run, 'demo.sock'));
    s.setTimeout(6000, () => s.destroy(Error('timeout')));
    s.on('error', reject);
    s.on('connect', () => s.write(JSON.stringify({ operation, ...fields })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
const received = () =>
  fs.readFileSync(path.join(run, 'receiver-44001.log'), 'utf8').split('RECEIVED').length - 1;
const q = (...args) => execFileSync('qdbus6', args, { encoding: 'utf8', timeout: 4000 }).trim();
const g = (bus, obj, method, ...args) =>
  execFileSync(
    'gdbus',
    ['call', '--session', '--dest', bus, '--object-path', obj, '--method', method, '--', ...args],
    { encoding: 'utf8', timeout: 4000 },
  ).trim();
try {
  lab = start('scripts/lab.sh', ['python3', 'scripts/acceptance/host-lab.py', run], 'lab');
  await wait(() => fs.existsSync(path.join(run, 'ready')));
  fixture = start(path.join(root, '.workspace/electron-traffic-fixture'), [], 'traffic');
  let info = await wait(() => {
    let line = fixture.output().split('\n')[0];
    return line.startsWith('{') ? JSON.parse(line) : null;
  });
  let launch = fs
    .readFileSync('electron/launch.py', 'utf8')
    .replace('ROOT = Path(__file__).resolve().parents[1]', `ROOT = Path(${JSON.stringify(root)})`)
    .replace(
      'a = p.parse_args()',
      `a, diagnostic_flags = p.parse_known_args()\nassert all(x.startswith(('--inspect=', '--remote-debugging-port=')) for x in diagnostic_flags)`,
    )
    .replace(
      '        if a.control:',
      '        args[1:1] = diagnostic_flags\n        if a.control:',
    );
  let launchPath = path.join(run, 'launch-debug.py');
  fs.writeFileSync(launchPath, launch, { mode: 0o700 });
  app = await _electron.launch({
    chromiumSandbox: true,
    executablePath: launchPath,
    args: ['--control', path.join(run, 'control.sock')],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0',
    },
  });
  let ep = app.process(),
    page = await app.firstWindow();
  await page.waitForFunction(() => !!window.flowgate);
  let snap = () => page.evaluate(() => window.flowgate.snapshot());
  await wait(async () => {
    let s = await snap();
    return s.control.connected && s.observation.connected && s.observation.activity?.rows.length;
  });
  assert(
    await app.evaluate(
      ({ BrowserWindow }) =>
        BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences().sandbox,
    ),
  );
  let mainPID = await app.evaluate(() => process.pid);
  assert(!fs.readFileSync(`/proc/${mainPID}/cmdline`, 'utf8').includes('--no-sandbox'));
  let observerPID = Number(
    fs
      .readFileSync(`/proc/${ep.pid}/task/${ep.pid}/children`, 'utf8')
      .trim()
      .split(/\s+/)
      .find((pid) => {
        try {
          return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('electron-observer');
        } catch {
          return false;
        }
      }),
  );
  assert(observerPID);
  let row = async () => {
    let s = await snap();
    return s.observation.activity.rows.find(
      (r) => r.socket.protocol === 'tcp' && r.socket.local.endsWith(':' + info.client4),
    );
  };
  await wait(async () => (await row())?.traffic.available);
  fixture.stdin.write('t\n');
  await wait(async () => {
    let r = await row();
    return (
      r?.traffic.uploaded === 262144 && r.traffic.downloaded === 131072 && r.traffic.upload_bps > 0
    );
  });
  await page.click('#activityTab');
  await page.locator('#search').fill(String(info.pid));
  await page.click('#expand');
  let socketId = (await row()).id;
  await page.locator('#tree tr[data-id=' + JSON.stringify(socketId) + ']').click();
  assert((await page.locator('#info').textContent()).includes('Visible holder'));
  assert((await page.locator('#info').textContent()).includes(String(info.pid)));
  await page.screenshot({ path: path.join(run, 'integrated-activity.png') });
  await page.locator('#search').fill('');
  assert((await row()).owners.length === 1);
  console.log(
    'PASS sandboxed Wayland Activity: real TCP measurements and current ownership details',
  );
  await command('send', { port: 44001 });
  await wait(async () =>
    (await snap()).control.events.some((e) => e.state === 'awaiting-decision'),
  );
  assert.equal(received(), 0);
  await page.click('#requestsTab');
  await page.locator('#requestRows tr').first().click();
  await page.click('#createRule');
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#saveRule');
  await wait(() => received() === 1);
  await page.click('#rulesTab');
  await wait(() => page.locator('#ruleRows tr').count());
  await page.locator('#ruleRows tr').first().click();
  await page.click('#editRule');
  await page.selectOption('#editAction', 'block');
  await page.click('#previewRule');
  await wait(() => page.locator('#saveRule').isEnabled());
  await page.click('#saveRule');
  await wait(async () => (await snap()).control.rules[0]?.action === 'block');
  await command('send', { port: 44001, source_port: 45201 });
  await sleep(300);
  assert.equal(received(), 1);
  console.log('PASS Electron create Allow delivers retained UDP; edit Block prevents new delivery');
  if (await page.locator('#closeEditor').isVisible()) await page.click('#closeEditor');
  await page.click('#deleteRule');
  await page.click('#confirmYes');
  await wait(async () => (await snap()).control.rules.length === 0);
  await command('send', { port: 44001, source_port: 45202 });
  await wait(async () =>
    (await snap()).control.events.some((e) => e.state === 'awaiting-decision'),
  );
  assert.equal(received(), 1);
  console.log('PASS Electron conditional Delete restores Ask without receiver delivery');
  await page.screenshot({ path: path.join(run, 'integrated-rules.png') });
  await wait(
    async () => (await page.evaluate(() => window.flowgate.backgroundStatus())).trayAvailable,
  );
  await page.check('#keepInTray');
  let winID = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].id);
  await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).close(), winID);
  assert.equal(
    await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), winID),
    false,
  );
  let bus = await wait(
    () =>
      q(
        'org.kde.StatusNotifierWatcher',
        '/StatusNotifierWatcher',
        'org.freedesktop.DBus.Properties.Get',
        'org.kde.StatusNotifierWatcher',
        'RegisteredStatusNotifierItems',
      )
        .split('\n')
        .find((s) => {
          try {
            return (
              Number(
                q(
                  'org.freedesktop.DBus',
                  '/org/freedesktop/DBus',
                  'org.freedesktop.DBus.GetConnectionUnixProcessID',
                  s.split('/')[0],
                ),
              ) === mainPID
            );
          } catch {
            return false;
          }
        })
        ?.split('/')[0],
  );
  const menu = () =>
    g(
      bus,
      '/StatusNotifierItem',
      'org.freedesktop.DBus.Properties.Get',
      'org.kde.StatusNotifierItem',
      'Menu',
    ).match(/objectpath '([^']+)'/)[1];
  const click = (label) => {
    g(bus, menu(), 'com.canonical.dbusmenu.AboutToShow', '0');
    let layout = g(bus, menu(), 'com.canonical.dbusmenu.GetLayout', '0', '1', "['label']"),
      match = new RegExp("\\((\\d+), \\{'label': <'" + label).exec(layout);
    assert(match, layout);
    g(bus, menu(), 'com.canonical.dbusmenu.Event', match[1], 'clicked', '<int32 0>', '0');
  };
  click('Open FlowGate');
  await wait(() =>
    app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), winID),
  );
  let deadline = (await snap()).control.enforcement.stops_at;
  await app.evaluate(({ dialog }) => {
    dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false });
  });
  click('Quit FlowGate UI');
  await wait(() => ep.exitCode !== null);
  await wait(() => !fs.existsSync(`/proc/${observerPID}`));
  assert.equal((await command('status')).state, 'active');
  console.log(
    'PASS real KDE tray hide/reopen/Quit; owned observer exits, independent controller remains active (Quit confirmation simulated)',
  );
  console.log('EVIDENCE', run);
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  try {
    await app?.close();
  } catch {}
  try {
    await command('quit');
  } catch {}
  if (lab && lab.exitCode === null)
    await Promise.race([new Promise((r) => lab.once('exit', r)), sleep(5000)]);
  for (let p of [fixture, lab]) if (p && p.exitCode === null) p.kill('SIGTERM');
}
