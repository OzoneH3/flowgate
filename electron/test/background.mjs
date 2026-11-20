// Real KDE tray and automatic popup + isolated Go controller. No host enforcement.
import { _electron as electron } from 'playwright-core';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { call } = createRequire(import.meta.url)('../dist/test/backend.cjs');
const root = path.resolve(import.meta.dirname, '../..'),
  run = fs.mkdtempSync(path.join(root, '.workspace/bg-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function wait(fn, seconds = 15) {
  let error;
  for (const end = Date.now() + seconds * 1000; Date.now() < end;) {
    try {
      const r = await fn();
      if (r) return r;
    } catch (e) {
      error = e;
    }
    await sleep(80);
  }
  throw Error('Timed out ' + String(error || fn));
}
function command(operation, fields = {}) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(path.join(run, 'demo.sock'));
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('harness timeout')));
    s.on('connect', () => s.write(JSON.stringify({ operation, ...fields })));
    s.once('data', (b) => {
      s.destroy();
      resolve(JSON.parse(b));
    });
  });
}
const received = (port) =>
  (fs.readFileSync(path.join(run, `receiver-${port}.log`), 'utf8').match(/RECEIVED/g) || []).length;
const q = (...args) => execFileSync('qdbus6', args, { encoding: 'utf8', timeout: 4000 }).trim();
const g = (bus, obj, method, ...args) =>
  execFileSync(
    'gdbus',
    ['call', '--session', '--dest', bus, '--object-path', obj, '--method', method, '--', ...args],
    { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'pipe'] },
  );
let app, lab, monitor;
const notices = [],
  pendingReplies = new Map();
let block = '';
function parseBlock(text) {
  if (
    text.startsWith('method call') &&
    text.includes('member=Notify') &&
    text.includes('FlowGate ·')
  ) {
    const sender = /sender=([^ ]+)/.exec(text)?.[1],
      serial = /serial=(\d+)/.exec(text)?.[1];
    if (sender && serial)
      pendingReplies.set(sender + ':' + serial, text.match(/string "FlowGate ·[^\n]*/)?.[0]);
  }
  if (text.startsWith('method return')) {
    const dest = /destination=([^ ]+)/.exec(text)?.[1],
      serial = /reply_serial=(\d+)/.exec(text)?.[1],
      key = dest + ':' + serial;
    if (pendingReplies.has(key)) {
      const id = /uint32 (\d+)/.exec(text)?.[1];
      if (id) notices.push({ id: Number(id), title: pendingReplies.get(key) });
      pendingReplies.delete(key);
    }
  }
}
const prefFile = path.join(root, 'build/desktop-session/electron-preferences.json'),
  oldPrefs = fs.existsSync(prefFile) ? fs.readFileSync(prefFile) : undefined;
try {
  const text = fs
    .readFileSync(path.join(root, 'scripts/acceptance/host-lab.py'), 'utf8')
    .replace('ROOT=Path(__file__).resolve().parents[1]', `ROOT=Path(${JSON.stringify(root)})`)
    .replace("start('30s')", "start('120s')");
  fs.writeFileSync(path.join(run, 'harness.py'), text);
  const out = fs.openSync(path.join(run, 'lab.log'), 'w');
  lab = spawn(
    'scripts/lab.sh',
    ['python3', path.join(run, 'harness.py'), run, '--desktop-workflow'],
    {
      cwd: root,
      detached: true,
      stdio: ['ignore', out, out],
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    },
  );
  fs.closeSync(out);
  await wait(() => fs.existsSync(path.join(run, 'ready')));
  const job = path.join(run, 'job');
  fs.mkdirSync(job, { mode: 0o700 });
  fs.writeFileSync(path.join(job, 'request.json'), '{"profile":"incoming"}');
  await command('start', { job });
  monitor = spawn(
    'dbus-monitor',
    [
      '--session',
      "type='method_call',interface='org.freedesktop.Notifications',member='Notify'",
      "type='method_return'",
    ],
    { stdio: ['ignore', 'pipe', 'ignore'] },
  );
  let tail = '';
  monitor.stdout.on('data', (b) => {
    tail += b;
    const lines = tail.split('\n');
    tail = lines.pop();
    for (const line of lines) {
      if (/^(method |signal )/.test(line)) {
        parseBlock(block);
        block = line + '\n';
      } else if (block.length < 65536) block += line + '\n';
    }
  });
  const launchCopy = path.join(run, 'launch-debug.py');
  const launcherSource = fs
    .readFileSync(path.join(root, 'electron/launch.py'), 'utf8')
    .replace('ROOT = Path(__file__).resolve().parents[1]', `ROOT = Path(${JSON.stringify(root)})`)
    // Playwright discovers the debugger endpoint on stderr. The normal
    // launcher combines it into stdout for logs, so preserve stderr here.
    .replace('stderr=subprocess.STDOUT', 'stderr=None')
    .replace(
      'a = p.parse_args()',
      `a, diagnostic_flags = p.parse_known_args()\nassert all(x.startswith(('--inspect=', '--remote-debugging-port=')) for x in diagnostic_flags)`,
    )
    .replace(
      '        if a.control:',
      '        args[1:1] = diagnostic_flags\n        if a.control:',
    );
  fs.writeFileSync(launchCopy, launcherSource, { mode: 0o700 });
  app = await electron.launch({
    chromiumSandbox: true,
    timeout: 20000,
    artifactsDir: run,
    executablePath: launchCopy,
    args: ['--control', path.join(run, 'api/control.sock')],
    cwd: root,
    env: {
      ...process.env,
      XDG_CACHE_HOME: path.join(run, 'cache'),
      TMPDIR: path.join(root, '.workspace/tmp'),
    },
  });
  const electronProcess = app.process(),
    mainPID = await app.evaluate(() => process.pid);
  assert(!fs.readFileSync(`/proc/${mainPID}/cmdline`, 'utf8').includes('--no-sandbox'));
  const ownedObserverPID = Number(
    fs
      .readFileSync(`/proc/${electronProcess.pid}/task/${electronProcess.pid}/children`, 'utf8')
      .trim()
      .split(/\s+/)
      .find((pid) => fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('electron-observer')),
  );
  assert(ownedObserverPID);
  const page = await wait(() => app.windows().find((p) => p.url() === 'flowgate://app/index.html'));
  await page.waitForFunction(() => !!window.flowgate);
  await wait(
    async () => (await page.evaluate(() => window.flowgate.backgroundStatus())).trayAvailable,
  );
  await wait(async () => (await page.evaluate(() => window.flowgate.snapshot())).control.connected);
  assert(
    await app.evaluate(
      ({ BrowserWindow }) =>
        BrowserWindow.getAllWindows()
          .find((w) => w.webContents.getURL() === 'flowgate://app/index.html')
          .webContents.getLastWebPreferences().sandbox,
    ),
  );
  const mainID = await app.evaluate(
    ({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().find(
        (w) => w.webContents.getURL() === 'flowgate://app/index.html',
      ).id,
  );
  const close = () =>
    app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).close(), mainID);
  const trayBus = await wait(() => {
    const items = q(
      'org.kde.StatusNotifierWatcher',
      '/StatusNotifierWatcher',
      'org.freedesktop.DBus.Properties.Get',
      'org.kde.StatusNotifierWatcher',
      'RegisteredStatusNotifierItems',
    ).split('\n');
    return items
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
      ?.split('/')[0];
  });
  const menu = () =>
    g(
      trayBus,
      '/StatusNotifierItem',
      'org.freedesktop.DBus.Properties.Get',
      'org.kde.StatusNotifierItem',
      'Menu',
    ).match(/objectpath '([^']+)'/)[1];
  const layout = () => {
    g(trayBus, menu(), 'com.canonical.dbusmenu.AboutToShow', '0');
    return g(trayBus, menu(), 'com.canonical.dbusmenu.GetLayout', '0', '1', "['label']");
  };
  const menuClick = (label) => {
    const l = layout(),
      match = new RegExp("\\((\\d+), \\{'label': <'" + label).exec(l);
    assert(match, l);
    g(trayBus, menu(), 'com.canonical.dbusmenu.Event', match[1], 'clicked', '<int32 0>', '0');
  };
  assert.equal(
    await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), mainID),
    false,
    'startup stays hidden while tray host is available',
  );
  menuClick('Open FlowGate');
  await wait(() =>
    app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), mainID),
  );
  await page.evaluate(() => window.flowgate.preferences({ keepInTray: true }));
  await close();
  await wait(() =>
    app.evaluate(({ BrowserWindow }, id) => !BrowserWindow.fromId(id).isVisible(), mainID),
  );
  await command('send', { port: 44001 });
  await wait(() => layout().includes('Pending requests (1)'));
  assert.equal(received(44001), 0);
  const prompt = await wait(() => app.windows().find((p) => p.url().includes('?request=')));
  await prompt.waitForSelector('#allow');
  assert.equal(received(44001), 0);
  await prompt.selectOption('#rememberDuration', 'once');
  await prompt.screenshot({ path: path.join(run, 'automatic-prompt.png') });
  await prompt.click('#allow');
  await wait(() => received(44001) === 1);

  console.log('PASS automatic popup opens without notification; only explicit Allow delivers UDP');
  await close();
  await command('send', { port: 44003 });
  const blockPrompt = await wait(() => app.windows().find((p) => p.url().includes('?request=')));
  await blockPrompt.selectOption('#rememberDuration', 'once');
  await blockPrompt.click('#block');
  await sleep(250);
  assert.equal(received(44003), 0);

  console.log('PASS Block from automatic popup prevents delivery');
  menuClick('Pending requests');
  await wait(() => page.locator('#requestsView').isVisible());
  await page.click('#activityTab');
  await page.fill('#search', 'fixture-search');
  for (let i = 0; i < 4; i++) {
    await close();
    menuClick('Open FlowGate');
    await wait(() =>
      app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), mainID),
    );
    assert.equal(await page.inputValue('#search'), 'fixture-search');
  }
  console.log('PASS close-to-tray preserves main-window state through four reopen cycles');
  await close();
  // Repeated polling and incoming request bursts must not send desktop
  // notifications: the automatic permission window is the sole prompt.
  for (let i = 0; i < 12; i++) await command('send', { port: [44001, 44003, 44005, 44007][i % 4] });
  await sleep(4000);
  parseBlock(block);
  assert.equal(notices.length, 0, 'automatic popups must not emit desktop notifications');
  assert.equal(received(44001), 1);
  assert.equal(received(44003), 0);
  console.log('PASS popup burst emits no desktop notifications or implicit Allows');
  // Inject only host-detection failure, not desktop state or backend responses.
  await app.evaluate(() => {
    const cp = process.getBuiltinModule('node:child_process'),
      original = cp.execFile;
    cp.execFile = (command, ...args) =>
      command === 'dbus-send'
        ? args.at(-1)(Error('synthetic unavailable host'), '')
        : original(command, ...args);
  });
  await wait(
    async () => !(await page.evaluate(() => window.flowgate.backgroundStatus())).trayAvailable,
    12,
  );
  assert(
    await app.evaluate(({ BrowserWindow }, id) => BrowserWindow.fromId(id).isVisible(), mainID),
  );
  console.log('PASS synthetic tray-host loss restores a visible recovery window');
  const deadline = (await call(path.join(run, 'api/control.sock'), { operation: 'list' }))
    .enforcement.stops_at;
  await app.evaluate(({ dialog }) => {
    dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false });
  }); // Confirmation response simulated; actual Quit handler runs.
  menuClick('Quit FlowGate UI');
  await wait(() => electronProcess.exitCode !== null);
  assert.equal(fs.existsSync(`/proc/${ownedObserverPID}`), false);
  assert.equal(
    (await call(path.join(run, 'api/control.sock'), { operation: 'list' })).enforcement.stops_at,
    deadline,
  );
  console.log(
    'PASS explicit tray Quit exits Electron and its owned observer; independent controller retains original deadline (confirmation response simulated)',
  );
  fs.writeFileSync(
    path.join(run, 'desktop-notifications.json'),
    JSON.stringify(
      {
        notifications: notices,
        activation: 'automatic popup and KDE tray menu; no desktop notifications',
      },
      null,
      2,
    ),
  );
  console.log('EVIDENCE', run);
} finally {
  monitor?.kill();
  try {
    await app?.close();
  } catch {}
  if (fs.existsSync(path.join(run, 'demo.sock')))
    try {
      await command('quit');
    } catch {}
  if (lab && lab.exitCode === null) {
    await sleep(600);
    if (lab.exitCode === null)
      try {
        process.kill(-lab.pid, 'SIGTERM');
      } catch {}
  }
  if (oldPrefs) fs.writeFileSync(prefFile, oldPrefs);
  else fs.rmSync(prefFile, { force: true });
  console.log('Artifacts', run);
}
