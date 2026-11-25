#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { renderer, until } from './browser.mjs';
import { recipeNames, startSeed } from './seeds.mjs';

const here = import.meta.dirname;
const plan = JSON.parse(await readFile(path.join(here, 'expected.json'), 'utf8'));
const slug = /^[a-z][a-z0-9-]*$/;
const flat = plan.journeys.flatMap(journey => journey.states);
const fileName = ({ window, id }) => window + '--' + id + '.json';
const expected = new Set(flat.map(fileName));
if (expected.size !== flat.length) throw Error('Duplicate expected window/state');
for (const { seed, states } of plan.journeys) {
  if (!recipeNames.includes(seed)) throw Error('Unknown seed recipe ' + seed);
  for (const state of states)
    if (!slug.test(state.window) || !slug.test(state.id) || !plan.windows[state.window])
      throw Error('Invalid expected window/state ' + fileName(state));
}
const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === '--list') {
  for (const state of flat) console.log(fileName(state));
  process.exit(0);
}
const opts = {};
for (let i = 0; i < argv.length; i += 2) {
  if (!['--package', '--out', '--work', '--only'].includes(argv[i]) || !argv[i + 1] || opts[argv[i]])
    throw Error('Usage: node capture.mjs --package /path/to/extracted/gui --out /path/to/captures --work /short/private/path [--only journey-id]');
  opts[argv[i]] = argv[i + 1];
}
if (!opts['--package'] || !opts['--out'] || !opts['--work'])
  throw Error('Specify --package, --out and --work. Use --list to display expected files.');
const pkg = path.resolve(opts['--package']);
const out = path.resolve(opts['--out']);
const work = path.resolve(opts['--work']);
const journeys = opts['--only'] ? plan.journeys.filter(j => j.id === opts['--only']) : plan.journeys;
if (!journeys.length) throw Error('Unknown journey ' + opts['--only']);
await access(path.join(pkg, 'matched-manifest.json'));
const executable = path.join(pkg, 'runtime', 'electron');
const client = path.join(pkg, 'electron');
await access(executable, constants.X_OK);
await access(path.join(client, 'dist', 'main.cjs'));
await mkdir(out, { recursive: true });
if ((await readdir(out)).length) throw Error('Use an empty output directory');
await mkdir(work, { recursive: true, mode: 0o700 });
const runtime = process.env.XDG_RUNTIME_DIR;
const wayland = process.env.WAYLAND_DISPLAY;
const actualWayland = wayland && (path.isAbsolute(wayland) ? wayland : runtime && path.join(runtime, wayland));
if (!actualWayland && !process.env.DISPLAY) throw Error('Run in a logged-in Linux desktop session');

let failures = 0;
async function publish(state, surface, status, controls, issues) {
  if (status !== 'captured') failures++;
  const record = { schemaVersion: 1, windowId: state.window, stateId: state.id, surface,
    status, controls, issues };
  await writeFile(path.join(out, fileName(state)), JSON.stringify(record, null, 2) + '\n', { flag: 'wx' });
  console.log(status + ' ' + fileName(state));
}

// Keep stdin transport separate from process arguments so the same AT-SPI
// executable can be used on any desktop session and does not need shell quoting.
async function desktop(operation) {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/python3', [path.join(here, 'native.py')], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 12000);
    child.stdout.setEncoding('utf8').on('data', x => { stdout += x; });
    child.stderr.setEncoding('utf8').on('data', x => { stderr += x; });
    child.stdin.on('error', () => {});
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      try {
        const json = JSON.parse(stdout);
        if (code !== 0) throw Error(json.error);
        resolve(json);
      } catch (error) { reject(Error(stdout ? error.message : stderr.trim() || 'Desktop accessibility yielded no response')); }
    });
    child.stdin.end(JSON.stringify(operation));
  });
}

function startApplication(directory, control, observer) {
  const env = { ...process.env, FLOWGATE_INSTALLED: '1',
    XDG_RUNTIME_DIR: path.join(directory, 'run'), XDG_CONFIG_HOME: path.join(directory, 'config'),
    XDG_CACHE_HOME: path.join(directory, 'cache'), XDG_DATA_HOME: path.join(directory, 'data'),
    XDG_STATE_HOME: path.join(directory, 'state'), TMPDIR: path.join(directory, 'tmp'),
    TZ: 'UTC', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
  };
  delete env.ELECTRON_RUN_AS_NODE;
  if (actualWayland) env.WAYLAND_DISPLAY = actualWayland;
  if (!env.DBUS_SESSION_BUS_ADDRESS && runtime) env.DBUS_SESSION_BUS_ADDRESS = 'unix:path=' + path.join(runtime, 'bus');
  const child = spawn(executable, ['--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
    '--force-renderer-accessibility', '--lang=en-US', ...(actualWayland ? ['--ozone-platform=wayland'] : ['--ozone-platform=x11']),
    client, '--show', '--control', control, '--observer', observer],
  { cwd: directory, env, stdio: ['ignore', 'ignore', 'pipe'] });
  let log = '', address = '', launchError;
  child.once('error', error => { launchError = error; });
  child.stderr.setEncoding('utf8').on('data', chunk => {
    log = (log + chunk).slice(-32768);
    address ||= log.match(/DevTools listening on ws:\/\/(127\.0\.0\.1:\d+)\//)?.[1];
  });
  const done = new Promise(resolve => child.once('close', resolve));
  return { child, log: () => log,
    endpoint: () => until(() => {
      if (launchError) throw launchError;
      if (child.exitCode !== null || child.signalCode) throw Error('Packaged Electron exited during launch');
      return address && 'http://' + address;
    }, 'Packaged Electron did not publish a loopback DevTools endpoint', 12000),
    close: async () => {
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
      try { await done; } finally { clearTimeout(timer); }
    },
  };
}

function locate(step) {
  return typeof step === 'string' ? { selector: step } : step;
}
async function perform(page, steps = []) {
  for (const step of steps) {
    if (step.wait) {
      await until(() => page.verify(step.wait), 'State not reached ' + JSON.stringify(step.wait), step.timeout);
      continue;
    }
    if (step.focus) await page.focus(locate(step.focus));
    if (step.type !== undefined) {
      await page.key('a', 2);
      for (const character of step.type) await page.key(character);
    }
    for (const key of step.keys ?? []) await page.key(key);
    if (step.press) {
      await page.focus(locate(step.press));
      await page.key(step.key ?? 'Enter', 0, step.closesWindow === true);
    }
  }
}
async function performDesktop(steps = [], pid) {
  for (const step of steps) {
    const target = step.focus && { ...step.focus, ...(step.focus.ownProcess ? { pid } : {}) };
    if (target) await until(async () => {
      try { return await desktop({ op: 'focus', locator: target }); } catch { return null; }
    }, 'Desktop keyboard focus missing ' + JSON.stringify(target), 3000);
    if (step.keys) await desktop({ op: 'key', keys: step.keys });
  }
}
const windowOf = (entry, state) => ({ ...entry, query: state.query ?? entry.query });

async function captureState(endpoint, pid, state) {
  const window = plan.windows[state.window];
  const surface = window.document ? 'electron' : 'desktop-accessibility';
  if (state.reason) {
    await publish(state, surface, 'blocked', [], [{ kind: 'blocked', id: state.window, message: state.reason }]);
    return;
  }
  if (window.document) {
    let page;
    try {
      await performDesktop(state.desktopSteps, pid);
      if (state.setup) {
        const setup = await renderer(endpoint, windowOf(plan.windows[state.setup.window], state.setup));
        try { await perform(setup, state.setup.steps); } finally { setup.close(); }
      }
      try {
        page = await renderer(endpoint, windowOf(window, state));
      } catch (error) {
        await publish(state, 'electron', 'missing', [], [{ kind: 'missing', id: state.window, message: error.message }]);
        return;
      }
      await perform(page, state.steps);
      if (state.ready) await until(() => page.verify(state.ready), 'Expected surface not displayed ' + JSON.stringify(state.ready), state.timeout);
      const controls = await page.capture(state.root ?? window.root);
      const issues = [];
      for (const assertion of state.expect ?? []) {
        if (!await page.verify(assertion)) issues.push({
          kind: 'missing', id: assertion.selector, message: 'Expected rendered control/state: ' + JSON.stringify(assertion),
        });
      }
      await publish(state, 'electron', controls.length ? (issues.length ? 'partial' : 'captured') : 'unreadable',
        controls, controls.length ? issues : [{ kind: 'unreadable', id: state.window, message: 'No readable rendered controls' }]);
    } catch (error) {
      const controls = await page?.capture(state.root ?? window.root).catch(() => []) ?? [];
      await publish(state, 'electron', 'blocked', controls, [{ kind: 'blocked', id: state.window, message: error.message }]);
    } finally { page?.close(); }
    return;
  }
  let lastError;
  try {
    if (state.setup) {
      const page = await renderer(endpoint, windowOf(plan.windows[state.setup.window], state.setup));
      try { await perform(page, state.setup.steps); } finally { page.close(); }
    }
    await performDesktop(state.steps, pid);
    const locator = { ...window.locator, ...(window.locator.ownProcess ? { pid } : {}) };
    const native = await until(async () => {
      try { return await desktop({ op: 'capture', locator }); } catch (error) { lastError = error; return null; }
    }, 'Desktop-accessible window absent').catch(error => { throw lastError ?? error; });
    for (const text of state.expectText ?? [])
      if (!native.controls.some(c => c.text === text || c.accessibleName === text))
        native.issues.push({ kind: 'missing', id: text, message: 'Expected native control missing' });
    await publish(state, 'desktop-accessibility', native.controls.length ? (native.issues.length ? 'partial' : 'captured') : 'unreadable',
      native.controls, native.issues.length || native.controls.length ? native.issues : [
        { kind: 'unreadable', id: state.window, message: 'Desktop reported no readable controls' },
      ]);
  } catch (error) {
    await publish(state, 'desktop-accessibility', 'blocked', [], [{ kind: 'blocked', id: state.window, message: error.message }]);
  }
}
for (const journey of journeys) {
  const directory = await mkdtemp(path.join(work, 'i-'));
  const childPaths = ['run', 'config', 'cache', 'data', 'state', 'tmp'];
  for (const name of childPaths) await mkdir(path.join(directory, name), { mode: 0o700 });
  const control = path.join(directory, 'c'), observer = path.join(directory, 'o');
  let fixture, app, endpoint;
  try {
    if (Buffer.byteLength(control) > 107) throw Error('--work must give the fixture a shorter Unix socket path');
    fixture = await startSeed(journey.seed, control, observer);
    app = startApplication(directory, control, observer);
    endpoint = await app.endpoint();
    const main = await renderer(endpoint, plan.windows.main);
    try {
      const geometry = await main.run(() => [screen.width, screen.height, devicePixelRatio]);
      if (geometry.toString() !== '1920,1080,1') throw Error('Set the desktop to 1920×1080 at 100% scaling before capture');
      await until(() => main.verify({ selector: '#activityTab' }), 'Main toolbar missing');
    } finally { main.close(); }
  } catch (error) {
    for (const state of journey.states) await publish(state, plan.windows[state.window].document ? 'electron' : 'desktop-accessibility',
      'blocked', [], [{ kind: 'blocked', id: state.window, message: error.message }]);
    await app?.close();
    await fixture?.close();
    await writeFile(path.join(directory, 'electron.log'), app?.log() ?? '');
    continue;
  }
  try {
    for (const state of journey.states) {
      if (state.seedStage) fixture.setStage(state.seedStage);
      await captureState(endpoint, app.child.pid, state);
    }
  } finally {
    await app.close();
    await fixture.close();
    await writeFile(path.join(directory, 'electron.log'), app.log());
    await writeFile(path.join(directory, 'fixture-operations.json'), JSON.stringify(fixture.calls, null, 2));
  }
}
const written = await readdir(out);
if (written.length !== journeys.flatMap(journey => journey.states).length) throw Error('Incomplete capture output');
process.exitCode = failures ? 1 : 0;
