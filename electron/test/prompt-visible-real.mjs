// Real KDE Wayland check that an automatic permission window is actually ON SCREEN (KWin opacity and
// minimized state), not just rendered: content checks and page screenshots pass for a minimized,
// transparent window. Three sequential requests, each answered with Allow. Disposable fixture only.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
const project = path.resolve(import.meta.dirname, '../..'),
  readyPath = process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith('/home/flowgate-user/Apps/flowgate/.workspace/'), 'disposable fixture required');
const ready = JSON.parse(fs.readFileSync(readyPath)),
  dir = path.dirname(readyPath);
assert(ready.socket.startsWith(dir + '/') && !ready.socket.startsWith('/run/'));
const run = fs.mkdtempSync(project + '/.workspace/pvr-'),
  root = run + '/client';
fs.mkdirSync(root + '/electron', { recursive: true });
fs.cpSync(project + '/electron/dist', root + '/electron/dist', { recursive: true });
fs.copyFileSync(project + '/electron/package.json', root + '/electron/package.json');
fs.mkdirSync(root + '/.workspace/tmp', { recursive: true });
const evidence = { run, fixture: readyPath, steps: [], findings: [], errors: [], screenshots: {} };
const step = (s) => {
  evidence.steps.push(s);
  console.log('PASS', s);
};
const finding = (s) => {
  evidence.findings.push(s);
  console.log('FINDING', s);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn, ms = 20000, label = '', every = 80) => {
  for (let until = Date.now() + ms; Date.now() < until; ) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await sleep(every);
  }
  throw Error('timeout ' + label);
};
const call = (q) =>
  new Promise((resolve, reject) => {
    const s = net.createConnection(ready.socket);
    let t = '';
    s.on('error', reject);
    s.setTimeout(8000, () => s.destroy(Error('timeout')));
    s.on('connect', () => s.write(JSON.stringify({ version: 1, ...q }) + '\n'));
    s.on('data', (b) => {
      t += b;
      if (t.includes('\n')) {
        s.destroy();
        resolve(JSON.parse(t));
      }
    });
  });
async function command(q) {
  const f = dir + '/command-result.json';
  fs.rmSync(f, { force: true });
  fs.writeFileSync(ready.command, JSON.stringify(q));
  await wait(async () => fs.existsSync(f), 20000, 'fixture ' + q.op);
  return JSON.parse(fs.readFileSync(f));
}
const list = () => call({ operation: 'list' }).then((l) => ({ ...l, rules: l.rules || [], events: l.events || [] }));
const alphaCount = async () => (await command({ op: 'counts', name: 'alpha' })).counts?.tcp4 || 0;
// ---- KWin truth: is the permission window actually on screen? -----------------------------------------
const journalSince = new Date(Date.now() - 2000).toISOString();
let probes = 0;
function kwinProbe(pid) {
  const token = `FGPVR_${process.pid}_${++probes}`,
    name = 'fg-pvr-' + token,
    f = path.join(run, name + '.js');
  fs.writeFileSync(
    f,
    `for(const w of workspace.windowList())if(w.pid===${pid}&&/connection permission/.test(w.caption))print(${JSON.stringify(token)},JSON.stringify({caption:w.caption,minimized:w.minimized,opacity:w.opacity,x:w.frameGeometry.x,y:w.frameGeometry.y,w:w.frameGeometry.width,h:w.frameGeometry.height}));`,
  );
  const q = (...a) => execFileSync('qdbus6', ['org.kde.KWin', ...a], { encoding: 'utf8' }).trim();
  const id = q('/Scripting', 'org.kde.kwin.Scripting.loadScript', f, name);
  q('/Scripting/Script' + id, 'org.kde.kwin.Script.run');
  try { q('/Scripting/Script' + id, 'org.kde.kwin.Script.stop'); } catch {}
  try { q('/Scripting', 'org.kde.kwin.Scripting.unloadScript', name); } catch {}
  for (let i = 0; i < 20; i++) {
    const text = execFileSync('journalctl', ['--user', '-b', '--no-pager', '--since', journalSince, '_COMM=kwin_wayland', '-o', 'cat'], { encoding: 'utf8', maxBuffer: 64 << 20 });
    const line = text.split('\n').find((l) => l.startsWith(token + ' '));
    if (line) return JSON.parse(line.slice(token.length + 1));
    execFileSync('sleep', ['0.1']);
  }
  return null;
}
const onScreen = (k) => !!k && !k.minimized && k.opacity > 0;
let app, main;
const prompt = () => app.windows().find((w) => /[?&]request=/.test(w.url() || '') && !/request=__idle__/.test(w.url()));
try {
  const l0 = await list();
  for (const r of l0.rules) await call({ operation: 'rule-delete', generation: ready.generation, id: r.id, expected_version: r.version });
  const alpha = (await command({ op: 'launch', name: 'alpha' })).info;
  await command({ op: 'launch', name: 'beta' });
  app = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', root + '/electron', '--observer', ready.monitor_socket, '--control', ready.socket],
    env: { ...process.env, TMPDIR: root + '/.workspace/tmp', XDG_CACHE_HOME: run + '/cache' },
  });
  await app.firstWindow();
  main = await wait(async () => app.windows().find((w) => (w.url() || '').endsWith('/index.html')), 20000, 'main');
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  await main.locator('#rows tr').first().waitFor();
  const pid = await app.evaluate(() => process.pid);
  const menus = (o) => main.evaluate((o) => { document.getElementById('toolsMenu').open = o; document.getElementById('controlMenu').open = o; }, o);
  if (l0.protection?.state === 'active') await call({ operation: 'protection-stop', generation: ready.generation, protection_id: l0.protection.id });
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(async () => (await list()).protection?.state === 'active', 30000);
  await menus(false);
  // Like a real session: the main window is not in front.
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().find((w) => w.webContents.getURL().endsWith('/index.html'))?.minimize());
  evidence.idle_shell = kwinProbe(pid);
  const port = alpha.ports.tcp4;
  for (const round of [1, 2, 3]) {
    const t0 = Date.now();
    await command({ op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.1', port, v6: false, timeout_ms: 30000 });
    const timeline = [];
    let shown;
    for (const until = Date.now() + 8000; Date.now() < until && !shown; ) {
      const k = kwinProbe(pid);
      const n = await app.evaluate(({ BrowserWindow }) => {
        const w = BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL()));
        return w && { url: w.webContents.getURL().replace(/.*request=/, '').slice(0, 12), visible: w.isVisible(), minimized: w.isMinimized() };
      });
      const pending = (await list()).events.filter((e) => e.state === 'awaiting-decision').length;
      timeline.push({ dt: Date.now() - t0, kwin: k, native: n, pending });
      if (onScreen(k)) shown = Date.now() - t0;
      else await sleep(250);
    }
    evidence['round' + round] = { shown_ms: shown ?? null, timeline };
    if (!shown) {
      await prompt()?.screenshot({ path: `${run}/round${round}-offscreen.png` }).catch(() => {});
      throw Error(`round ${round}: permission window never on screen (KWin) within 8 s; last ${JSON.stringify(timeline.at(-1))}`);
    }
    step(`round ${round}: permission window on screen after ${shown} ms (KWin opacity/minimized)`);
    const w = await wait(async () => { const x = prompt(); return x && (await x.locator('#allow').isEnabled()) ? x : undefined; }, 10000, 'allow enabled');
    // A human click: press, hold for a few frames, release (Playwright's click() fits in one frame).
    const box = await w.locator('#allow').boundingBox();
    await w.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await w.mouse.down();
    await sleep(120);
    await w.mouse.up();
    await wait(async () => !onScreen(kwinProbe(pid)), 5000, 'hidden after Allow');
    step(`round ${round}: hidden after Allow`);
    await sleep(1500);
  }
  assert.deepEqual(evidence.errors, []);
  evidence.pass = true;
} catch (e) {
  evidence.failure = String(e?.stack || e);
} finally {
  fs.writeFileSync(run + '/evidence.json', JSON.stringify(evidence, null, 2));
  if (app) await app.close().catch(() => {});
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
