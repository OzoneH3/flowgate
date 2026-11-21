// Real KDE Wayland check that an automatic permission window is actually ON SCREEN (KWin opacity and
// minimized state), not just rendered: content checks and page screenshots pass for a minimized,
// transparent window. Three sequential requests, each answered with Allow once. Disposable fixture only.
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
  // First view facts, read from the rendered prompt.
  const view = (w) =>
    w.evaluate(() => {
      const t = (id) => document.getElementById(id)?.innerText.trim() ?? null;
      const rows = [...document.querySelectorAll('#fromToBox .nl-row')].map((r) => ({
        label: r.querySelector('.nl-label')?.innerText.trim(),
        program: !!r.querySelector('#requestApplication'),
        text: r.querySelector('.nl-cell')?.innerText.replace(/\s+/g, ' ').trim(),
      }));
      const shown = (id) => {
        const el = document.getElementById(id);
        if (!el) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0 && r.right <= innerWidth + 1 && r.bottom <= innerHeight + 1;
      };
      const body = document.getElementById('promptBody');
      return {
        header: t('connectionHeader'), rows,
        application: t('fieldApplication'), process: t('fieldProcess'), local: t('fieldLocal'), remote: t('fieldRemote'),
        detailsHidden: document.getElementById('requestMore')?.hidden,
        controls: ['allow', 'block', 'allowForAWhile', 'blockForAWhile', 'forAWhileDuration'].map(shown),
        labels: ['allow', 'block', 'allowForAWhile', 'blockForAWhile'].map(t),
        ruleScope: shown('rememberPanel'),
        temporaryDuration: document.getElementById('forAWhileDuration')?.selectedOptions[0]?.textContent,
        overflowX: body.scrollWidth - body.clientWidth, overflowY: body.scrollHeight - body.clientHeight,
        width: innerWidth, height: innerHeight,
      };
    });
  const rounds = [
    { label: 'outgoing-ipv4', q: { op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.1', port, v6: false, timeout_ms: 30000 }, dir: 'Outgoing', v6: false },
    { label: 'incoming-ipv4', q: { op: 'incoming', name: 'alpha', protocol: 'tcp', v6: false }, dir: 'Incoming', v6: false },
    { label: 'outgoing-ipv6', q: { op: 'outgoing', name: 'alpha', protocol: 'tcp', v6: true, timeout_ms: 30000 }, dir: 'Outgoing', v6: true },
  ];
  const seen = [];
  // The fixture runs one command at a time (an incoming send returns when answered).
  let pendingCommand = Promise.resolve();
  const issue = (q) => {
    const run = pendingCommand.then(() => command(q)).catch((e) => ({ error: String(e) }));
    pendingCommand = run;
    return run;
  };
  for (const [i, r] of rounds.entries()) {
    const round = i + 1;
    const t0 = Date.now();
    void issue(r.q);
    const timeline = [];
    let shown;
    for (const until = Date.now() + 10000; Date.now() < until && !shown; ) {
      const k = kwinProbe(pid);
      const x = prompt();
      const id = x ? new URL(x.url()).searchParams.get('request') : '';
      timeline.push({ dt: Date.now() - t0, kwin: k, id });
      if (onScreen(k) && id && !seen.includes(id)) shown = { ms: Date.now() - t0, kwin: k, id };
      else await sleep(200);
    }
    evidence['round' + round] = { label: r.label, shown: shown ?? null, timeline: timeline.slice(-5) };
    if (!shown) throw Error(`round ${round} (${r.label}): permission window never on screen (KWin) within 10 s; last ${JSON.stringify(timeline.at(-1))}`);
    seen.push(shown.id);
    const w = await wait(async () => { const x = prompt(); return x && (await x.locator('#allowForAWhile').isEnabled()) ? x : undefined; }, 10000, 'allow enabled');
    const v = await view(w);
    evidence['round' + round].view = v;
    await w.screenshot({ path: `${run}/${round}-${r.label}.png` });
    assert(v.header.startsWith(r.dir + ' connection - TCP(6)'), `${r.label}: header "${v.header}"`);
    const from = v.rows.find(row => row.label === 'From');
    const to = v.rows.find(row => row.label === 'To');
    assert.equal(v.rows.length, 2);
    assert.equal(from?.program, r.dir === 'Outgoing', `${r.label}: From side`);
    assert.equal(to?.program, r.dir === 'Incoming', `${r.label}: To side`);
    assert(v.application && /^Process \d+/.test(v.process), `${r.label}: application/process ${v.application} / ${v.process}`);
    for (const f of [v.local, v.remote]) {
      assert(/Port:\s*\d+$/.test(f), `${r.label}: address/port "${f}"`);
      assert(r.v6 ? /:/.test(f.replace(/Port:.*/, '')) && !/\[|\]/.test(f) : /^\d+\.\d+\.\d+\.\d+/.test(f), `${r.label}: address format "${f}"`);
    }
    assert.equal(v.detailsHidden, true);
    assert.deepEqual(v.controls, [true, true, true, true, true], `${r.label}: all decision controls visible`);
    assert.deepEqual(v.labels, ['Allow always', 'Deny always', 'Allow once', 'Deny once']);
    assert.equal(v.temporaryDuration, 'This connection only');
    assert(v.ruleScope, `${r.label}: rule scope visible on open`);
    assert(v.overflowX <= 0 && v.overflowY <= 0, `${r.label}: no scroll at ${v.width}x${v.height} (${v.overflowX}/${v.overflowY})`);
    assert.equal(Math.round(shown.kwin.w), 745, 'native window width 745');
    step(`round ${round} ${r.label}: on screen after ${shown.ms} ms (KWin ${Math.round(shown.kwin.w)}x${Math.round(shown.kwin.h)}); "${v.header}" From "${from.text}" To "${to.text}"; ${v.application} · ${v.process} · local ${v.local} · remote ${v.remote}`);
    // Human click: press, hold for a few frames, release.
    const box = await w.locator('#allowForAWhile').boundingBox();
    await w.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await w.mouse.down();
    await sleep(120);
    await w.mouse.up();
    await wait(async () => !onScreen(kwinProbe(pid)), 5000, 'hidden after Allow');
    step(`round ${round}: hidden after press-hold-release Allow`);
    await sleep(1200);
  }
  // Narrow window: a fourth request (incoming IPv6) at 420 px wide, answered with Deny.
  void issue({ op: 'incoming', name: 'alpha', protocol: 'tcp', v6: true });
  await wait(async () => { const x = prompt(); const id = x && new URL(x.url()).searchParams.get('request'); return id && !seen.includes(id) && onScreen(kwinProbe(pid)) ? x : undefined; }, 10000, 'fourth card');
  const w4 = await wait(async () => { const x = prompt(); return x && (await x.locator('#allowForAWhile').isEnabled()) ? x : undefined; }, 10000, 'allow enabled 4');
  await app.evaluate(({ BrowserWindow }) => { const w = BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL())); w.setSize(420, w.getSize()[1]); });
  await sleep(700);
  const n = await view(w4);
  evidence.narrow = n;
  await w4.screenshot({ path: `${run}/4-narrow-incoming-ipv6.png` });
  assert(n.width <= 425 && n.overflowX <= 0, `narrow: no horizontal overflow at ${n.width} (${n.overflowX})`);
  assert.deepEqual(n.controls.slice(0, 2), [true, true], 'narrow: Allow and Deny visible');
  assert(n.header.startsWith('Incoming connection - TCP(6)') && n.rows.find(row => row.label === 'To')?.program, 'narrow: incoming, program on To');
  step(`narrow ${n.width}px: no horizontal overflow; controls visible ${JSON.stringify(n.controls)} (vertical scroll ${n.overflowY > 0 ? 'yes' : 'no'})`);
  const b4 = await w4.locator('#blockForAWhile').boundingBox();
  await w4.mouse.move(b4.x + b4.width / 2, b4.y + b4.height / 2);
  await w4.mouse.down();
  await sleep(120);
  await w4.mouse.up();
  await wait(async () => !onScreen(kwinProbe(pid)), 5000, 'hidden after Deny');
  step('narrow card: hidden after press-hold-release Deny');
  await Promise.race([pendingCommand, sleep(15000)]);
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
