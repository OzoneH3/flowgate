// Real local-pair popup journey: beta connects to alpha's own listener (10.79.0.1) inside a held disposable
// fixture (scripts/process-rules-isolated.py --hold --continuous --zones --other; both directions intercepted).
// Simplified permission popup: the first view shows application / owner / destination / status line and
// Allow | Deny | Remember | For a while; there is no pair panel. A plain Allow/Deny on a backend-verified
// local pair sends decide-pair (Once) for exactly that connection, the permission window hides at once and
// the outcome is listed in the main window (Pending requests › Results). Never the host daemon.
//
// Hide latency: on KDE the main process hides the prompt through a KWin script (opacity 0 + minimized;
// BrowserWindow.isVisible() stays true), elsewhere through BrowserWindow.hide(). Both are measured: a KWin
// watcher script connected to the prompt window's minimizedChanged/opacityChanged/windowRemoved signals prints
// Date.now() (same wall clock as this process) into the user journal; in parallel isVisible() is polled from
// the main process. Latency = first observed hide - Date.now() immediately before the Playwright click.
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
const run = fs.mkdtempSync(project + '/.workspace/lpr-'),
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
let app, main;
const prompt = () => app.windows().find((w) => /[?&]request=/.test(w.url() || ''));
const requestOf = (w) => new URL(w.url()).searchParams.get('request');
const shot = async (w, n) => {
  const file = `${run}/${n}.png`;
  await w?.screenshot({ path: file }).catch(() => {});
  if (fs.existsSync(file)) evidence.screenshots[n] = file;
};
// Native facts of the prompt BrowserWindow (main process).
const promptNative = () =>
  app.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL()));
    return w && {
      id: w.id,
      title: w.getTitle(),
      visible: w.isVisible(),
      minimized: w.isMinimized(),
      opacity: w.getOpacity(),
      bounds: w.getBounds(),
      content: w.getContentBounds(),
    };
  });
// ---- KWin watcher (journal) ---------------------------------------------------------------------------
const journalSince = new Date(Date.now() - 2000).toISOString();
let kwinScript = 0;
function kwinLoad(code) {
  const name = `flowgate-lpr-watch-${process.pid}-${++kwinScript}`,
    f = path.join(run, name + '.js');
  fs.writeFileSync(f, code);
  const id = execFileSync('qdbus6', ['org.kde.KWin', '/Scripting', 'org.kde.kwin.Scripting.loadScript', f, name], {
    encoding: 'utf8',
  }).trim();
  execFileSync('qdbus6', ['org.kde.KWin', '/Scripting/Script' + id, 'org.kde.kwin.Script.run']);
  return () => {
    try {
      execFileSync('qdbus6', ['org.kde.KWin', '/Scripting/Script' + id, 'org.kde.kwin.Script.stop']);
    } catch {}
    try {
      execFileSync('qdbus6', ['org.kde.KWin', '/Scripting', 'org.kde.kwin.Scripting.unloadScript', name]);
    } catch {}
  };
}
function kwinLines(token) {
  const text = execFileSync('journalctl', ['--user', '-b', '--no-pager', '--since', journalSince, '_COMM=kwin_wayland', '-o', 'cat'], {
    encoding: 'utf8',
    maxBuffer: 64 << 20,
  });
  return text
    .split('\n')
    .filter((l) => l.startsWith(token + ' '))
    .map((l) => {
      try {
        return JSON.parse(l.slice(token.length + 1));
      } catch {
        return undefined;
      }
    })
    .filter(Boolean);
}
async function watchHide(pid, caption, label) {
  const token = `FLOWGATE_LPR_${process.pid}_${label}`;
  const stop = kwinLoad(
    `const P=${pid},C=${JSON.stringify(caption)},T=${JSON.stringify(token)};` +
      `function r(w,k){print(T,JSON.stringify({k:k,t:Date.now(),caption:w.caption,minimized:w.minimized,opacity:w.opacity}));}` +
      `for(const w of workspace.windowList())if(w.pid===P&&w.caption===C){w.minimizedChanged.connect(()=>r(w,'minimized'));w.opacityChanged.connect(()=>r(w,'opacity'));r(w,'armed');}` +
      `workspace.windowRemoved.connect((w)=>{if(w.pid===P&&w.caption===C)r(w,'removed');});`,
  );
  try {
    await wait(async () => kwinLines(token).some((x) => x.k === 'armed'), 5000, 'kwin watcher armed', 100);
  } catch {
    stop();
    return undefined;
  }
  return { token, stop };
}
const hiddenEntry = (x) => x.k === 'removed' || (x.k !== 'armed' && (x.minimized || x.opacity === 0));
// Click a control and measure until the prompt window is hidden (KWin and/or isVisible()).
async function clickAndMeasureHide(w, selector, label) {
  const pid = await app.evaluate(() => process.pid);
  const before = await promptNative();
  const watcher = await watchHide(pid, before.title, label).catch(() => undefined);
  const t0 = Date.now();
  await w.locator(selector).click();
  const clickReturned = Date.now();
  let visibleFalseAt;
  const hiddenNative = await wait(
    async () => {
      const n = await promptNative();
      if (n && !n.visible && !visibleFalseAt) visibleFalseAt = Date.now();
      if (visibleFalseAt) return true;
      if (watcher && kwinLines(watcher.token).some(hiddenEntry)) return true;
      return undefined;
    },
    5000,
    'prompt hidden',
    15,
  );
  assert(hiddenNative);
  await sleep(300);
  const kwin = watcher ? kwinLines(watcher.token) : [];
  watcher?.stop();
  const kwinHidden = kwin.find(hiddenEntry);
  const after = await promptNative();
  const out = {
    method: kwinHidden ? 'kwin-signal' : 'isVisible',
    t0,
    click_returned_ms: clickReturned - t0,
    kwin_hidden_ms: kwinHidden ? kwinHidden.t - t0 : null,
    kwin_events: kwin.map((x) => ({ ...x, dt: x.t - t0 })),
    is_visible_false_ms: visibleFalseAt ? visibleFalseAt - t0 : null,
    native_before: before,
    native_after: after,
  };
  out.hide_ms = kwinHidden ? out.kwin_hidden_ms : out.is_visible_false_ms;
  return out;
}
// Visible first view: text, forbidden pair-panel elements and identifiers.
async function firstView(w) {
  return w.evaluate(() => {
    const text = (id) => document.getElementById(id)?.innerText ?? null;
    const shown = (el) => {
      if (!el) return false;
      const r = el.getBoundingClientRect(),
        s = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
    };
    return {
      application: text('requestApplication'),
      owner: text('requestOwner'),
      destination: text('requestDestination'),
      status: text('requestStatusLine'),
      body: document.body.innerText,
      oldPairPanel: ['localPair', 'localPairTitle', 'pairAllow', 'pairBlock', 'pairResult'].filter((id) => document.getElementById(id)),
      buttonsText: [...document.querySelectorAll('button')].filter(shown).map((b) => b.textContent.trim()),
      detailsHidden: document.getElementById('requestMore')?.hidden,
      pairSection: !!document.querySelector('details[data-section="local-pair"]'),
      controls: ['allow', 'block', 'rememberToggle', 'forAWhileToggle'].map((id) => ({ id, present: !!document.getElementById(id), shown: shown(document.getElementById(id)) })),
      durationWrapHidden: document.getElementById('forAWhileDurationWrap')?.hidden ?? null,
    };
  });
}
function assertFirstView(v, port, label) {
  assert.deepEqual(v.oldPairPanel, [], label + ': old pair panel elements present');
  assert(!/Allow both|Deny both/i.test(v.body), label + ': "Allow both"/"Deny both" visible');
  assert(!v.buttonsText.some((t) => /both/i.test(t)), label + ': a "both" button is visible');
  assert(!/\bPID\b|cookie|start_ticks|\bstart \d+/i.test(v.body), label + ': PID/cookie text in visible first view');
  assert.equal(v.detailsHidden, true, label + ': Details view hidden in the first view');
  assert(v.application, label + ': #requestApplication');
  assert(v.status !== null, label + ': #requestStatusLine');
  assert(new RegExp(`^To Local service \\(.+\\) · 10\\.79\\.0\\.1:${port} · TCP$`).test(v.destination), label + ': destination "' + v.destination + '"');
  for (const c of v.controls) assert(c.present && c.shown, `${label}: #${c.id} visible`);
}
const resultRows = () =>
  main.evaluate(() =>
    [...document.querySelectorAll('#permissionResultRows li.permission-result')].map((li) => ({
      event: li.dataset.event,
      cls: li.className,
      text: li.querySelector('.result-text')?.textContent ?? '',
      app: li.querySelector('strong')?.textContent ?? '',
      destination: li.querySelector('.result-destination')?.textContent ?? '',
      detail: li.querySelector('.result-detail')?.textContent ?? '',
    })),
  );
// Wait for a fresh, actionable card of a verified local pair for `port` (not one of `seen`).
async function pairCard(port, seen) {
  return wait(
    async () => {
      const x = prompt();
      if (!x || seen.includes(requestOf(x))) return undefined;
      const n = await promptNative();
      if (!n?.visible || n.opacity === 0) return undefined;
      const dest = await x.locator('#requestDestination').innerText().catch(() => '');
      if (!dest.includes(`10.79.0.1:${port}`)) return undefined;
      if (!(await x.locator('details[data-section="local-pair"]').count())) return undefined;
      return (await x.locator('#allow').isEnabled()) ? x : undefined;
    },
    20000,
    'pair card',
  );
}
try {
  const l0 = await list();
  assert(l0.capabilities.includes('local-pair-v1'), 'fixture lacks local-pair-v1');
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
  main.on('pageerror', (e) => evidence.errors.push(String(e)));
  app.on('window', (w) => w.on('pageerror', (e) => evidence.errors.push(String(e))));
  await main.locator('#rows tr').first().waitFor();
  const menus = (o) =>
    main.evaluate((o) => {
      document.getElementById('toolsMenu').open = o;
      document.getElementById('controlMenu').open = o;
    }, o);
  const prior = l0.protection;
  if (prior?.state === 'active') await call({ operation: 'protection-stop', generation: ready.generation, protection_id: prior.id });
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  await menus(true);
  await main.selectOption('#protectionProfile', 'both');
  await main.locator('#protectionCheck').click();
  await wait(() => main.evaluate(() => window.flowgate.protectionState()).then((s) => s.canStart));
  await main.locator('#protectionStart').click();
  await wait(async () => (await list()).protection?.state === 'active', 30000);
  await menus(false);
  const port = alpha.ports.tcp4;
  const rulesBefore = (await list()).rules.map((r) => r.id).sort();

  // 1. Allow on the first view of a verified local pair.
  let before = await alphaCount();
  const sentAt = Date.now();
  await command({ op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.1', port, v6: false, timeout_ms: 30000 });
  const w = await pairCard(port, []);
  evidence.card_ms = Date.now() - sentAt;
  const firstId = requestOf(w);
  const v1 = await firstView(w);
  evidence.first_view = { ...v1, body: v1.body.slice(0, 800) };
  assertFirstView(v1, port, 'first card');
  await shot(w, '01-first-view');
  step(
    `first view: application "${v1.application}", owner "${v1.owner ?? '(none)'}", destination "${v1.destination}", ` +
      `status "${v1.status}"; no pair panel, no "Allow both"/"Deny both", no PID/cookie; Allow|Deny|Remember|For a while visible`,
  );
  const allowHide = await clickAndMeasureHide(w, '#allow', 'allow');
  evidence.allow_hide = allowHide;
  assert(allowHide.hide_ms < 1000, `prompt hidden after ${allowHide.hide_ms} ms (must be well under 1 s)`);
  step(
    `Allow hid the permission window after ${allowHide.hide_ms} ms (${allowHide.method}; ` +
      `KWin ${allowHide.kwin_hidden_ms ?? 'n/a'} ms, isVisible()=false ${allowHide.is_visible_false_ms ?? 'never'} ms; click returned ${allowHide.click_returned_ms} ms)`,
  );
  await wait(async () => (await alphaCount()) > before, 15000, 'server received');
  const evs = (await list()).events.filter((e) => e.local_peer);
  evidence.verdicts = evs.map((e) => [e.id, e.flow?.direction, e.state]);
  assert(evs.some((e) => e.id === firstId && e.flow?.direction === 'outgoing' && e.state === 'allowed'), 'outgoing allowed');
  assert(evs.some((e) => e.flow?.direction === 'incoming' && e.state === 'allowed'), 'incoming side allowed');
  assert(!evs.some((e) => e.state === 'awaiting-decision'), 'no side left pending');
  const ok = await wait(
    async () => (await resultRows()).find((r) => r.event === firstId && /\bresult-ok\b/.test(r.cls)),
    10000,
    'Results ok entry',
  );
  evidence.allow_result = ok;
  await main.locator('#requestsTab').click();
  await main.locator('#permissionResultsView').waitFor();
  await shot(main, '02-main-results');
  await main.locator('#activityTab').click();
  step(`alpha's listener received the connection; both sides allowed ${JSON.stringify(evidence.verdicts)}; Results ok: "${ok.text}"`);

  // 2. Second connection: Deny. Details view + narrow layout are captured on this card first.
  before = await alphaCount();
  await command({ op: 'outgoing', name: 'beta', protocol: 'tcp', host: '10.79.0.1', port, v6: false, timeout_ms: 30000 });
  const w2 = await pairCard(port, [firstId]);
  const secondId = requestOf(w2);
  const v2 = await firstView(w2);
  assertFirstView(v2, port, 'second card');
  await w2.locator('#detailsToggle').click();
  await w2.locator('#requestMore').waitFor();
  evidence.details_sections = await w2.locator('#requestMore details[data-section]').evaluateAll((xs) => xs.map((x) => x.dataset.section));
  assert(evidence.details_sections.includes('local-pair'), 'Details lists the local connection');
  assert(await w2.locator('#requestApplication').isHidden(), 'first view hidden while Details is open');
  await shot(w2, '03-details-view');
  await w2.locator('#detailsBack').click();
  await w2.locator('#requestDestination').waitFor();
  // Narrow: shrink the native prompt window to 360 px wide.
  const normal = await promptNative();
  await app.evaluate(({ BrowserWindow }, h) => {
    const x = BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL()));
    x.setSize(360, h);
  }, normal.bounds.height);
  let narrowMethod = 'BrowserWindow.setSize';
  const narrowed = await wait(async () => ((await w2.evaluate(() => innerWidth)) <= 380 ? true : undefined), 3000, 'narrow').catch(() => false);
  if (!narrowed) {
    narrowMethod = 'page.setViewportSize (compositor did not apply setSize)';
    await w2.setViewportSize({ width: 360, height: normal.content.height });
  }
  await sleep(250);
  const narrow = await w2.evaluate(() => {
    const body = document.getElementById('promptBody'),
      row = document.getElementById('decisionControls');
    const rect = (id) => {
      const r = document.getElementById(id)?.getBoundingClientRect();
      return r && { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height };
    };
    return {
      innerWidth,
      innerHeight,
      body: body && { scrollWidth: body.scrollWidth, clientWidth: body.clientWidth },
      row: row && { scrollWidth: row.scrollWidth, clientWidth: row.clientWidth },
      doc: { scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth },
      controls: Object.fromEntries(['allow', 'block', 'rememberToggle', 'forAWhileToggle'].map((id) => [id, rect(id)])),
    };
  });
  evidence.narrow = { method: narrowMethod, native: await promptNative(), ...narrow };
  await shot(w2, '04-first-view-narrow');
  assert(narrow.innerWidth <= 380, 'narrow viewport applied');
  assert(narrow.body.scrollWidth <= narrow.body.clientWidth, `#promptBody overflows horizontally ${JSON.stringify(narrow.body)}`);
  assert(narrow.row.scrollWidth <= narrow.row.clientWidth, `#decisionControls overflows ${JSON.stringify(narrow.row)}`);
  for (const [id, r] of Object.entries(narrow.controls))
    assert(r && r.width > 0 && r.height > 0 && r.left >= 0 && r.right <= narrow.innerWidth && r.top >= 0 && r.bottom <= narrow.innerHeight, `#${id} visible at narrow width ${JSON.stringify(r)}`);
  step(`narrow ${narrow.innerWidth}px (${narrowMethod}): #promptBody ${narrow.body.scrollWidth}/${narrow.body.clientWidth}, #decisionControls ${narrow.row.scrollWidth}/${narrow.row.clientWidth}; 4 controls inside the viewport`);
  if (narrowMethod.startsWith('page')) await w2.setViewportSize({ width: normal.content.width, height: normal.content.height });
  else
    await app.evaluate(({ BrowserWindow }, b) => {
      const x = BrowserWindow.getAllWindows().find((x) => /[?&]request=/.test(x.webContents.getURL()));
      x.setSize(b.width, b.height);
    }, normal.bounds);
  await sleep(200);
  const blockHide = await clickAndMeasureHide(w2, '#block', 'block');
  evidence.block_hide = blockHide;
  await sleep(2500);
  assert.equal(await alphaCount(), before, 'denied connection delivered');
  const l2 = await list();
  const out2 = l2.events.find((e) => e.id === secondId);
  evidence.block_verdict = out2 && [out2.flow?.direction, out2.state];
  assert.equal(out2?.state, 'blocked', 'outgoing blocked');
  assert(!l2.events.some((e) => e.local_peer && e.state === 'awaiting-decision'), 'no side left pending');
  assert.deepEqual(l2.rules.map((r) => r.id).sort(), rulesBefore, 'Deny created or changed rules');
  const denied = await wait(async () => (await resultRows()).find((r) => r.event === secondId), 10000, 'Results deny entry');
  evidence.block_result = denied;
  step(`Deny hid the window after ${blockHide.hide_ms} ms; nothing delivered, outgoing ${out2.state}, rules unchanged (${rulesBefore.length}); Results "${denied.text}"`);
  if (!/\bresult-ok\b/.test(denied.cls)) finding('Deny result not ok: ' + JSON.stringify(denied));
  assert.deepEqual(evidence.errors, []);
  await menus(true);
  await main.locator('#protectionStop').click();
  await wait(async () => (await list()).protection?.state !== 'active', 30000);
  evidence.pass = evidence.findings.length === 0;
} catch (e) {
  evidence.failure = String(e?.stack || e);
  if (main) await shot(main, 'failure-main');
  if (app) await shot(prompt(), 'failure-prompt');
} finally {
  fs.writeFileSync(run + '/evidence.json', JSON.stringify(evidence, null, 2));
  if (app) await app.close().catch(() => {});
  console.log(evidence.pass ? 'JOURNEY PASS' : 'JOURNEY FAIL', run);
  if (!evidence.pass) process.exitCode = 1;
}
