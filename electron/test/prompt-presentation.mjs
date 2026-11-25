// Labelled synthetic presentation/state checks. Not native receiver/enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/connection-compact-'));
const endpoint = path.join(run, 'api');
let ids = [],
  decisionCalls = [],
  direction = 'incoming',
  disconnected = false,
  resolved = false,
  mutations = 0,
  showEvents = false;
const appIdentity = {
  key: 'fixture',
  revision: 'r',
  name: 'SYNTHETIC dedicated app',
  executable: '/synthetic/' + 'long-directory/'.repeat(18) + 'fixture',
  display_name: 'SYNTHETIC dedicated app',
};
let queuedExpiry = new Date(Date.now() + 1000).toISOString();
const deadline = new Date(Date.now() + 120000).toISOString();
const event = (id) => ({
  id,
  state: resolved ? 'expired' : 'awaiting-decision',
  reason: 'SYNTHETIC presentation fixture',
  deadline: id === 'expires' ? queuedExpiry : deadline,
  request_group: id.startsWith('repeat') ? 'same-repeat' : id,
  first_seen: new Date().toISOString(),
  flow: {
    direction,
    protocol: 'udp',
    local: '[2001:db8::1]:44001',
    remote: '[2001:db8::2]:50000',
    network_scope: {
      state: 'known',
      zone: direction === 'incoming' ? 'local' : 'internet',
      revision: 'r',
      source: 'synthetic',
      reason: 'SYNTHETIC configured zone',
    },
  },
  attribution: {
    status: 'directly-associated',
    visibility_complete: true,
    application: appIdentity,
    owners: [{ pid: 12345, uid: 1000, start_ticks: '123', executable: '/synthetic/fixture' }],
  },
  scope_previews: {
    once: 'Only this held connection.',
    application: 'Backend preview: application and peer/service, any network, one hour.',
    persistent: 'SYNTHETIC persistent rule',
  },
});
const server = net.createServer((s) =>
  s.once('data', (raw) => {
    if (disconnected) {
      s.destroy();
      return;
    }
    const req = JSON.parse(raw);
    if (!['list', 'policy-view'].includes(req.operation)) mutations++;
    if (req.operation === 'decide') {
      decisionCalls.push({ id: req.id, at: Date.now() });
      ids = ids.filter((id) => id !== req.id);
    }
    s.end(
      JSON.stringify({
        version: 1,
        capabilities: ['decision-remember-fields-v1', 'network-zone-policy-v1'],
        network_zones: {
          model: 'configured-prefix-v1',
          revision: 'r',
          local_prefixes: [],
          internet_prefixes: [],
          reason: 'SYNTHETIC',
        },
        ...(req.operation === 'decision-preview'
          ? { error: 'SYNTHETIC validation error: ' + 'long error '.repeat(15) }
          : {}),
        ...(req.operation === 'decide'
          ? {
              decision: { ...event(req.id), state: req.action === 'allow' ? 'allowed' : 'blocked' },
            }
          : {}),
        generation: 'synthetic',
        mode: 'isolated-lab',
        read_only: false,
        server_time: new Date().toISOString(),
        permissions: {
          role: 'administrator',
          policy_scope: 'machine',
          observation_scope: 'machine',
          can_manage_rules: true,
          can_decide: true,
        },
        events: showEvents ? ids.map(event) : [],
        rules: [],
        activity: {
          sequence: 1,
          collected: new Date().toISOString(),
          complete: true,
          processes: {},
          rows: [],
        },
      }) + '\n',
    );
  }),
);
await new Promise((r) => server.listen(endpoint, r));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const wait = async (fn) => {
  for (let n = 0; n < 150; n++) {
    const v = await fn();
    if (v) return v;
    await sleep(50);
  }
  throw Error('timeout');
};
const prefs = path.join(root, 'build/desktop-session/electron-preferences.json'),
  oldPrefs = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
let app, inputDaemon;
const seenRequests = [];
const result = {
  run,
  synthetic: true,
  rememberWindowPositionsLoaded: execFileSync(
    'qdbus6',
    [
      'org.kde.KWin',
      '/Scripting',
      'org.kde.kwin.Scripting.isScriptLoaded',
      'rememberwindowpositions',
    ],
    { encoding: 'utf8' },
  ).trim(),
};
let scriptNumber = 0;
function script(code) {
  const name = 'flowgate-placement-check-' + process.pid + '-' + ++scriptNumber,
    f = path.join(run, name + '.js');
  fs.writeFileSync(f, code);
  const id = execFileSync(
    'qdbus6',
    ['org.kde.KWin', '/Scripting', 'org.kde.kwin.Scripting.loadScript', f, name],
    { encoding: 'utf8' },
  ).trim();
  try {
    execFileSync('qdbus6', ['org.kde.KWin', '/Scripting/Script' + id, 'org.kde.kwin.Script.run']);
  } finally {
    execFileSync('qdbus6', ['org.kde.KWin', '/Scripting/Script' + id, 'org.kde.kwin.Script.stop']);
    execFileSync('qdbus6', [
      'org.kde.KWin',
      '/Scripting',
      'org.kde.kwin.Scripting.unloadScript',
      name,
    ]);
  }
}
const started = new Date().toISOString();
try {
  app = await _electron.launch({
    chromiumSandbox: true,
    args: [
      '--ozone-platform=wayland',
      path.join(root, 'electron'),
      '--observer',
      endpoint,
      '--control',
      endpoint,
    ],
    env: { ...process.env, TMPDIR: path.join(root, '.workspace/tmp') },
  });
  const main = await app.firstWindow();
  await main.locator('#requestsTab').waitFor();
  await sleep(3000); // finish application startup before testing an automatic arrival
  const own = await app.evaluate(() => ({ pid: process.pid }));
  const snapshot = async (label) => {
    const token = 'FLOWGATE_PACING_' + process.pid + '_' + label;
    script(
      `for(const w of workspace.windowList())if(w.pid===${own.pid})print(${JSON.stringify(token)},JSON.stringify({caption:w.caption,geometry:w.frameGeometry,cursor:workspace.cursorPos,keepAbove:w.keepAbove,active:w===workspace.activeWindow,activePID:workspace.activeWindow?.pid,activeCaption:workspace.activeWindow?.caption,area:workspace.clientArea(KWin.PlacementArea,w.output,workspace.currentDesktopForScreen(w.output))}));`,
    );
    const logs = execFileSync(
      'journalctl',
      ['--user', '-b', '--no-pager', '--since', started, '_COMM=kwin_wayland', '-o', 'cat'],
      { encoding: 'utf8' },
    );
    fs.writeFileSync(path.join(run, 'compositor.log'), logs);
    const actual = logs
      .split('\n')
      .filter((l) => l.startsWith(token + ' '))
      .map((l) => JSON.parse(l.slice(token.length + 1)))
      .find((w) => w.caption.startsWith('FlowGate — connection permission'));
    assert(actual, 'native permission window measured');
    if (label !== 'before-opening')
      assert.equal(actual.geometry.x + actual.geometry.width, actual.area.x + actual.area.width);
    if (label !== 'before-opening')
      assert.equal(actual.geometry.y + actual.geometry.height, actual.area.y + actual.area.height);
    result[label] = actual;
    return actual;
  };
  // A separate sandboxed Electron application serves as a visible typing target.
  const focusDir = path.join(run, 'focus-app');
  fs.mkdirSync(focusDir);
  fs.writeFileSync(path.join(focusDir, 'package.json'), JSON.stringify({ main: 'main.cjs' }));
  fs.writeFileSync(
    path.join(focusDir, 'main.cjs'),
    `const {app,BrowserWindow}=require('electron');app.setPath('userData',${JSON.stringify(path.join(run, 'typing-profile'))});app.whenReady().then(()=>{let w=new BrowserWindow({title:'SYNTHETIC separate typing app',webPreferences:{sandbox:true}});w.loadURL('data:text/html,<title>SYNTHETIC separate typing app</title><textarea autofocus></textarea>');});`,
  );
  const other = await _electron.launch({
    chromiumSandbox: true,
    args: ['--ozone-platform=wayland', focusDir],
    env: { ...process.env, TMPDIR: path.join(root, '.workspace/tmp') },
  });
  try {
    const typing = await other.firstWindow();
    await typing.locator('textarea').waitFor();
    const otherPID = await other.evaluate(() => process.pid);
    await sleep(800);
    script(
      `for(const w of workspace.windowList())if(w.pid===${otherPID})workspace.activeWindow=w;`,
    );
    await sleep(200);
    const inputSocket = path.join(run, 'input.sock');
    inputDaemon = spawn('ydotoold', ['--socket-path=' + inputSocket], {
      stdio: 'ignore',
    });
    await wait(() => fs.existsSync(inputSocket));
    await sleep(600);
    script(
      `for(const w of workspace.windowList())if(w.pid===${otherPID})workspace.activeWindow=w;`,
    );
    await sleep(200);
    result.beforeOpening = await snapshot('before-opening');
    assert.equal(
      result.beforeOpening.activePID,
      otherPID,
      'typing target owns actual focus before arrival',
    );
    const text = 'focus 123';
    const input = spawn('ydotool', ['type', '--key-delay', '120', text], {
      env: { ...process.env, YDOTOOL_SOCKET: inputSocket },
      stdio: 'ignore',
    });
    showEvents = true;
    ids = ['first'];
    let prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=first')));
    prompt.on('framenavigated', (frame) => {
      if (frame === prompt.mainFrame())
        seenRequests.push(new URL(frame.url()).searchParams.get('request'));
    });
    await prompt.locator('#allow').waitFor();
    await prompt.locator('#rememberDuration').selectOption('once');
    await sleep(3400);
    result.compact = await snapshot('compact');
    assert.equal(result.compact.active, false, 'automatic opening must not activate');
    input.kill();

    assert.equal(
      result.compact.activePID,
      otherPID,
      'compositor keyboard focus stays in separate app',
    );
    assert.equal(
      await typing.locator('textarea').inputValue(),
      text,
      'actual uinput typing stays in other app during automatic presentation',
    );
    assert.equal(result.compact.keepAbove, true);
    assert.equal(result.compact.geometry.width, 745);
    assert.equal(result.compact.geometry.height, 590);
    const prefs = await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().at(-1).webContents.getLastWebPreferences(),
    );
    assert(prefs.sandbox && prefs.contextIsolation && !prefs.nodeIntegration);
    // A real pointer click may focus the popup normally.
    const checkRect = await prompt.locator('#requestApplication strong').boundingBox();
    const target = {
      x: result.compact.geometry.x + checkRect.x + checkRect.width / 2,
      y: result.compact.geometry.y + checkRect.y + checkRect.height / 2,
    };
    // Relative uinput movement with compositor feedback avoids changing acceleration settings.
    for (let n = 0; n < 12; n++) {
      const position = (await snapshot('pointer-' + n)).cursor;
      const dx = target.x - position.x,
        dy = target.y - position.y;
      if (Math.abs(dx) < checkRect.width / 2 && Math.abs(dy) < checkRect.height / 2) break;
      execFileSync(
        'ydotool',
        ['mousemove', '-x', String(Math.round(dx / 2)), '-y', String(Math.round(dy / 2))],
        { env: { ...process.env, YDOTOOL_SOCKET: inputSocket } },
      );
      await sleep(150);
    }
    execFileSync('ydotool', ['click', '0xC0'], {
      env: { ...process.env, YDOTOOL_SOCKET: inputSocket },
    });
    await sleep(400);
    assert.equal(
      (await snapshot('deliberate-click')).active,
      true,
      'deliberate click focuses normally',
    );
    await prompt.locator('#rememberDuration').selectOption('0');
    await sleep(700);
    result.expanded = await snapshot('expanded');
    assert(result.expanded.geometry.height > 590);
    for (const f of ['protocol', 'process', 'address', 'port'])
      await prompt.locator(`[data-field="${f}"]`).check();
    for (const value of ['0', '60', '300', '600', '1800', '3600', '21600', '43200'])
      await prompt.selectOption('#rememberDuration', value);
    await sleep(700);
    assert.match(
      await prompt.locator('#requestMore #rememberSummary').textContent(),
      /SYNTHETIC validation error/,
    );
    assert(await prompt.locator('#rememberSummary').isHidden());
    await prompt.locator('#rememberDuration').focus();
    queuedExpiry = new Date(Date.now() + 700).toISOString();
    ids.push(...Array.from({ length: 20 }, (_, i) => 'repeat' + i), 'expires', 'second');
    await sleep(1200);
    assert(prompt.url().includes('?request=first'));
    assert(await prompt.locator('[data-field="port"]').isChecked());
    assert.equal(await prompt.locator('#rememberDuration').inputValue(), '43200');
    assert.equal(await prompt.evaluate(() => document.activeElement.id), 'rememberDuration');
    assert.match(await prompt.locator('#promptPending').innerText(), /\(3\)/);
    await prompt.locator('summary').click();
    await sleep(600);
    result.details = await snapshot('details');
    await prompt.screenshot({ path: path.join(run, 'expanded-details.png') });
    await prompt.locator('summary').click();
    await prompt.locator('#rememberDuration').selectOption('once');
    await sleep(700);
    result.collapsed = await snapshot('collapsed');
    assert.equal(result.collapsed.geometry.height, 590);
    // Manual resize of this card must not be inherited by the next one.
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()
        .find((w) => w.webContents.getURL().includes('?request=first'))
        .setSize(700, 800),
    );
    await sleep(500);
    script(
      `for(const w of workspace.windowList())if(w.pid===${own.pid} && w.caption.includes('connection permission')) {const a=workspace.clientArea(KWin.PlacementArea,w.output,workspace.currentDesktopForScreen(w.output));w.frameGeometry={x:a.x+a.width-700,y:a.y+a.height-800,width:700,height:800};}`,
    );
    await sleep(1200);
    result.manuallyResized = await snapshot('manual-resize');
    assert.equal(
      result.manuallyResized.geometry.height,
      800,
      'polling preserves user-sized height',
    );
    const decisionAt = Date.now();
    await prompt.locator('#allow').dblclick({ delay: 80 });
    await sleep(300);
    assert.equal(decisionCalls.length, 1);
    assert(prompt.url().includes('?request=first'));
    prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=repeat0')));
    await prompt.locator('#allow').waitFor();
    await sleep(100);
    assert(await prompt.locator('#allow').isDisabled(), 'new presentation starts disabled');
    assert(
      await prompt.locator('#rememberDuration').isDisabled(),
      'new options advertise the same readiness gate',
    );
    await prompt.locator('#rememberDuration').selectOption('once');
    await wait(() => prompt.locator('#allow').isEnabled());
    await sleep(500);
    result.reset = await snapshot('reset');
    assert.equal(result.reset.geometry.width, 745);
    assert.equal(result.reset.geometry.height, 590);
    assert.equal(decisionCalls.length, 1, 'double-click only decided one request');
    await app.evaluate(({ BrowserWindow }) => {
      globalThis.popupInputs = [];
      BrowserWindow.getAllWindows()
        .find((w) => w.webContents.getURL().includes('?request=repeat0'))
        .webContents.on('before-input-event', (_, i) =>
          globalThis.popupInputs.push({ key: i.key, type: i.type, repeat: i.isAutoRepeat }),
        );
    });
    await prompt.locator('#allow').focus();
    await prompt.keyboard.down('Enter');
    await sleep(850);
    result.inputEvents = await app.evaluate(() => globalThis.popupInputs);
    assert(
      prompt.url().includes('?request=repeat0'),
      'held Enter delays following card ' + JSON.stringify(result.inputEvents),
    );
    for (let i = 0; i < 4; i++) await prompt.keyboard.down('Enter');
    assert.equal(decisionCalls.length, 2);
    await prompt.keyboard.up('Enter');
    await sleep(350);
    assert(prompt.url().includes('?request=repeat0'));
    await wait(() => Promise.resolve(prompt.url().includes('?request=repeat1')));
    await wait(() => prompt.locator('#allow').isEnabled());
    assert.equal(decisionCalls.length, 2);
    assert(!seenRequests.includes('expires'), 'queued expiry never presented');
    result.seenRequests = seenRequests;
    result.decisionCalls = decisionCalls;
    result.transitionMS = 650;
    result.elapsedHandoff = decisionCalls[1].at - decisionAt;
    // Clamped viewport: no display settings change. Scroll only at native available height.
    await app.evaluate(({ screen }) => {
      const actual = screen.getPrimaryDisplay.bind(screen);
      screen.getPrimaryDisplay = () => {
        const d = actual();
        return { ...d, workArea: { ...d.workArea, width: 400, height: 400 } };
      };
    });
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()
        .find((w) => w.webContents.getURL().includes('?request=repeat1'))
        .setSize(400, 400),
    );
    await prompt.locator('#rememberDuration').selectOption('0');
    await sleep(700);
    await prompt.locator('#promptBody').evaluate((el) => (el.scrollTop = el.scrollHeight));
    const decisionRect = await prompt.locator('#allow').boundingBox();
    assert(
      decisionRect.y >= 0 && decisionRect.y + decisionRect.height <= 400,
      'decision controls reachable in constrained viewport',
    );
    result.constrained = await snapshot('constrained');
    assert.equal(result.constrained.geometry.height, 400);
    await prompt.screenshot({ path: path.join(run, 'small.png') });
    result.passed = true;
  } finally {
    await other.close();
  }
  result.mutations = mutations;
  result.passed = true;
  console.log('PASS popup pacing/focus/content sizing', run);
} finally {
  inputDaemon?.kill();
  if (app) await app.close();
  if (oldPrefs) fs.writeFileSync(prefs, oldPrefs);
  else fs.rmSync(prefs, { force: true });
  server.close();
  fs.writeFileSync(path.join(run, 'placement-result.json'), JSON.stringify(result, null, 2));
}
