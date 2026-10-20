// Labelled synthetic presentation/state checks. Not native receiver/enforcement evidence.
import { _electron } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '../..');
const run = fs.mkdtempSync(path.join(root, '.workspace/connection-compact-'));
const endpoint = path.join(run, 'api');
let direction = 'incoming',
  disconnected = false,
  resolved = false,
  mutations = 0,
  showEvents = false;
const appIdentity = {
  key: 'fixture',
  revision: 'r',
  name: 'SYNTHETIC dedicated app',
  executable: '/synthetic/fixture',
  display_name: 'SYNTHETIC dedicated app',
};
const deadline = new Date(Date.now() + 120000).toISOString();
const event = (id) => ({
  id,
  state: resolved ? 'expired' : 'awaiting-decision',
  reason: 'SYNTHETIC presentation fixture',
  deadline,
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
    owners: [],
  },
  scope_previews: {
    once: 'Only this held connection.',
    application: 'Backend preview: application and peer/service, any network, one hour.',
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
    s.end(
      JSON.stringify({
        version: 1,
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
        events: showEvents ? [event('first'), event('second')] : [],
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
const prefs = path.join(root, '.workspace/electron-preferences.json'),
  oldPrefs = fs.existsSync(prefs) ? fs.readFileSync(prefs) : undefined;
let app;
const result = { run, synthetic: true };
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
  await main.evaluate(() => window.flowgate.paneControl('info', 'undock'));
  const info = await wait(() => app.windows().find((w) => w.url().includes('pane.html')));
  const own = await app.evaluate(({ BrowserWindow }) => ({
    pid: process.pid,
    windows: BrowserWindow.getAllWindows().map((w) => ({ id: w.id, title: w.getTitle() })),
  }));
  const outputs = JSON.parse(
    execFileSync('kscreen-doctor', ['-j'], {
      encoding: 'utf8',
      env: { ...process.env, QT_QPA_PLATFORM: 'wayland', WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY || 'wayland-0' },
    }),
  )
    .outputs.filter((o) => o.connected && o.priority > 0)
    .sort((a, b) => a.priority - b.priority);
  const primary = outputs[0].name,
    secondary = outputs.at(-1).name;
  script(
    `for(const w of workspace.windowList()) if(w.pid===${own.pid}) { const o=workspace.screens.find(o=>o.name===(w.caption==='FlowGate'?${JSON.stringify(secondary)}:${JSON.stringify(primary)})); if(o) workspace.sendClientToScreen(w,o); }`,
  );
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()
      .find((w) => w.getTitle() === 'FlowGate')
      .hide(),
  );
  showEvents = true;
  let prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=first')));
  await prompt.locator('#allow').waitFor();
  await sleep(2600);
  const inspect = async (page, label) => {
    const requestId = new URL(page.url()).searchParams.get('request');
    const native = await app.evaluate(({ BrowserWindow }, id) => {
      const w = BrowserWindow.getAllWindows().find(
        (w) => new URL(w.webContents.getURL()).searchParams.get('request') === id,
      );
      return {
        id: w.id,
        title: w.getTitle(),
        zoom: w.webContents.getZoomFactor(),
        parent: !!w.getParentWindow(),
      };
    }, requestId);
    fs.writeFileSync(path.join(run, label + '-native.json'), JSON.stringify(native));
    const token = 'FLOWGATE_CHECK_' + process.pid + '_' + label;
    script(
      `for(const w of workspace.windowList())if(w.pid===${own.pid})print(${JSON.stringify(token)},JSON.stringify({caption:w.caption,output:w.output.name,geometry:w.frameGeometry,opacity:w.opacity,area:workspace.clientArea(KWin.PlacementArea,w.output,workspace.currentDesktopForScreen(w.output))}));`,
    );
    const readLogs = () =>
      execFileSync(
        'journalctl',
        ['--user', '-b', '--no-pager', '--since', started, '_COMM=kwin_wayland', '-o', 'cat'],
        { encoding: 'utf8' },
      );
    const logs = await wait(() => {
      const text = readLogs();
      return text.split('\n').some((l) => l.startsWith(token + ' ') && l.includes(native.title))
        ? text
        : undefined;
    });
    fs.writeFileSync(
      path.join(run, 'compositor.log'),
      logs
        .split('\n')
        .filter((l) => l.includes(String(own.pid)) || l.startsWith('FLOWGATE_CHECK_' + process.pid))
        .join('\n'),
    );
    const line = logs
      .split('\n')
      .find((l) => l.startsWith(token + ' ') && l.includes(native.title));
    assert(line, 'compositor response');
    const actual = JSON.parse(line.slice(token.length + 1));
    assert.equal(actual.output, primary);
    assert.equal(actual.opacity, 1);
    assert.equal(native.parent, false);
    assert.equal(native.zoom, 1);
    assert.deepEqual(
      { ...actual.geometry },
      {
        x: actual.area.x + actual.area.width - 745,
        y: actual.area.y + actual.area.height - 590,
        width: 745,
        height: 590,
      },
    );
    await page.screenshot({ path: path.join(run, label + '.png') });
    return { native, ...actual };
  };
  result.first = await inspect(prompt, 'hidden-main-detached-info');
  await sleep(1200);
  result.afterPolling = await inspect(prompt, 'stable');
  assert.deepEqual(result.first, result.afterPolling);
  await prompt.evaluate(() => window.flowgate.dismissPrompt());
  prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=second')));
  await prompt.locator('#allow').waitFor();
  await sleep(2600);
  result.second = await inspect(prompt, 'second-arrival');
  const held = fs.readFileSync(path.join(run, 'compositor.log'), 'utf8');
  assert.match(held, /FLOWGATE_PROMPT_HELD/);
  assert.match(held, /FLOWGATE_PROMPT_CONFIRMED/);
  await app.evaluate(({ BrowserWindow }) =>
    BrowserWindow.getAllWindows()
      .find((w) => w.webContents.getURL().includes('?request=second'))
      .setSize(400, 400),
  );
  await sleep(500);
  const rect = await prompt.locator('#allow').boundingBox(),
    viewport = await prompt.evaluate(() => ({ width: innerWidth, height: innerHeight }));
  assert(
    rect && rect.x >= 0 && rect.y >= 0 && rect.y + rect.height <= viewport.height - 35,
    'Allow remains visible in compact400x400',
  );
  await prompt.screenshot({ path: path.join(run, 'small400.png') });
  result.small = { viewport, allow: rect };
  assert.equal(mutations, 0);
  result.mutations = mutations;
  result.passed = true;
  console.log('PASS compositor placement', run);
} finally {
  if (app) await app.close();
  if (oldPrefs) fs.writeFileSync(prefs, oldPrefs);
  else fs.rmSync(prefs, { force: true });
  server.close();
  fs.writeFileSync(path.join(run, 'placement-result.json'), JSON.stringify(result, null, 2));
}
