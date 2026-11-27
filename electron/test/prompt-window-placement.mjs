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
const direction = 'incoming';
let mutations = 0, showEvents = false, releasePreviews;
const pendingPreviews = new Set();
const previewRequests = new Map();
const previewsReady = new Promise(resolve => { releasePreviews = resolve; });
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
  state: 'awaiting-decision',
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
    owners: [{ pid: 12345, uid: 1000, start_ticks: '123', executable: appIdentity.executable, application: appIdentity }],
  },
  remembered_filter: { application: appIdentity.key, revision: appIdentity.revision, uid: 1000,
    direction, protocol: 'udp', remote_address: '2001:db8::2', local_port: 44001, remote_port: 0 },
  scope_previews: {
    once: 'Only this held connection.',
    application: 'Backend preview: application and peer/service, any network, one hour.',
    persistent: 'This application.',
  },
});
const server = net.createServer((s) =>
  s.once('data', async (raw) => {
    const req = JSON.parse(raw);
    const now = new Date().toISOString();
    let preview;
    if (req.operation === 'decision-preview') {
      const e = event(req.id);
      pendingPreviews.add(req.action);
      await previewsReady;
      const key = req.id + ':' + req.action;
      previewRequests.set(key, (previewRequests.get(key) || 0) + 1);
      preview = {
        ...req, event_id: e.id, token: `preview-${e.id}-${req.action}`,
        expires_at: new Date(Date.now() + 6000).toISOString(),
        connection_network: e.flow.network_scope,
        scope_preview: e.scope_previews[req.scope],
        summary: req.action + ' this application.',
        rule: {
          id: `rule-${e.id}-${req.action}`, version: 1, action: req.action,
          created: now, expires: '0001-01-01T00:00:00Z',
          filter: { ...e.remembered_filter, protocol: '*', remote_address: '*', local_port: 0 },
        },
      };
    } else if (!['list', 'policy-view'].includes(req.operation)) mutations++;
    s.end(
      JSON.stringify({
        version: 1,
        generation: 'synthetic',
        mode: 'isolated-lab',
        read_only: false,
        server_time: now,
        capabilities: ['decision-remember-fields-v1', 'network-zone-policy-v1',
          'decision-for-a-while-v1', 'decision-for-a-while-durations-v1'],
        for_a_while_durations: [15, 60, 300, 600, 1800, 3600],
        network_zones: { model: 'configured-prefix-v1', revision: 'r', local_prefixes: [], internet_prefixes: [], reason: 'Synthetic' },
        ...(preview ? { decision_preview: preview } : {}),
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
const prefs = path.join(root, 'build/desktop-session/electron-preferences.json'),
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
    env: { ...process.env, FLOWGATE_INSTALLED: '0', TMPDIR: path.join(root, '.workspace/tmp'),
      XDG_CONFIG_HOME: path.join(run, 'config'), XDG_CACHE_HOME: path.join(run, 'cache') },
  });
  const main = await wait(() => app.windows().find((w) => w.url().endsWith('/index.html')));
  await wait(() => main.evaluate(() => !!document.querySelector('#requestsTab')));
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
  await wait(() => pendingPreviews.has('allow') && pendingPreviews.has('block'));
  assert(await prompt.locator('#rememberPanel').isVisible());
  assert(await prompt.locator('#allow').isDisabled());
  assert(await prompt.locator('#block').isDisabled());
  releasePreviews();
  const waitForActions = (page) => page.waitForFunction(() =>
    document.querySelector('#allow')?.disabled === false &&
    document.querySelector('#block')?.disabled === false,
  );
  await waitForActions(prompt);
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
      `for(const w of workspace.windowList())if(w.pid===${own.pid})print(${JSON.stringify(token)},JSON.stringify({caption:w.caption,output:w.output.name,geometry:w.frameGeometry,opacity:w.opacity,area:workspace.clientArea(KWin.PlacementArea,w.output,typeof workspace.currentDesktopForScreen==='function'?workspace.currentDesktopForScreen(w.output):workspace.currentDesktop)}));`,
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
    const { width, height } = actual.geometry;
    assert.equal(width, 745);
    assert.equal(actual.geometry.x + width, actual.area.x + actual.area.width);
    assert.equal(actual.geometry.y + height, actual.area.y + actual.area.height);
    const ruleSection = await page.locator('#rememberPanel').boundingBox();
    assert(ruleSection && ruleSection.y + ruleSection.height <= height);
    const actions = {};
    for (const action of ['allow', 'block']) {
      const button = page.locator('#' + action);
      const rect = await button.boundingBox();
      actions[action] = { enabled: await button.isEnabled(), rect };
      assert(actions[action].enabled && rect && rect.y + rect.height <= height);
    }
    await page.screenshot({ path: path.join(run, label + '.png') });
    return { native, ...actual, actions, ruleSection };
  };
  result.first = await inspect(prompt, 'hidden-main-detached-info');
  await sleep(1200);
  result.afterPolling = await inspect(prompt, 'stable');
  assert.deepEqual(result.first, result.afterPolling);
  // Reproduce the stale Electron flags independently of KWin's actual mapped
  // state. No focus event should be needed to renew a preview or retarget.
  await app.evaluate(({ BrowserWindow }, id) => {
    const window = BrowserWindow.fromId(id);
    window.isVisible = () => false;
    window.isMinimized = () => true;
    window.fixtureFocusCount = Number(window.isFocused());
    window.on('focus', () => window.fixtureFocusCount++);
  }, result.first.native.id);
  const previewCounts = ['allow', 'block'].map(action => previewRequests.get('first:' + action));
  await wait(() => ['allow', 'block'].every((action, index) =>
    previewRequests.get('first:' + action) > previewCounts[index],
  ));
  await waitForActions(prompt);
  result.renewedWithoutFocus = true;
  await prompt.evaluate(() => window.flowgate.dismissPrompt());
  prompt = await wait(() => app.windows().find((w) => w.url().includes('?request=second')));
  await prompt.locator('#allow').waitFor();
  await waitForActions(prompt);
  result.second = await inspect(prompt, 'second-arrival');
  assert.equal(result.second.native.id, result.first.native.id);
  assert.equal(await app.evaluate(({ BrowserWindow }, id) =>
    BrowserWindow.fromId(id).fixtureFocusCount, result.second.native.id), 0);
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
  releasePreviews();
  if (app) await app.close();
  if (oldPrefs) fs.writeFileSync(prefs, oldPrefs);
  else fs.rmSync(prefs, { force: true });
  server.close();
  fs.writeFileSync(path.join(run, 'placement-result.json'), JSON.stringify(result, null, 2));
}
