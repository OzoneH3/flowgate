import { app, BrowserWindow, ipcMain, protocol, session, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';
import { ApplicationIcons } from './icons';
import { Background } from './background';
import { TrafficHistory } from './history';
import type { RequestRef } from './notifications';
import fs from 'node:fs';
import { ExtendedMonitoring } from './extended';
import { Rules } from './rules';
import { Evaluation } from './evaluation';
import type { Preferences } from './protocol';
import { Backend } from './backend';
import { validateDecision } from './protocol';
if (process.getuid?.() === 0) throw Error('FlowGate Electron must run unprivileged');
app.enableSandbox();
const workspace = path.resolve(__dirname, '../../.workspace');
fs.mkdirSync(workspace, { recursive: true });
const profile = fs.mkdtempSync(path.join(workspace, 'electron-profile-'));
app.setPath('userData', profile);
app.setPath('sessionData', profile);
app.setPath('crashDumps', path.join(profile, 'crashes'));
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'flowgate',
    privileges: { standard: true, secure: true, supportFetchAPI: false, corsEnabled: false },
  },
]);
function option(name: string) {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
}
const observer = option('--observer');
const controller = option('--control');
for (const p of [observer, controller])
  if (p !== undefined && (!path.isAbsolute(p) || Buffer.byteLength(p) > 107))
    throw Error('Endpoints must be absolute Unix socket paths of at most 107 bytes');
if (!observer) throw Error('Use scripts/run-electron.sh, or provide --observer /absolute/socket');
function dimension(name: string, fallback: number, min: number, max: number) {
  const value = option(name);
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw Error('Invalid window dimension');
  return n;
}
let saved: { width?: number; height?: number; ui?: Preferences } = {};
const prefsFile = path.join(workspace, 'electron-preferences.json');
try {
  saved = JSON.parse(fs.readFileSync(prefsFile, 'utf8'));
} catch {}
const persist = () => fs.writeFileSync(prefsFile, JSON.stringify(saved), { mode: 0o600 });
const width = dimension(
    '--width',
    Math.max(800, Math.min(3840, Number(saved.width) || 1280)),
    800,
    3840,
  ),
  height = dimension(
    '--height',
    Math.max(550, Math.min(2160, Number(saved.height) || 820)),
    550,
    2160,
  );
let main: BrowserWindow;
let prompt: BrowserWindow | undefined;
const windows = new Set<BrowserWindow>();
let backend: Backend;
let evaluation: Evaluation;
let background: Background;
let quitting = false;
function showMain(list = false, message = '') {
  if (main.isDestroyed()) return;
  main.show();
  main.restore();
  main.focus();
  main.webContents.send('state', backend.view());
  if (list) main.webContents.send('navigate', { tab: 'requests', message });
}
async function review(ref: RequestRef) {
  await backend.pollControl();
  const c = backend.view().control;
  const e = c.events.find((e) => e.id === ref.id);
  if (
    !c.connected ||
    c.generation !== ref.generation ||
    !e ||
    e.state !== 'awaiting-decision' ||
    e.remainingMs <= 0 ||
    e.attempt
  ) {
    showMain(
      true,
      'Request no longer pending or controller unavailable. Review the current list; no decision was sent.',
    );
    return;
  }
  if (prompt && !prompt.isDestroyed()) prompt.close();
  prompt = windowFor(true, ref.id, ref.generation);
}
function trusted(e: IpcMainInvokeEvent) {
  if (
    ![...windows].some((w) => !w.isDestroyed() && w.webContents === e.sender) ||
    e.senderFrame !== e.sender.mainFrame
  )
    throw Error('Untrusted IPC sender');
  const u = new URL(e.senderFrame.url);
  if (u.protocol !== 'flowgate:' || u.host !== 'app' || u.pathname !== '/index.html')
    throw Error('Unexpected IPC origin');
}
function windowFor(isPrompt = false, id = '', generation = '') {
  const w = new BrowserWindow({
    title: isPrompt ? 'FlowGate — connection permission' : 'FlowGate',
    width: isPrompt ? 620 : width,
    height: isPrompt ? 740 : height,
    minWidth: isPrompt ? 480 : 800,
    minHeight: isPrompt ? 560 : 550,
    backgroundColor: '#222222',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
    },
  });
  windows.add(w);
  w.setMenu(null);
  w.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  w.webContents.on('will-navigate', (e) => e.preventDefault());
  w.webContents.on('will-attach-webview', (e) => e.preventDefault());
  w.on('closed', () => windows.delete(w));
  w.once('ready-to-show', () => w.show());
  const refresh = () => {
    if (backend && !w.isDestroyed()) w.webContents.send('state', backend.view());
  };
  w.on('show', refresh);
  w.on('restore', refresh);
  void w.loadURL(
    'flowgate://app/index.html' +
      (isPrompt
        ? '?request=' + encodeURIComponent(id) + '&generation=' + encodeURIComponent(generation)
        : ''),
  );
  return w;
}
app.whenReady().then(async () => {
  const csp =
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'";
  const icons = new ApplicationIcons();
  protocol.handle('flowgate', (request) => {
    const u = new URL(request.url);
    const name = u.pathname.slice(1);
    if (u.host === 'app' && /^icons\/[a-f0-9]{64}\.(png|svg)$/.test(name)) {
      const asset = icons.asset(name.slice(6));
      return asset
        ? new Response(new Uint8Array(asset.data), {
            headers: {
              'Content-Type': asset.type,
              'Content-Security-Policy': csp,
              'X-Content-Type-Options': 'nosniff',
            },
          })
        : new Response('Not found', { status: 404 });
    }
    if (u.host !== 'app' || !['index.html', 'style.css', 'renderer.js'].includes(name))
      return new Response('Not found', { status: 404 });
    return new Response(fs.readFileSync(path.join(__dirname, name)), {
      headers: {
        'Content-Type': name.endsWith('.html')
          ? 'text/html'
          : name.endsWith('.css')
            ? 'text/css'
            : 'text/javascript',
        'Content-Security-Policy': csp,
        'X-Content-Type-Options': 'nosniff',
      },
    });
  });
  session.defaultSession.setPermissionRequestHandler((_w, _p, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onBeforeRequest((details, callback) =>
    callback({ cancel: !details.url.startsWith('flowgate://app/') }),
  );
  const history = new TrafficHistory();
  ipcMain.handle('graph', (e, value) => {
    trusted(e);
    return history.view(value);
  });
  backend = new Backend(observer!, controller, (state) => {
    history.observe(state.observation);
    icons.observe(state);
    for (const w of windows)
      if (!w.isDestroyed() && w.isVisible() && !w.isMinimized()) w.webContents.send('state', state);
    background?.update(state);
  });
  ipcMain.handle('application:icons', (e, value) => {
    trusted(e);
    return icons.request(value);
  });
  const rules = new Rules(backend);
  const extended = new ExtendedMonitoring(path.resolve(__dirname, '../..'));
  ipcMain.handle('extended:action', (e, a) => {
    trusted(e);
    return extended.action(a);
  });
  ipcMain.handle('extended:state', (e) => {
    trusted(e);
    return extended.view(backend.view().observation.activity?.udp?.state === 'active');
  });
  evaluation = new Evaluation(
    path.resolve(__dirname, '../..'),
    backend,
    controller || '/run/flowgate-api/control.sock',
  );
  for (const [channel, handler] of Object.entries({
    'rule:draft': (v: unknown) => rules.draft(v),
    'rule:preview': (v: unknown) => rules.preview(v),
    'rule:save': (v: unknown) => rules.save(v),
    'rule:reconcile': (v: unknown) => rules.reconcile(v),
    'rule:delete': (v: unknown) => rules.delete(v),
  }))
    ipcMain.handle(channel, (e, v) => {
      trusted(e);
      return handler(v);
    });
  ipcMain.handle('evaluation:action', (e, a, p) => {
    trusted(e);
    return evaluation.action(a, p);
  });
  ipcMain.handle('evaluation:state', (e) => {
    trusted(e);
    return evaluation.state;
  });
  ipcMain.handle('background:status', (e) => {
    trusted(e);
    return background.status();
  });
  ipcMain.handle('app:quit', (e) => {
    trusted(e);
    return background.requestQuit();
  });
  ipcMain.handle('preferences', (e, v) => {
    trusted(e);
    if (v !== undefined) {
      if (
        !v ||
        typeof v !== 'object' ||
        Object.keys(v).some((k) => !['sidebar', 'columns', 'keepInTray'].includes(k))
      )
        throw Error('Invalid preferences');
      if (
        v.sidebar !== undefined &&
        (!Number.isInteger(v.sidebar) || v.sidebar < 240 || v.sidebar > 600)
      )
        throw Error('Invalid sidebar');
      if (v.keepInTray !== undefined && typeof v.keepInTray !== 'boolean')
        throw Error('Invalid tray preference');
      const columns: Record<string, number> = {};
      if (v.columns) {
        if (typeof v.columns !== 'object' || Object.keys(v.columns).length > 16)
          throw Error('Invalid columns');
        for (const [k, n] of Object.entries(v.columns)) {
          if (
            ![
              'name',
              'download_bps',
              'upload_bps',
              'count',
              'pid',
              'downloaded',
              'uploaded',
              'protocol',
              'local',
              'remote',
              'state',
            ].includes(k) ||
            !Number.isInteger(n) ||
            Number(n) < 45 ||
            Number(n) > 700
          )
            throw Error('Invalid column');
          columns[k] = Number(n);
        }
      }
      saved.ui = {
        ...saved.ui,
        sidebar: v.sidebar,
        columns,
        ...(v.keepInTray !== undefined ? { keepInTray: v.keepInTray } : {}),
      };
      persist();
    }
    return saved.ui || {};
  });
  ipcMain.handle('snapshot', (e) => {
    trusted(e);
    return backend.view();
  });
  ipcMain.handle('decide', (e, value) => {
    trusted(e);
    return backend.decide(validateDecision(value));
  });
  ipcMain.handle('prompt:open', (e, id) => {
    trusted(e);
    if (
      typeof id !== 'string' ||
      id.length > 256 ||
      !backend.view().control.events.some((v) => v.id === id)
    )
      throw Error('Unknown request');
    if (prompt && !prompt.isDestroyed()) prompt.close();
    prompt = windowFor(true, id, backend.view().control.generation);
  });
  ipcMain.handle('prompt:dismiss', (e) => {
    trusted(e);
    if (prompt && !prompt.isDestroyed() && prompt.webContents === e.sender) prompt.close();
  });
  main = windowFor();
  main.on('resize', () => {
    const [w, h] = main.getSize();
    saved.width = w;
    saved.height = h;
    persist();
  });
  background = new Background(
    main,
    windows,
    () => backend.view(),
    showMain,
    (ref) => void review(ref),
    () => app.quit(),
  );
  main.on('close', (e) => {
    if (quitting) return;
    e.preventDefault();
    if (saved.ui?.keepInTray === true && background.available()) {
      if (prompt && !prompt.isDestroyed()) prompt.close();
      main.hide();
    } else void background.requestQuit();
  });
  main.on('closed', () => app.quit());
  backend.start();
});
app.on('before-quit', () => {
  quitting = true;
  background?.close();
  backend?.stop();
  evaluation?.close();
});
app.on('window-all-closed', () => app.quit());
process.on('SIGTERM', () => app.quit());
process.on('SIGINT', () => app.quit());
