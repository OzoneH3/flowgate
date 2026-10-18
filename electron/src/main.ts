import { placeKDEPrompt, PROMPT_TITLE, promptTitle } from './prompt-placement';
import { AutomaticPrompts, edgePosition, boundDecision } from './automatic-prompts';
import {
  app,
  BrowserWindow,
  clipboard,
  ipcMain,
  protocol,
  session,
  screen,
  type IpcMainInvokeEvent,
} from 'electron';
import path from 'node:path';
import {
  PaneModel,
  paneKind,
  ruleAction,
  visibleGeometry,
  type PaneKind,
  type Rect,
} from './pane-model';
import { isDisplayUnit } from './display-units';
import { bundledAsset } from './assets';
import { ApplicationIcons } from './icons';
import { Background } from './background';
import { TrafficHistory } from './history';
import type { RequestRef } from './notifications';
import fs from 'node:fs';
import { ExtendedMonitoring } from './extended';
import { Rules } from './rules';
import { sameProcessTarget } from './process-rules';
import { DecisionLogClient } from './decision-log-client';
import { Evaluation } from './evaluation';
import type { Preferences } from './protocol';
import { Backend } from './backend';
import { validateDecision } from './protocol';
if (process.getuid?.() === 0) throw Error('FlowGate Electron must run unprivileged');
app.enableSandbox();
// Native Wayland uses the accelerated OpenGL/ANGLE path; Vulkan presentation
// is unsupported by Chromium's Wayland surface factory in this Electron release.
// WebGPU's Vulkan/GL interop otherwise initializes Vulkan independently of the
// compositor flag. Select its GLES adapter too; do not disable GPU acceleration.
if (app.commandLine.getSwitchValue('ozone-platform') === 'wayland') {
  const disabled = new Set(
    app.commandLine.getSwitchValue('disable-features').split(',').filter(Boolean),
  );
  disabled.add('Vulkan');
  app.commandLine.appendSwitch('disable-features', [...disabled].join(','));
  app.commandLine.appendSwitch('use-angle', 'gl');
  app.commandLine.appendSwitch('use-webgpu-adapter', 'opengles');
}
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
let saved: {
  width?: number;
  height?: number;
  ui?: Preferences;
  panes?: Partial<Record<PaneKind, Rect>>;
} = {};
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
const automaticPrompts = new AutomaticPrompts();
const promptRefs = new Map<number, RequestRef>();
function openDecision(ref: RequestRef) {
  if (prompt && !prompt.isDestroyed()) {
    const url = new URL(prompt.webContents.getURL() || 'about:blank');
    if (
      url.searchParams.get('request') === ref.id &&
      url.searchParams.get('generation') === ref.generation
    ) {
      prompt.show();
      prompt.focus();
      return;
    }
    prompt.close();
  }
  automaticPrompts.mark(ref);
  prompt = windowFor(true, ref.id, ref.generation);
}
function automaticDecision() {
  if (quitting || !backend || !main) return;
  const next = automaticPrompts.next(backend.view(), !!prompt && !prompt.isDestroyed());
  if (next) openDecision(next);
}
const windows = new Set<BrowserWindow>();
let backend: Backend;
let evaluation: Evaluation;
let background: Background;
let quitting = false;
const paneModel = new PaneModel(
  isDisplayUnit(saved.ui?.displayUnit) ? saved.ui.displayUnit : 'autoByte',
);
const detached = new Map<PaneKind, BrowserWindow>();
const paneRoles = new Map<number, PaneKind>();
const paneFrame = () => ({ presentation: paneModel.value, state: backend.view() });
function publishPanes() {
  if (!backend || quitting) return;
  for (const w of windows) if (!w.isDestroyed()) w.webContents.send('pane:frame', paneFrame());
}
function paneWindow(kind: PaneKind) {
  const existing = detached.get(kind);
  if (existing && !existing.isDestroyed()) {
    existing.show();
    existing.focus();
    return;
  }
  const bounds = visibleGeometry(
    saved.panes?.[kind],
    screen.getAllDisplays().map((d) => d.workArea),
    { x: 40, y: 40, width: kind === 'info' ? 500 : 700, height: kind === 'info' ? 650 : 350 },
  );
  const w = new BrowserWindow({
    title: kind === 'info' ? 'FlowGate — Info View' : 'FlowGate — Traffic chart',
    ...bounds,
    minWidth: 320,
    minHeight: 220,
    backgroundColor: '#222222',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'pane-preload.cjs'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      webviewTag: false,
      spellcheck: false,
    },
  });
  detached.set(kind, w);
  paneRoles.set(w.webContents.id, kind);
  windows.add(w);
  w.setMenu(null);
  w.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  w.webContents.on('will-navigate', (e) => e.preventDefault());
  w.webContents.on('will-attach-webview', (e) => e.preventDefault());
  const save = () => {
    if (!quitting && !w.isDestroyed()) {
      saved.panes = { ...saved.panes, [kind]: w.getBounds() };
      persist();
    }
  };
  w.on('resize', save);
  w.on('move', save);
  w.once('ready-to-show', () => {
    if (main.isVisible()) w.show();
    publishPanes();
  });
  const contentsID = w.webContents.id;
  w.on('closed', () => {
    paneRoles.delete(contentsID);
    windows.delete(w);
    detached.delete(kind);
    if (!quitting) {
      if (paneModel.value.panes[kind] === 'detached') paneModel.mode(kind, 'hidden');
      publishPanes();
    }
  });
  void w.loadURL('flowgate://app/pane.html?pane=' + kind);
}

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
  openDecision(ref);
}
function trusted(e: IpcMainInvokeEvent, allowPane = false) {
  if (
    ![...windows].some((w) => !w.isDestroyed() && w.webContents === e.sender) ||
    e.senderFrame !== e.sender.mainFrame
  )
    throw Error('Untrusted IPC sender');
  const u = new URL(e.senderFrame.url);
  if (
    u.protocol !== 'flowgate:' ||
    u.host !== 'app' ||
    u.pathname !== (paneRoles.has(e.sender.id) ? '/pane.html' : '/index.html') ||
    (!allowPane && paneRoles.has(e.sender.id))
  )
    throw Error('Unexpected IPC origin');
}
function presentationSender(e: IpcMainInvokeEvent) {
  trusted(e, true);
  if (e.sender !== main.webContents && !paneRoles.has(e.sender.id))
    throw Error('Presentation operation is unavailable from a prompt');
}
function windowFor(isPrompt = false, id = '', generation = '') {
  const w = new BrowserWindow({
    title: isPrompt ? PROMPT_TITLE : 'FlowGate',
    frame: !isPrompt,
    width: isPrompt ? 520 : width,
    height: isPrompt ? 460 : height,
    minWidth: isPrompt ? 480 : 800,
    minHeight: isPrompt ? 400 : 550,
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
  if (isPrompt) {
    w.setTitle(promptTitle(w.id));
    promptRefs.set(w.webContents.id, { id, generation });
    w.on('page-title-updated', (event) => event.preventDefault());
    const senderID = w.webContents.id;
    w.on('closed', () => promptRefs.delete(senderID));
  }
  w.setMenu(null);
  w.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  w.webContents.on('will-navigate', (e) => e.preventDefault());
  w.webContents.on('will-attach-webview', (e) => e.preventDefault());
  w.on('closed', () => {
    windows.delete(w);
    if (isPrompt && prompt === w) {
      prompt = undefined;
      setImmediate(automaticDecision);
    }
  });
  w.once('ready-to-show', () => {
    if (isPrompt) {
      const area = screen.getPrimaryDisplay().workArea;
      w.setBounds(edgePosition(area, 520, 460));
    }
    w.show();
    if (isPrompt) {
      w.focus();
      setTimeout(() => {
        if (!w.isDestroyed())
          void placeKDEPrompt(
            profile,
            process.pid,
            w.id,
            edgePosition(screen.getPrimaryDisplay().workArea, 520, 460),
            () => !w.isDestroyed() && prompt === w,
          ).catch((error) => console.info('FlowGate: prompt placement unavailable', String(error)));
      }, 100);
    }
  });
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
    const mime = bundledAsset(name);
    if (u.host !== 'app' || !mime) return new Response('Not found', { status: 404 });
    return new Response(fs.readFileSync(path.join(__dirname, name)), {
      headers: {
        'Content-Type': mime,
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
    trusted(e, true);
    return history.view(value);
  });
  backend = new Backend(observer!, controller, (state) => {
    history.observe(state.observation);
    paneModel.observe(state);
    publishPanes();
    icons.observe(state);
    for (const w of windows)
      if (!w.isDestroyed() && !paneRoles.has(w.webContents.id) && w.isVisible() && !w.isMinimized())
        w.webContents.send('state', state);
    automaticDecision();
    background?.update(state);
  });
  ipcMain.handle('application:metadata', (e, value) => {
    trusted(e, true);
    return icons.metadata(value);
  });
  ipcMain.handle('application:icons', (e, value) => {
    trusted(e, true);
    return icons.request(value);
  });
  ipcMain.handle('pane:snapshot', (e) => {
    trusted(e, true);
    return paneFrame();
  });
  ipcMain.handle('pane:update', (e, v) => {
    presentationSender(e);
    paneModel.update(v, e.sender === main.webContents, backend.view());
    if (v.unit !== undefined) {
      saved.ui = { ...saved.ui, displayUnit: paneModel.value.unit };
      persist();
    }
    publishPanes();
  });
  ipcMain.handle('pane:control', (e, raw, action) => {
    presentationSender(e);
    const kind = paneKind(raw);
    const role = paneRoles.get(e.sender.id);
    if (role && role !== kind) throw Error('Pane cannot control another window');
    if (!['undock', 'dock', 'close', 'open'].includes(action))
      throw Error('Unknown pane operation');
    if (action === 'open' && paneModel.value.panes[kind] === 'detached') {
      paneWindow(kind);
      publishPanes();
      return;
    }
    if (action === 'open') action = 'dock';
    if (action === 'undock') {
      paneModel.mode(kind, 'detached');
      paneWindow(kind);
    } else {
      paneModel.mode(kind, action === 'dock' ? 'docked' : 'hidden');
      detached.get(kind)?.close();
    }
    publishPanes();
  });
  ipcMain.handle('pane:rule', (e, raw) => {
    trusted(e, true);
    if (paneRoles.get(e.sender.id) !== 'info')
      throw Error('Rule entry is only available from Info View');
    const action = ruleAction(raw),
      p = paneModel.value;
    if (
      action.selection !== p.selection ||
      action.generation !== p.generation ||
      !backend.view().observation.connected
    )
      throw Error('Selection changed or disconnected; reselect and review in Activity');
    showMain();
    main.webContents.send('pane:rule-open', action);
  });
  ipcMain.handle('rule:context', async (e) => {
    trusted(e, true);
    return backend.refreshRuleContext();
  });
  const rules = new Rules(backend);
  // Detached Info can use only drafts/receipts issued to its frozen selection.
  // Rules remains the single main-process mutation/preview service.
  const paneDrafts = new Map<string, { owner: number; selection: string; generation: string }>();
  const paneReceipts = new Map<string, { owner: number; selection: string; generation: string }>();
  const paneReconciles = new Map<
    string,
    { owner: number; selection: string; generation: string }
  >();
  ipcMain.handle('pane:rule-operation', async (e, op, value, context) => {
    trusted(e, true);
    if (paneRoles.get(e.sender.id) !== 'info')
      throw Error('Only Info View can request a quick action');
    const p = paneModel.value,
      state = backend.view();
    if (
      !context ||
      context.selection !== p.selection ||
      context.generation !== p.generation ||
      !state.control.connected ||
      !state.observation.connected
    )
      throw Error('Selection changed or disconnected; review the target again');
    const binding = { owner: e.sender.id, selection: p.selection, generation: p.generation };
    const owned = (map: typeof paneDrafts, token: unknown) => {
      const held = typeof token === 'string' ? map.get(token) : undefined;
      if (!held || JSON.stringify(held) !== JSON.stringify(binding))
        throw Error('Fresh selection-bound preview required');
    };
    if (op === 'draft') {
      const row = p.row;
      if (!row || !value || typeof value !== 'object') throw Error('Unsupported target');
      if (value.zone) {
        if (
          row.kind !== 'network' ||
          value.zone.zone !== (row.id === 'network:local' ? 'local' : 'internet') ||
          value.zone.generation !== p.generation
        )
          throw Error('Zone target differs from selection');
      } else if (value.observed) {
        const o = value.observed;
        if (
          o.generation !== p.generation ||
          !row.rows.some(
            (r) => r.id === o.row_id && r.owners.length === 1 && r.owners[0] === o.process_id,
          )
        )
          throw Error('Observed target is not the selected identity');
      } else {
        const rule = state.control.rules?.find((r) => r.id === value.id);
        const app = row.process?.application;
        if (rule?.filter.all_programs && row.kind === 'network') {
          if (rule.filter.network_zone !== (row.id === 'network:local' ? 'local' : 'internet'))
            throw Error('Zone rule differs from selection');
        } else if (
          !rule ||
          !app ||
          rule.filter.application !== app.key ||
          rule.filter.revision !== app.revision ||
          rule.filter.uid !== row.process?.uid ||
          (rule.filter.process &&
            !sameProcessTarget(
              rule.filter.process,
              state.control.policy?.processes?.find((p) => p.process_id === row.process?.id)
                ?.target,
            ))
        )
          throw Error('Rule does not belong to selected target');
      }
      const draft = await rules.draft(value);
      if (paneDrafts.size >= 32) paneDrafts.delete(paneDrafts.keys().next().value!);
      paneDrafts.set(draft.token, binding);
      return draft;
    }
    if (op === 'preview') {
      owned(paneDrafts, value?.token);
      const preview = await rules.preview(value);
      if (paneReceipts.size >= 32) paneReceipts.delete(paneReceipts.keys().next().value!);
      paneReceipts.set(preview.receipt, binding);
      return preview;
    }
    if (op === 'save') {
      owned(paneReceipts, value);
      paneReceipts.delete(value);
      const result = await rules.save(value);
      if (result.reconcile) {
        if (paneReconciles.size >= 32) paneReconciles.delete(paneReconciles.keys().next().value!);
        paneReconciles.set(result.reconcile, binding);
      }
      return result;
    }
    if (op === 'reconcile') {
      owned(paneReconciles, value);
      return rules.reconcile(value);
    }
    throw Error('Unsupported pane rule operation');
  });
  const decisionLog = new DecisionLogClient(backend);
  for (const [channel, handler] of Object.entries({
    'log:state': () => decisionLog.state(),
    'log:visible': (v: unknown) => decisionLog.setVisible(v),
    'log:filter': (v: unknown) => decisionLog.setFilter(v),
    'log:older': () => decisionLog.older(),
    'log:live': (v: unknown) => decisionLog.setLive(v),
    'log:detail': (v: unknown) => decisionLog.detail(v),
    'log:copy': (v: unknown) => clipboard.writeText(decisionLog.copyText(v)),
  }))
    ipcMain.handle(channel, (e, v) => {
      trusted(e);
      return handler(v);
    });
  const extended = new ExtendedMonitoring(path.resolve(__dirname, '../..'), backend);
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
    return evaluation.view();
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
        Object.keys(v).some((k) => !['sidebar', 'columns', 'keepInTray', 'displayUnit'].includes(k))
      )
        throw Error('Invalid preferences');
      if (
        v.sidebar !== undefined &&
        (!Number.isInteger(v.sidebar) || v.sidebar < 240 || v.sidebar > 600)
      )
        throw Error('Invalid sidebar');
      if (v.keepInTray !== undefined && typeof v.keepInTray !== 'boolean')
        throw Error('Invalid tray preference');
      if (v.displayUnit !== undefined && !isDisplayUnit(v.displayUnit))
        throw Error('Invalid display unit');
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
        ...(v.sidebar !== undefined ? { sidebar: v.sidebar } : {}),
        ...(v.columns !== undefined ? { columns } : {}),
        ...(v.displayUnit !== undefined ? { displayUnit: v.displayUnit } : {}),
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
  ipcMain.handle('decision:preview', (e, value) => {
    trusted(e);
    return backend.previewDecision(boundDecision(value, promptRefs.get(e.sender.id)));
  });
  ipcMain.handle('decision:reconcile', (e, value) => {
    trusted(e);
    if (
      !value ||
      typeof value !== 'object' ||
      Object.keys(value).sort().join(',') !== 'generation,id,preview_token' ||
      ['generation', 'id', 'preview_token'].some(
        (k) => typeof value[k] !== 'string' || !value[k] || value[k].length > 256,
      )
    )
      throw Error('Invalid decision receipt');
    const ref = promptRefs.get(e.sender.id);
    if (ref && (ref.generation !== value.generation || ref.id !== value.id))
      throw Error('Receipt belongs to another request');
    return backend.reconcileDecision(value);
  });
  ipcMain.handle('decide', (e, value) => {
    trusted(e);
    return backend.decide(boundDecision(value, promptRefs.get(e.sender.id)));
  });
  ipcMain.handle('prompt:open', (e, id) => {
    trusted(e);
    if (e.sender !== main.webContents) throw Error('Open permissions from Activity');
    if (
      typeof id !== 'string' ||
      id.length > 256 ||
      !backend.view().control.events.some((v) => v.id === id)
    )
      throw Error('Unknown request');
    openDecision({ id, generation: backend.view().control.generation });
  });
  ipcMain.handle('prompt:dismiss', (e) => {
    trusted(e);
    if (prompt && !prompt.isDestroyed() && prompt.webContents === e.sender) prompt.close();
  });
  main = windowFor();
  main.on('hide', () => {
    for (const w of detached.values()) if (!w.isDestroyed()) w.hide();
  });
  main.on('show', () => {
    for (const [kind, w] of detached)
      if (paneModel.value.panes[kind] === 'detached' && !w.isDestroyed()) w.show();
    publishPanes();
  });
  main.webContents.on('did-finish-load', () =>
    console.info(
      'FlowGate: main window rendered; sandbox enabled; native platform',
      app.commandLine.getSwitchValue('ozone-platform') || 'default',
    ),
  );
  main.webContents.on('render-process-gone', (_event, details) =>
    console.error('FlowGate: renderer exited', JSON.stringify(details)),
  );
  app.on('child-process-gone', (_event, details) =>
    console.error('FlowGate: child process exited', JSON.stringify(details)),
  );
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
