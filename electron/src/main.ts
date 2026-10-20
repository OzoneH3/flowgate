import { matchesApplicationZone } from './application-zones';
import { Essential } from './essential';
import { Protection } from './protection';
import { placeKDEPrompt, resizeKDEPrompt, PROMPT_TITLE, promptTitle } from './prompt-placement';
import { AutomaticPrompts, PROMPT_HEIGHT, PROMPT_WIDTH, edgePosition, boundDecision, groupOf, inputSettled } from './automatic-prompts';
import { leaseHolds } from './process-lease';
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
import { ZoneMigration } from './zone-migration';
import { sameProcessTarget } from './process-rules';
import { DecisionLogClient } from './decision-log-client';
import { Evaluation } from './evaluation';
import type { Preferences } from './protocol';
import { Backend } from './backend';
import { validateDecision } from './protocol';
import { validateRequestRule } from './request-rule';
import { endedLeaseResult, validateEndedLease } from './prompt-decision';
import { attemptResult, failureResult, pairOutcome } from './permission-results';
import { validatePairChoice } from './local-pair';
import { validForAWhileSeconds } from './process-lease';
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
  // Reviewed Essential interface exclusions; validated by Essential on load.
  essential?: { excluded_interfaces?: unknown };
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
// Keep the old native window until release: its input stream must not reach a new card.
const TRANSITION_MS = 650;
let transitionUntil = 0;
let transitionTimer: ReturnType<typeof setTimeout> | undefined;
const pressedPromptKeys = new Set<string>();
const rendererPromptKeys = new Set<string>();
let promptPointerDown = false;
let promptDismissed = false;
let promptIdle = false;
let promptKDEReady = false;
const promptReadyAt = new Map<number, number>();
const promptPlacement = new Map<number, Promise<void>>();
const promptLayouts = new Map<number, Promise<void>>();
const promptContentHeights = new Map<number, number>();
function pacePrompt() {
  transitionUntil = Date.now() + TRANSITION_MS;
  clearTimeout(transitionTimer);
  transitionTimer = setTimeout(automaticDecision, TRANSITION_MS + 10);
}
const promptRefs = new Map<number, RequestRef>();
const promptURL = (ref: RequestRef) =>
  'flowgate://app/index.html?request=' +
  encodeURIComponent(ref.id) +
  '&generation=' +
  encodeURIComponent(ref.generation);
// The one permission window shows one request card. Switching card reuses the
// window: rebinding promptRefs first makes decisions from the old card fail closed.
function retarget(ref: RequestRef, reload = false) {
  const w = prompt!,
    current = promptRefs.get(w.webContents.id);
  if (!reload && current?.id === ref.id && current.generation === ref.generation) {
    promptRefs.set(w.webContents.id, { ...current, group: ref.group ?? current.group });
    return;
  }
  promptRefs.set(w.webContents.id, ref);
  promptContentHeights.delete(w.webContents.id);
  promptReadyAt.set(w.webContents.id, Date.now() + TRANSITION_MS);
  const compact = edgePosition(screen.getPrimaryDisplay().workArea, PROMPT_WIDTH, PROMPT_HEIGHT);
  w.setBounds(compact);
  const reset = (
    promptLayouts.get(w.webContents.id) ||
    promptPlacement.get(w.webContents.id) ||
    Promise.resolve()
  ).then(async () => {
    if (w.isDestroyed() || promptIdle || promptRefs.get(w.webContents.id)?.id !== ref.id) return;
    const current = backend.view().control;
    if (
      current.generation !== ref.generation ||
      !current.events.some(
        (e) => e.id === ref.id && e.state === 'awaiting-decision' && e.remainingMs > TRANSITION_MS,
      )
    )
      return;
    if (promptKDEReady) await resizeKDEPrompt(profile, process.pid, w.id, compact);
    else w.showInactive();
  });
  promptLayouts.set(w.webContents.id, reset);
  void w.loadURL(promptURL(ref));
}
// A valid Allow/Deny click hides the permission window at once (NetLimiter);
// the submission continues asynchronously and its outcome, including refusals
// and uncertain acknowledgements, is kept in Pending requests › Results. The
// next waiting request is presented after the usual input-release pacing.
function promptAnswered(sender: Electron.WebContents) {
  const w = prompt;
  if (!w || w.isDestroyed() || w.webContents !== sender || promptIdle) return;
  promptIdle = true;
  // The click that answered is the release: a hidden window's pointer-up/key-up
  // report arrives a frame later or never, and must not hold the input-release
  // guard forever (no further popup would ever appear). The next card is still
  // paced and ignores input until its own layout settles.
  promptPointerDown = false;
  pressedPromptKeys.clear();
  rendererPromptKeys.clear();
  if (promptKDEReady) void resizeKDEPrompt(profile, process.pid, w.id, w.getBounds(), false);
  else w.hide();
  pacePrompt();
}
function trackResult<T>(
  generation: string,
  id: string,
  run: Promise<T>,
  ok: (value: T) => Parameters<Backend['noteResult']>[2],
): Promise<T> {
  run.then(
    (value) => backend.noteResult(generation, id, ok(value)),
    (error) => backend.noteResult(generation, id, failureResult(error)),
  );
  return run;
}
// Closed by FlowGate because its request group is settled: not a user dismissal.
let promptAutoClosing = false;
function openDecision(ref: RequestRef) {
  // A hidden window (answered or dismissed) always presents a fresh card.
  const hidden = promptIdle;
  promptIdle = false;
  promptDismissed = false;
  ref = { ...ref, group: ref.group ?? groupOf(backend.view(), ref.id) };
  if (prompt && !prompt.isDestroyed()) {
    retarget(ref, hidden);
    return;
  }
  prompt = windowFor(true, ref.id, ref.generation, ref.group);
}
const promptInputSettled = () =>
  inputSettled({
    now: Date.now(),
    transitionUntil,
    keys: pressedPromptKeys.size,
    rendererKeys: rendererPromptKeys.size,
    pointerDown: promptPointerDown,
  });
function automaticDecision() {
  if (quitting || !backend || !main) return;
  const view = backend.view();
  if (prompt && !prompt.isDestroyed() && !promptIdle) {
    const ref = promptRefs.get(prompt.webContents.id);
    let next = ref && automaticPrompts.follow(view, ref);
    // A request just decided "For a while" keeps its card while its lease is
    // active, so the lease stays inspectable; any other waiting request wins.
    if (!promptDismissed && !next && ref && leaseHolds(view.control, ref.id))
      next = automaticPrompts.next(view, false) ?? ref;
    if (!promptDismissed && next?.id === ref?.id) {
      // The same card stays (for example a request that just ended and is now
      // retained): cancel a transition paced while it was briefly unfollowed,
      // otherwise its actions stay refused as "transitioning" indefinitely.
      if (transitionUntil) {
        transitionUntil = 0;
        clearTimeout(transitionTimer);
      }
      return;
    }
    if (!transitionUntil) pacePrompt();
    if (!promptInputSettled()) return;
    transitionUntil = 0;
    if (promptDismissed || !next) {
      promptIdle = true;
      if (promptKDEReady)
        void resizeKDEPrompt(profile, process.pid, prompt.id, prompt.getBounds(), false);
      else prompt.hide();
      pacePrompt();
    } else if (view.control.events.some((e) => e.id === next.id && e.remainingMs > 1000))
      retarget(next);
    return;
  }
  const next = automaticPrompts.next(view, false);
  if (!promptInputSettled()) return;
  transitionUntil = 0;
  if (next && view.control.events.some((e) => e.id === next.id && e.remainingMs > 1000))
    openDecision(next);
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
let panePublication = '';
function publishPanes() {
  if (!backend || quitting) return;
  const frame = paneFrame(),
    c = frame.state.control;
  const key = JSON.stringify([
    paneModel.value.revision,
    c.snapshotStarted,
    c.policy?.snapshot.sequence,
    c.connected,
    c.generation,
    c.policyError,
  ]);
  if (key === panePublication) return;
  panePublication = key;
  for (const w of windows)
    if (!w.isDestroyed() && w.isVisible() && !w.isMinimized() && !promptRefs.has(w.webContents.id))
      w.webContents.send('pane:frame', frame);
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
  w.on('show', () => {
    panePublication = '';
    publishPanes();
  });
  w.on('restore', () => {
    panePublication = '';
    publishPanes();
  });
  w.once('ready-to-show', () => {
    if (main.isVisible()) w.show();
    panePublication = '';
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
  const view = backend.view(),
    c = view.control;
  // A notified group whose representative settled shows its next representative.
  const next = c.connected
      ? automaticPrompts.follow(view, { ...ref, group: ref.group ?? groupOf(view, ref.id) })
      : undefined,
    e = next && c.events.find((e) => e.id === next.id);
  if (!next || !e || e.state !== 'awaiting-decision' || e.remainingMs <= 0 || e.attempt) {
    showMain(
      true,
      'Request no longer pending or controller unavailable. Review the current list; no decision was sent.',
    );
    return;
  }
  openDecision(next);
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
function windowFor(isPrompt = false, id = '', generation = '', group?: string) {
  const w = new BrowserWindow({
    title: isPrompt ? PROMPT_TITLE : 'FlowGate',
    frame: !isPrompt,
    alwaysOnTop: isPrompt,
    width: isPrompt ? PROMPT_WIDTH : width,
    height: isPrompt ? PROMPT_HEIGHT : height,
    minWidth: isPrompt ? 320 : 800,
    minHeight: isPrompt ? 240 : 550,
    backgroundColor: '#222222',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      focusOnNavigation: !isPrompt,
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
    // Dismiss into the already-mapped native shell. Mapping a new Wayland
    // toplevel later would let KWin activate it before windowAdded fires.
    w.on('close', (event) => {
      if (quitting) return;
      event.preventDefault();
      const ref = promptRefs.get(w.webContents.id);
      if (ref && !promptIdle) automaticPrompts.dismiss(ref);
      promptDismissed = true;
      pacePrompt();
    });
    promptDismissed = false;
    promptReadyAt.set(w.webContents.id, Date.now() + TRANSITION_MS);
    w.webContents.on('before-input-event', (event, input) => {
      if (!['Enter', ' ', 'Escape'].includes(input.key)) return;
      if (input.type === 'keyUp') {
        pressedPromptKeys.delete(input.key);
        if (transitionUntil) pacePrompt();
      } else if (input.type === 'keyDown') {
        if (input.isAutoRepeat || Date.now() < (promptReadyAt.get(w.webContents.id) || 0))
          event.preventDefault();
        pressedPromptKeys.add(input.key);
      }
    });
    w.setTitle(promptTitle(w.id));
    promptRefs.set(w.webContents.id, { id, generation, group });
    w.on('page-title-updated', (event) => event.preventDefault());
    const senderID = w.webContents.id;
    w.on('closed', () => {
      // Closing by the user (× / Escape / Decide later) dismisses the group: it
      // never auto-opens again. Closing because the group settled does not.
      const ref = promptRefs.get(senderID);
      if (ref && prompt === w && !promptAutoClosing) automaticPrompts.dismiss(ref);
      if (prompt === w) promptAutoClosing = false;
      promptRefs.delete(senderID);
      promptReadyAt.delete(senderID);
      promptLayouts.delete(senderID);
      promptContentHeights.delete(senderID);
      promptPlacement.delete(senderID);
      pressedPromptKeys.clear();
      rendererPromptKeys.clear();
      promptPointerDown = false;
      pacePrompt();
    });
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
    if (!isPrompt) {
      w.show();
      return;
    }
    const bounds = edgePosition(screen.getPrimaryDisplay().workArea, PROMPT_WIDTH, PROMPT_HEIGHT);
    w.setBounds(bounds);
    // Install the native windowAdded hook before mapping. Wayland ignores global
    // setBounds; showing first causes a visible wrong-monitor flash.
    const placement = placeKDEPrompt(
      profile,
      process.pid,
      w.id,
      bounds,
      () => !w.isDestroyed() && prompt === w,
      (installed) => {
        if (w.isDestroyed() || prompt !== w) return;
        promptKDEReady = installed;
        if (installed) {
          w.minimize(); // Initial minimized map prevents KWin automatic activation.
        } else if (!promptIdle) {
          w.showInactive();
        }
      },
      id !== '__idle__',
    ).catch((error) => {
      console.info('FlowGate: prompt placement unavailable', String(error));
      if (!w.isDestroyed() && !promptIdle) w.showInactive();
    });
    promptPlacement.set(w.webContents.id, placement);
  });
  const refresh = () => {
    if (backend && !w.isDestroyed()) {
      w.webContents.send('state', backend.view());
      if (!isPrompt) {
        panePublication = '';
        publishPanes();
      }
    }
  };
  w.on('show', refresh);
  w.on('restore', refresh);
  void w.loadURL(isPrompt ? promptURL({ id, generation }) : 'flowgate://app/index.html');
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
  backend = new Backend(observer!, controller, (state, clockOnly) => {
    if (clockOnly) {
      for (const w of windows)
        if (
          !w.isDestroyed() &&
          !paneRoles.has(w.webContents.id) &&
          w.isVisible() &&
          !w.isMinimized()
        )
          w.webContents.send('state:clock', {
            generation: state.control.generation,
            serverNow: state.control.serverNow,
            publication: state.publication,
          });
      automaticDecision();
      background?.update(state);
      return;
    }
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
  const paneZoneDrafts = new Map<string, string>();
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
        if(row.applicationZone && ((o.target_scope && o.target_scope!=='application') || row.applicationZone.model!==state.control.networkZones?.model))throw Error('Application/zone creation scope differs from selection');
        if (
          o.generation !== p.generation ||
          !(row.policyRows || row.rows).some(
            (r) => r.id === o.row_id && r.owners.length === 1 && r.owners[0] === o.process_id,
          )
        )
          throw Error('Observed target is not the selected identity');
      } else {
        const rule = state.control.rules?.find((r) => r.id === value.id);
        const app = row.process?.application;
        if(row.applicationZone && (!rule || rule.filter.process || !matchesApplicationZone(rule.filter,row.applicationZone)))throw Error('Rule belongs to a different application/zone scope');
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
      if(value.observed && row.applicationZone){
        if(paneZoneDrafts.size>=32)paneZoneDrafts.delete(paneZoneDrafts.keys().next().value!);
        paneZoneDrafts.set(draft.token,row.applicationZone.zone);
      }
      return draft;
    }
    if (op === 'preview') {
      owned(paneDrafts, value?.token);
      const requiredZone=paneZoneDrafts.get(value?.token);
      if(requiredZone && value?.network_zone!==requiredZone)throw Error('Preview network zone differs from selected child row');
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
  const essential = new Essential(backend, {
    load: () => saved.essential?.excluded_interfaces,
    save: (excluded_interfaces) => {
      saved.essential = { excluded_interfaces };
      persist();
    },
  });
  ipcMain.handle('essential:state', (e) => {
    trusted(e);
    if (e.sender !== main.webContents) throw Error('Essential networking requires the main window');
    return essential.view();
  });
  ipcMain.handle('essential:action', (e, action, value) => {
    trusted(e);
    if (e.sender !== main.webContents) throw Error('Essential networking requires the main window');
    return essential.action(action, value);
  });
  const zoneMigration = new ZoneMigration(backend);
  for (const [channel, action] of Object.entries({
    'zone-migration:state': () => zoneMigration.view(),
    'zone-migration:preview': (v: unknown) => zoneMigration.preview(v),
    'zone-migration:confirm': (v: unknown) => zoneMigration.confirm(v),
    'zone-migration:reconcile': () => zoneMigration.reconcile(),
  })) ipcMain.handle(channel, (e, value) => {
    trusted(e);
    if (e.sender !== main.webContents) throw Error('Review zone migrations in the main window');
    return action(value);
  });
  const protection = new Protection(backend);
  ipcMain.handle('protection:state', (e) => {
    trusted(e);
    return protection.view();
  });
  ipcMain.handle('protection:action', (e, action, tokens) => {
    trusted(e);
    if (e.sender !== main.webContents) throw Error('Protection control requires the main window');
    return protection.action(action, tokens);
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
        Object.keys(v).some((k) => !['sidebar', 'columns', 'keepInTray', 'displayUnit', 'forAWhileSeconds'].includes(k))
      )
        throw Error('Invalid preferences');
      if (v.forAWhileSeconds !== undefined && !validForAWhileSeconds(v.forAWhileSeconds))
        throw Error('Invalid For a while duration');
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
        ...(v.forAWhileSeconds !== undefined ? { forAWhileSeconds: v.forAWhileSeconds } : {}),
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
    if (
      promptRefs.has(e.sender.id) &&
      (promptIdle ||
        promptDismissed ||
        transitionUntil ||
        Date.now() < (promptReadyAt.get(e.sender.id) || 0))
    )
      throw Error('Permission presentation is transitioning');
    const d = boundDecision(value, promptRefs.get(e.sender.id));
    const run = backend.decide(d);
    promptAnswered(e.sender);
    return trackResult(d.generation, d.id, run, (a) => attemptResult(a, d.action));
  });
  // local-pair-v1: a permission window may decide only the pair of its own request.
  ipcMain.handle('decide-pair', (e, value) => {
    trusted(e);
    const choice = validatePairChoice(value),
      ref = promptRefs.get(e.sender.id);
    if (ref) {
      if (promptIdle || promptDismissed || transitionUntil || Date.now() < (promptReadyAt.get(e.sender.id) || 0))
        throw Error('Permission presentation is transitioning');
      if (ref.generation !== choice.generation || !choice.ids.includes(ref.id))
        throw Error('Pair decision belongs to another permission window');
    }
    const run = backend.decidePair(choice);
    promptAnswered(e.sender);
    return trackResult(choice.generation, ref?.id ?? choice.ids[0], run, (r) => pairOutcome(r.result, choice.action, r.text));
  });
  // Future application rule from a retained, ended request. The prompt window
  // may act only on its own request; saving never decides that request.
  const ownRequestRule = (e: Electron.IpcMainInvokeEvent, value: unknown, save: boolean) => {
    const choice = validateRequestRule(value, save), ref = promptRefs.get(e.sender.id);
    if (e.sender !== main.webContents && !ref) throw Error('Save application rules from a request view');
    if (ref && (ref.generation !== choice.generation || ref.id !== choice.id))
      throw Error('Rule request belongs to another permission window');
    return choice;
  };
  ipcMain.handle('request-rule:preview', (e, value) => {
    trusted(e);
    return backend.previewRequestRule(ownRequestRule(e, value, false));
  });
  ipcMain.handle('request-rule:save', (e, value) => {
    trusted(e);
    if (promptRefs.has(e.sender.id) && (promptIdle || promptDismissed || transitionUntil || Date.now() < (promptReadyAt.get(e.sender.id) || 0)))
      throw Error('Permission presentation is transitioning');
    const choice = ownRequestRule(e, value, true);
    const run = backend.saveRequestRule(choice);
    promptAnswered(e.sender);
    return trackResult(choice.generation, choice.id, run, (r) => ({
      severity: 'ok',
      text: r.replayed ? 'Rule already saved for future connections' : 'Rule saved for future connections',
      detail: r.message,
    }));
  });
  // For a while from an ended request whose process still runs: creates the
  // process lease only; the ended request is never decided or delivered.
  ipcMain.handle('request:for-a-while', (e, value) => {
    trusted(e);
    const choice = validateEndedLease(value), ref = promptRefs.get(e.sender.id);
    if (e.sender !== main.webContents && !ref) throw Error('Use For a while from a request view');
    if (ref && (ref.generation !== choice.generation || ref.id !== choice.id))
      throw Error('Request belongs to another permission window');
    if (ref && (promptIdle || promptDismissed || transitionUntil || Date.now() < (promptReadyAt.get(e.sender.id) || 0)))
      throw Error('Permission presentation is transitioning');
    const run = backend.requestForAWhile(choice);
    promptAnswered(e.sender);
    return trackResult(choice.generation, choice.id, run, (r) => ({ severity: 'ok', text: endedLeaseResult(r.lease), detail: r.message }));
  });
  ipcMain.handle('request:future-application', (e, value) => {
    trusted(e);
    const ref = promptRefs.get(e.sender.id);
    if (e.sender !== main.webContents && !ref) throw Error('Open future rules from a request view');
    if (ref && (ref.generation !== value?.generation || ref.id !== value?.id))
      throw Error('Original request differs from this permission window');
    const source = backend.futureApplicationSource(value);
    // Explicit user navigation, not automatic queue activation or a decision.
    main.webContents.send('request:future-application-open', source);
    if (main.isMinimized()) main.restore();
    main.show();
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
  ipcMain.handle('prompt:layout', async (e, value) => {
    trusted(e);
    const w = BrowserWindow.fromWebContents(e.sender);
    if (!w || w !== prompt || !promptRefs.has(e.sender.id)) throw Error('Not a permission window');
    if (
      !value ||
      !Number.isFinite(value.height) ||
      value.height < 0 ||
      value.height > 100000 ||
      typeof value.pointerDown !== 'boolean' ||
      !Array.isArray(value.keysDown) ||
      value.keysDown.length > 3 ||
      value.keysDown.some((k: unknown) => !['Enter', ' ', 'Escape'].includes(String(k)))
    )
      throw Error('Invalid permission layout');
    // Input release is tracked even while hidden (a release after the answering
    // click must clear the guard); only geometry is ignored when idle.
    if (promptIdle) {
      if (!value.pointerDown) promptPointerDown = false;
      if (value.keysDown.length === 0) rendererPromptKeys.clear();
      if (transitionUntil) pacePrompt();
      return;
    }
    const senderURL = new URL(e.senderFrame!.url),
      currentRef = promptRefs.get(e.sender.id)!;
    if (
      senderURL.searchParams.get('request') !== currentRef.id ||
      senderURL.searchParams.get('generation') !== currentRef.generation
    )
      return;
    const contentChanged = promptContentHeights.get(e.sender.id) !== Math.ceil(value.height);
    promptContentHeights.set(e.sender.id, Math.ceil(value.height));
    const released =
      (promptPointerDown && !value.pointerDown) ||
      (rendererPromptKeys.size > 0 && value.keysDown.length === 0);
    rendererPromptKeys.clear();
    for (const key of value.keysDown) rendererPromptKeys.add(key);
    promptPointerDown = value.pointerDown;
    if (released && transitionUntil) pacePrompt();
    const bounds = edgePosition(
      screen.getPrimaryDisplay().workArea,
      w.getBounds().width,
      Math.max(PROMPT_HEIGHT, Math.ceil(value.height)),
    );
    // Serialize native resizes after the startup handshake; no stale configure
    // may restore compact geometry over a just-expanded Remember panel.
    const ref = promptRefs.get(e.sender.id);
    const prior =
      promptLayouts.get(e.sender.id) || promptPlacement.get(e.sender.id) || Promise.resolve();
    const resize = prior.then(async () => {
      if (w.isDestroyed() || w !== prompt || promptRefs.get(e.sender.id) !== ref) return;
      if (!promptIdle && contentChanged) {
        if (w.getBounds().height !== bounds.height || w.getBounds().width !== bounds.width)
          w.setBounds(bounds);
        await resizeKDEPrompt(profile, process.pid, w.id, bounds);
      }
    });
    promptLayouts.set(e.sender.id, resize);
    await resize;
  });
  ipcMain.handle('prompt:dismiss', (e) => {
    trusted(e);
    if (prompt && !prompt.isDestroyed() && prompt.webContents === e.sender) {
      const ref = promptRefs.get(e.sender.id);
      if (ref) automaticPrompts.dismiss(ref);
      promptDismissed = true;
      pacePrompt();
    }
  });
  main = windowFor();
  // Warm the native shell during application startup; subsequent automatic
  // requests only reveal it and never map or activate another toplevel.
  promptIdle = true;
  prompt = windowFor(true, '__idle__', '__idle__');
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
  main.on('hide', () => {
    for (const w of detached.values()) if (!w.isDestroyed()) w.hide();
  });
  main.on('show', () => {
    for (const w of detached.values()) if (!w.isDestroyed()) w.showInactive();
  });
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
