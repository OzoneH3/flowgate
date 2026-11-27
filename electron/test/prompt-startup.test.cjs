const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const { transformSync } = require('esbuild');
const { compactPromptBounds, edgePosition, PROMPT_HEIGHT, PROMPT_MIN_HEIGHT } = require('../dist/test/automatic-prompts.cjs');

test('an early request waits for native startup cleanup without ready-to-show', async () => {
  // Run the actual main-process creation and retarget functions while holding
  // the compositor startup operation open. There is no renderer paint event.
  const source = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  const functions = [
    source.slice(source.indexOf('function retarget('), source.indexOf('// Temporary Allow/Deny')),
    source.slice(source.indexOf('function windowFor('), source.indexOf('app.whenReady()')),
    source.slice(source.indexOf("ipcMain.handle('prompt:layout'"), source.indexOf("ipcMain.handle('prompt:dismiss'")),
  ].join('\n');
  const { code } = transformSync(functions, { loader: 'ts' });
  const calls = [];
  const bounds = { x: 535, y: 151, width: 745, height: 590 };
  const ref = { id: 'early', generation: 'session', group: 'g:early' };
  let finishStartup;
  let releaseResize;
  let holdResize = false;
  const startup = new Promise((resolve) => {
    finishStartup = resolve;
  });
  class Window extends EventEmitter {
    constructor(options) {
      super();
      assert.equal(options.webPreferences.focusOnNavigation, false);
      assert.equal(options.webPreferences.backgroundThrottling, false);
    }
    static fromWebContents(sender) { return context.prompt.webContents === sender && context.prompt; }
    id = 2;
    webContents = Object.assign(new EventEmitter(), {
      id: 7,
      setWindowOpenHandler() {},
      send() {},
    });
    setTitle() {}
    setMenu() {}
    setBounds() { calls.push(['electron-set-bounds']); }
    getBounds() {
      return bounds;
    }
    isDestroyed() {
      return false;
    }
    loadURL(url) {
      calls.push(['load', url]);
    }
    minimize() {
      calls.push(['map-minimized']);
    }
    showInactive() {
      calls.push(['show-inactive']);
    }
  }
  const context = vm.createContext({
    BrowserWindow: Window,
    ipcMain: { handle: (_name, handler) => { context.layout = handler; } },
    trusted() {},
    URL,
    console,
    path,
    __dirname,
    process: { pid: 42 },
    PROMPT_TITLE: 'Permission',
    APP_ICON: '',
    PROMPT_MIN_HEIGHT,
    PROMPT_HEIGHT,
    compactPromptBounds,
    edgePosition,
    nativeWayland: true,
    prompt: undefined,
    promptIdle: true,
    promptKDEReady: false,
    promptDismissed: false,
    promptRemember: false,
    promptPointerDown: false,
    rendererPromptKeys: new Set(),
    transitionUntil: 0,
    TRANSITION_MS: 650,
    profile: 'fixture-profile',
    windows: new Set(),
    promptRefs: new Map(),
    measuredPrompts: new WeakSet(),
    promptOutputRefresh: new WeakSet(),
    promptLayouts: new Map(),
    promptPlacement: new Map(),
    promptContentHeights: new Map(),
    promptTitle: (id) => 'Permission ' + id,
    promptURL: ({ id, generation }) =>
      `flowgate://app/prompt.html?request=${id}&generation=${generation}`,
    screen: {
      getPrimaryDisplay: () => ({ workArea: bounds }),
      getDisplayMatching: () => ({ workArea: { ...bounds, height: 1000 } }),
    },
    backend: {
      view: () => ({
        control: {
          generation: ref.generation,
          events: [{ ...ref, state: 'awaiting-decision', remainingMs: 10000 }],
        },
      }),
    },
    placeKDEPrompt: async (_profile, pid, id, _bounds, live, prepared, reveal) => {
      assert.equal(pid, 42);
      assert.equal(id, 2);
      assert(live());
      assert.equal(reveal, false);
      calls.push(['prepare']);
      prepared(true);
      await startup;
      calls.push(['cleanup']);
    },
    resizeKDEPrompt: async (_profile, pid, id, requested, visible, retainOutput) => {
      assert.equal(visible, true);
      calls.push(['reveal', pid, id, requested.height, retainOutput]);
      if (holdResize) await new Promise(resolve => { releaseResize = resolve; });
    },
    ref,
  });
  vm.runInContext(code, context);
  vm.runInContext(
    `
    prompt = windowFor(true, '__idle__', '__idle__');
    promptIdle = false;
    retarget(ref, true);
  `,
    context,
  );
  await new Promise(setImmediate);
  assert.deepEqual(calls, [
    ['load', 'flowgate://app/prompt.html?request=__idle__&generation=__idle__'],
    ['load', 'flowgate://app/prompt.html?request=early&generation=session'],
    ['prepare'],
    ['map-minimized'],
  ]);
  const report = (id, height) => context.layout({
    sender: context.prompt.webContents,
    senderFrame: { url: 'flowgate://app/prompt.html?request=' + id + '&generation=session' },
  }, { height, pointerDown: false, keysDown: [], remember: false });
  const layout = report('early', 730);
  assert.equal(context.measuredPrompts.has(ref), false, 'Native layout is still pending');
  finishStartup();
  assert.equal(await layout, true);
  assert.equal(context.measuredPrompts.has(ref), true, 'Can decide as soon as native layout is acknowledged');
  assert.deepEqual(calls.slice(-2), [['cleanup'], ['reveal', 42, 2, 730, false]]);

  holdResize = true;
  const oldLayout = report('early', 740);
  await new Promise(setImmediate);
  assert.deepEqual(calls.at(-1), ['reveal', 42, 2, 740, true]);
  const next = { ...ref, id: 'next' };
  context.retarget(next);
  assert.equal(context.measuredPrompts.has(next), false);
  releaseResize();
  assert.equal(await oldLayout, false, 'An earlier native completion cannot acknowledge a replacement card');
  assert.equal(await report('early', 740), false, 'Layout from a superseded renderer is refused');
  assert.equal(context.measuredPrompts.has(next), false);

  holdResize = false;
  assert.equal(await report('next', 740), true);
  assert.equal(context.measuredPrompts.has(next), true);
  assert.deepEqual(calls.at(-1), ['reveal', 42, 2, 740, true]);

  const reopened = { ...ref, id: 'reopened' };
  context.retarget(reopened, true);
  assert.equal(await report('reopened', 740), true);
  assert.deepEqual(calls.at(-1), ['reveal', 42, 2, 740, false]);
});

test('a live permission card keeps receiving state and clock while Electron reports it minimized', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  const { code } = transformSync(source.slice(
    source.indexOf('function receivesBackendUpdates('),
    source.indexOf('let backend: Backend;'),
  ), { loader: 'ts' });
  const popup = {
    isDestroyed: () => false,
    webContents: { id: 1 },
    isVisible: () => false,
    isMinimized: () => true,
  };
  const main = { ...popup, webContents: { id: 2 } };
  const context = vm.createContext({ prompt: popup, promptIdle: false, paneRoles: new Map(), main });
  vm.runInContext(code, context);
  assert.equal(vm.runInContext('receivesBackendUpdates(prompt)', context), true);
  assert.equal(vm.runInContext('receivesBackendUpdates(main)', context), false);
  context.promptIdle = true;
  assert.equal(vm.runInContext('receivesBackendUpdates(prompt)', context), false);
  context.promptIdle = false;
  popup.isDestroyed = () => true;
  assert.equal(vm.runInContext('receivesBackendUpdates(prompt)', context), false);
});
