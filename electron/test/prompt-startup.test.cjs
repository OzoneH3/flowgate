const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const { transformSync } = require('esbuild');
const { compactPromptBounds, PROMPT_MIN_HEIGHT } = require('../dist/test/automatic-prompts.cjs');

test('an early request waits for native startup cleanup without ready-to-show', async () => {
  // Run the actual main-process creation and retarget functions while holding
  // the compositor startup operation open. There is no renderer paint event.
  const source = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  const functions = [
    source.slice(source.indexOf('function retarget('), source.indexOf('// Temporary Allow/Deny')),
    source.slice(source.indexOf('function windowFor('), source.indexOf('app.whenReady()')),
  ].join('\n');
  const { code } = transformSync(functions, { loader: 'ts' });
  const calls = [];
  const bounds = { x: 535, y: 151, width: 745, height: 590 };
  const ref = { id: 'early', generation: 'session', group: 'g:early' };
  let finishStartup;
  const startup = new Promise((resolve) => {
    finishStartup = resolve;
  });
  class Window extends EventEmitter {
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
    console,
    path,
    __dirname,
    process: { pid: 42 },
    PROMPT_TITLE: 'Permission',
    APP_ICON: '',
    PROMPT_MIN_HEIGHT,
    compactPromptBounds,
    nativeWayland: true,
    prompt: undefined,
    promptIdle: true,
    promptKDEReady: false,
    promptDismissed: false,
    promptRemember: false,
    TRANSITION_MS: 650,
    profile: 'fixture-profile',
    windows: new Set(),
    promptRefs: new Map(),
    promptReadyAt: new Map(),
    promptLayouts: new Map(),
    promptPlacement: new Map(),
    promptContentHeights: new Map(),
    promptTitle: (id) => 'Permission ' + id,
    promptURL: ({ id, generation }) =>
      `flowgate://app/prompt.html?request=${id}&generation=${generation}`,
    screen: {
      getPrimaryDisplay: () => ({ workArea: bounds }),
      getDisplayMatching: () => ({ workArea: bounds }),
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
    resizeKDEPrompt: async (_profile, pid, id) => {
      calls.push(['reveal', pid, id]);
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
  finishStartup();
  await context.promptLayouts.get(context.prompt.webContents.id);
  assert.deepEqual(calls.slice(-2), [['cleanup'], ['reveal', 42, 2]]);
  assert.equal(context.promptRefs.get(7), ref);
});
