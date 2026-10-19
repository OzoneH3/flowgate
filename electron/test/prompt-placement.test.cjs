const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { placementScript, PROMPT_TITLE, promptTitle } = require('../dist/test/prompt-placement.cjs');
test('KDE placement only touches own PID and fixed permission caption', () => {
  const desired = { x: 2040, y: 980, width: 520, height: 460 };
  const windows = [
    { pid: 42, caption: promptTitle(7) },
    { pid: 43, caption: promptTitle(7) },
    { pid: 42, caption: promptTitle(8) },
    { pid: 42, caption: 'FlowGate' },
    { pid: 42, caption: 'Firefox' },
  ];
  const workspace = { windowList: () => windows };
  vm.runInNewContext(placementScript(42, 7, desired), {
    workspace,
    print: () => {},
  });
  assert.deepEqual({ ...windows[0].frameGeometry }, desired);
  assert.equal(workspace.activeWindow, undefined);
  for (const w of windows.slice(1)) assert.equal(w.frameGeometry, undefined);
  assert.throws(() => placementScript(-1, 7, desired));
  assert.throws(() => placementScript(42, 7, { ...desired, x: NaN }));
});
test('KDE configured priority overrides Electron output order and uses that output workarea', () => {
  const { primaryOutputName } = require('../dist/test/prompt-placement.cjs');
  assert.equal(
    primaryOutputName({
      outputs: [
        { name: 'DP-3', priority: 2, connected: true },
        { name: 'DP-2', priority: 1, connected: true },
      ],
    }),
    'DP-2',
  );
  assert.equal(
    primaryOutputName({
      outputs: [
        { name: 'disabled', priority: 0, connected: true },
        { name: 'missing', priority: 1, connected: false },
      ],
    }),
    undefined,
  );
  const w = { pid: 42, caption: promptTitle(7) },
    output = { name: 'DP-2' };
  const workspace = {
    windowList: () => [w],
    screens: [{ name: 'DP-3' }, output],
    sendClientToScreen: (window, o) => assert.equal(o, output),
    currentDesktopForScreen: () => 1,
    clientArea: () => ({ x: 2560, y: 0, width: 2560, height: 1392 }),
  };
  vm.runInNewContext(placementScript(42, 7, { x: 2040, y: 980, width: 520, height: 460 }, 'DP-2'), {
    workspace,
    KWin: { PlacementArea: 0 },
    print: () => {},
  });
  assert.deepEqual({ ...w.frameGeometry }, { x: 4600, y: 932, width: 520, height: 460 });
});

test('startup handshake waits for native configure and reveals without activation', () => {
  const { placementQML } = require('../dist/test/prompt-placement.cjs');
  const qml = placementQML(42, 7, { x: 0, y: 0, width: 520, height: 460 }, 'primary');
  const body = qml.slice(
    qml.indexOf('  function tick() {') + '  function tick() {'.length,
    qml.lastIndexOf('\n  }'),
  );
  const output = { name: 'primary' },
    other = { name: 'secondary' };
  let requested,
    focused = 0,
    stopped = 0;
  const w = {
    pid: 42,
    caption: promptTitle(7),
    internalId: 'native-A',
    output: other,
    opacity: 0,
    setMaximize() {},
    get frameGeometry() {
      return this.actual;
    },
    set frameGeometry(v) {
      requested = v;
    },
    actual: { x: 0, y: 0, width: 1280, height: 848 },
  };
  const state = {
    ticks: 0,
    nativeID: null,
    previous: '',
    stable: 0,
    applied: 0,
    waited: 0,
    confirmed: 0,
  };
  const workspace = {
    stackingOrder: [w, { ...w, pid: 43 }],
    screens: [other, output],
    sendClientToScreen(win, o) {
      win.output = o;
    },
    currentDesktopForScreen() {
      return 1;
    },
    clientArea() {
      return { x: 2000, y: 30, width: 900, height: 570 };
    },
    set activeWindow(v) {
      assert.equal(v, w);
      focused++;
    },
  };
  const context = vm.createContext({
    state,
    target: w,
    workspace,
    clock: {
      stop() {
        stopped++;
      },
    },
    KWin: { PlacementArea: 0 },
    console: { log() {} },
  });
  const tick = () => vm.runInContext(`(function(){${body}})()`, context);
  for (let i = 0; i < 5; i++) tick();
  assert.equal(w.opacity, 0);
  assert.equal(focused, 0);
  assert(requested);
  // Requested setBounds is NOT proof; native actual frame remains the restored main size.
  assert.equal(state.confirmed, 0);
  w.actual = { ...requested };
  for (let i = 0; i < 3; i++) tick();
  assert.equal(w.opacity, 1);
  assert.equal(w.keepAbove, true);
  assert.equal(focused, 0);
  assert.equal(stopped, 1);
  assert.deepEqual({ ...w.actual }, { x: 2380, y: 140, width: 520, height: 460 });
  assert.match(qml, /windowAdded.connect/);
  assert.match(qml, /windowAdded.disconnect/);
});
test('handshake rejects native-window replacement', () => {
  const { placementQML } = require('../dist/test/prompt-placement.cjs');
  const qml = placementQML(42, 7, { x: 0, y: 0, width: 520, height: 460 }, 'primary');
  const body = qml.slice(
    qml.indexOf('  function tick() {') + '  function tick() {'.length,
    qml.lastIndexOf('\n  }'),
  );
  const output = { name: 'primary' },
    w = { pid: 42, caption: promptTitle(7), internalId: 'new-native', output };
  let stopped = false;
  const context = vm.createContext({
    state: { ticks: 0, nativeID: 'old-native' },
    workspace: { stackingOrder: [w] },
    clock: {
      stop() {
        stopped = true;
      },
    },
  });
  vm.runInContext(`(function(){${body}})()`, context);
  assert.equal(stopped, true);
  assert.equal(w.opacity, undefined);
});
