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
  assert.equal(workspace.activeWindow, windows[0]);
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
