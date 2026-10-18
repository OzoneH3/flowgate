const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { placementScript, PROMPT_TITLE } = require('../dist/test/prompt-placement.cjs');
test('KDE placement only touches own PID and fixed permission caption', () => {
  const desired = { x: 2040, y: 980, width: 520, height: 460 };
  const windows = [
    { pid: 42, caption: PROMPT_TITLE },
    { pid: 43, caption: PROMPT_TITLE },
    { pid: 42, caption: 'FlowGate' },
    { pid: 42, caption: 'Firefox' },
  ];
  const workspace = { windowList: () => windows };
  vm.runInNewContext(placementScript(42, desired), {
    workspace,
    print: () => {},
  });
  assert.deepEqual({ ...windows[0].frameGeometry }, desired);
  assert.equal(workspace.activeWindow, windows[0]);
  for (const w of windows.slice(1)) assert.equal(w.frameGeometry, undefined);
  assert.throws(() => placementScript(-1, desired));
  assert.throws(() => placementScript(42, { ...desired, x: NaN }));
});
