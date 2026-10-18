const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AutomaticPrompts, edgePosition } = require('../dist/test/automatic-prompts.cjs');
const state = (ids, generation = 'g') => ({
  control: {
    connected: true,
    readOnly: false,
    generation,
    permissions: { can_decide: true },
    events: ids.map((id) => ({ id, state: 'awaiting-decision', remainingMs: 1000 })),
  },
});
test('automatic foreground queue pins target, dismissal does not reopen or mutate', () => {
  const q = new AutomaticPrompts();
  assert.equal(q.next(state(['a', 'b']), false).id, 'a');
  assert.equal(q.next(state(['a', 'b']), true), undefined);
  assert.equal(q.next(state(['a', 'b']), false).id, 'b');
  assert.equal(q.next(state(['a', 'b']), false), undefined);
  assert.equal(q.next(state(['a'], 'new'), false).id, 'a');
});
test('disconnected/read-only/expired/submitted never auto-open', () => {
  for (const alter of [
    (s) => (s.control.connected = false),
    (s) => (s.control.readOnly = true),
    (s) => (s.control.events[0].remainingMs = 0),
    (s) => (s.control.events[0].attempt = {}),
    (s) => (s.control.permissions.can_decide = false),
  ]) {
    const s = state(['a']);
    alter(s);
    assert.equal(new AutomaticPrompts().next(s, false), undefined);
  }
});
test('bottom-right work area placement handles display offset and small screens', () => {
  assert.deepEqual(edgePosition({ x: 1280, y: 0, width: 860, height: 600 }, 520, 460), {
    x: 1620,
    y: 140,
    width: 520,
    height: 460,
  });
  assert.deepEqual(edgePosition({ x: 0, y: 0, width: 400, height: 300 }, 520, 460), {
    x: 0,
    y: 0,
    width: 400,
    height: 300,
  });
});
