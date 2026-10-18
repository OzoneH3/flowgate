const { test } = require('node:test');
const assert = require('node:assert/strict');
const { advanceClock } = require('../dist/test/state-clock.cjs');
test('clock changes deadline presentation, never inventory/authority or daemon generation', () => {
  const s = {
    observation: { connected: true },
    control: {
      generation: 'new',
      connected: true,
      serverNow: 100,
      rules: [{ id: 'saved' }],
      events: [{ id: 'pending', deadline: new Date(200).toISOString(), remainingMs: 100 }],
      policy: { snapshot: { valid_until: new Date(180).toISOString() } },
    },
  };
  assert.equal(advanceClock(s, { generation: 'old', serverNow: 300 }), s);
  assert.equal(advanceClock(s, { generation: 'new', serverNow: 99 }), s);
  assert.equal(advanceClock(s, { generation: 'new', serverNow: NaN }), s);
  const next = advanceClock(s, { generation: 'new', serverNow: 210 });
  assert.equal(next.control.events[0].remainingMs, 0);
  assert.equal(next.control.policy, undefined);
  assert.equal(next.control.rules, s.control.rules);
  assert.equal(next.control.connected, true);
  assert.equal(next.control.generation, 'new');
  assert.equal(s.control.events[0].remainingMs, 100);
});
