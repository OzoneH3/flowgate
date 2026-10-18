const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { acceptsPublication } = require('../dist/test/publication.cjs');
const { advanceClock } = require('../dist/test/state-clock.cjs');
test('late invoke cannot erase a rule from newer push or revert restarted daemon', () => {
  const old = { publication: 2, control: { generation: 'old', rules: [] } },
    saved = { publication: 3, control: { generation: 'old', rules: [{ id: 'saved' }] } },
    restarted = { publication: 4, control: { generation: 'new', rules: [] } };
  assert(!acceptsPublication(saved, old));
  assert(acceptsPublication(saved, restarted));
  assert(!acceptsPublication(restarted, saved));
  assert(acceptsPublication(undefined, old));
  assert(acceptsPublication(saved, { ...saved }));
});
test('clock sequence cannot let an old snapshot restore expired decision', () => {
  const s = {
    publication: 4,
    control: {
      generation: 'g',
      serverNow: 100,
      events: [{ id: 'e', deadline: new Date(200).toISOString(), remainingMs: 100 }],
    },
  };
  const advanced = advanceClock(s, { generation: 'g', serverNow: 210, publication: 5 });
  assert.equal(advanced.publication, 5);
  assert.equal(advanced.control.events[0].remainingMs, 0);
  assert(!acceptsPublication(advanced, s));
  assert.equal(
    advanceClock(advanced, { generation: 'g', serverNow: 220, publication: 4 }),
    advanced,
  );
});
test('late popup refresh cannot replace newer selection or rule context', () => {
  const { ActivityPolicy } = require('../dist/test/activity-policy.cjs');
  const p = Object.create(ActivityPolicy.prototype),
    current = { publication: 8, control: { generation: 'g', rules: [{ id: 'new' }] } };
  p.state = current;
  p.row = { id: 'current' };
  p.update({ id: 'stale' }, { publication: 7, control: { generation: 'g', rules: [] } });
  assert.equal(p.state, current);
  assert.equal(p.row.id, 'current');
});
