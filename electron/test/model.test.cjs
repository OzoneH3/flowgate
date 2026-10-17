const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hierarchy, sum, flatten } = require('../dist/test/model.cjs');
function row(id, owners = [], traffic = {}) {
  return {
    id,
    owners,
    state: 'Established',
    socket: { protocol: 'tcp', state: 1, local: '[::1]:80', remote: '[::1]:90' },
    traffic: { available: true, definition: 'tcp', uploaded: 10, upload_bps: 2, ...traffic },
  };
}
test('shared/unknown counted once and incompatible sources never summed', () => {
  const a = {
    rows: [row('one', ['a', 'b']), row('one', ['a', 'b']), row('two', [], { definition: 'udp' })],
    processes: {},
  };
  const roots = hierarchy(a);
  assert.equal(roots.length, 1);
  assert.equal(roots[0].id, 'unidentified');
  assert.equal(roots[0].rows.length, 2);
  assert.equal(sum(roots[0].rows, 'uploaded').mixed, true);
  assert.equal(sum(roots[0].rows, 'uploaded').value, undefined);
});
test('numeric sort, partial and unavailable counters', () => {
  const roots = hierarchy({
    rows: [
      row('slow', [], { uploaded: 2 }),
      row('fast', [], { uploaded: 100 }),
      row('none', [], { available: false }),
    ],
    processes: {},
  });
  assert.deepEqual(
    flatten(roots, new Set(['unidentified']), 'uploaded', true)
      .slice(1)
      .map((v) => v.row.id),
    ['fast', 'slow', 'none'],
  );
  assert.equal(sum(roots[0].rows, 'uploaded').partial, true);
});
test('reassociation preserves backend socket ID; groups use executable identity', () => {
  const r = row('stable', []);
  const a = {
    rows: [r],
    processes: {
      p: {
        id: 'p',
        pid: 7,
        executable: '/a',
        application: { key: 'a', revision: 'r', name: 'same' },
      },
    },
  };
  assert.equal(hierarchy(a)[0].children[0].id, 'stable');
  r.owners = ['p'];
  assert.equal(hierarchy(a)[0].children[0].children[0].id, 'stable');
});
