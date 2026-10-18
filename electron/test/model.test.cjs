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
test('explicit display association groups shared sockets once; unresolved and inode-zero remain Unidentified', () => {
  const application = {
    key: 'native',
    revision: 'r',
    name: 'native app',
    executable: '/long/native/app',
  };
  const processes = {
    a: { id: 'a', pid: 11, uid: 1000, executable: application.executable, application },
    b: {
      id: 'b',
      pid: 12,
      uid: 1000,
      thread_group_pid: 10,
      executable: application.executable,
      application,
    },
  };
  const shared = {
    ...row('shared', ['a', 'b']),
    display_application: application,
    ownership_category: 'shared',
  };
  const unknown = { ...row('unknown'), ownership_category: 'unknown' },
    zero = { ...row('zero'), ownership_category: 'no-userspace-inode' };
  const a = { rows: [shared, unknown, zero, shared], processes };
  const roots = hierarchy(a);
  assert.equal(roots.length, 2);
  assert.equal(roots[0].children[0].id, 'shared');
  assert.equal(roots[0].rows.length, 1);
  assert.equal(sum(roots[0].rows, 'uploaded').value, 10);
  assert.equal(roots[1].id, 'unidentified');
  assert.equal(roots[1].rows.length, 2);
  delete shared.display_application;
  const regrouped = hierarchy(a);
  assert.equal(regrouped.length, 1);
  assert(regrouped[0].children.some((r) => r.id === 'shared'));
  assert.equal(sum(regrouped[0].rows, 'uploaded').value, 30);
  const worker = hierarchy({ rows: [row('worker', ['b'])], processes })[0].children[0];
  assert.match(worker.label, /Worker TID 12 \(process 10\)/);
  const { ownershipExplanation } = require('../dist/test/model.cjs');
  assert.match(ownershipExplanation('no-userspace-inode'), /No userspace inode/);
  assert.match(ownershipExplanation('unknown'), /do not prove/);
});
test('rate sorting uses numbers across units and leaves unavailable last in both directions', () => {
  const roots = hierarchy({
    rows: [
      row('small', [], { upload_bps: 900, download_bps: 900 }),
      row('large', [], { upload_bps: 2048, download_bps: 2048 }),
      row('missing', [], { available: false, upload_bps: undefined, download_bps: undefined }),
    ],
    processes: {},
  });
  for (const key of ['upload_bps', 'download_bps'])
    for (const desc of [true, false])
      assert.deepEqual(
        flatten(roots, new Set(['unidentified']), key, desc)
          .slice(1)
          .map((v) => v.row.id),
        desc ? ['large', 'small', 'missing'] : ['small', 'large', 'missing'],
      );
});

test('overview/source selection deduplicates sockets and preserves missing-source coverage', () => {
  const { overview } = require('../dist/test/model.cjs');
  const tcp = row('tcp', [], { definition: 'tcp-transport-payload', upload_bps: 120 });
  const udp = {
    ...row('udp', [], { definition: 'udp-api-reported', upload_bps: 70 }),
    socket: { protocol: 'udp' },
  };
  const missing = { ...row('missing', [], { available: false }), socket: { protocol: 'udp' } };
  const root = overview({ rows: [tcp, tcp, udp, missing] });
  assert.equal(root.rows.length, 3);
  assert.equal(root.kind, 'overview');
  assert.equal(root.process, undefined);
  assert.equal(sum(root.rows, 'upload_bps').value, undefined);
  assert.equal(sum(root.rows, 'upload_bps', 'tcp').value, 120);
  assert.deepEqual(sum(root.rows, 'upload_bps', 'udp'), {
    value: 70,
    partial: true,
    mixed: false,
    known: 1,
    count: 2,
  });
});
