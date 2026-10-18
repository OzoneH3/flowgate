const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { rowStructure } = require('../dist/test/row-structure.cjs');
test('live rate updates preserve row DOM identity; native target/state/direction changes do not', () => {
  const socket = {
    id: 's',
    owners: ['p'],
    ownership_category: 'visible-holder',
    socket: { remote: '127.0.0.1:80' },
    state: 'connected',
    initiation: { state: 'known', direction: 'outgoing' },
    traffic: { available: true, upload_bps: 5 },
  };
  const row = {
    id: 'socket:s',
    kind: 'socket',
    label: 'remote',
    rows: [socket],
    socket,
    children: [],
  };
  const key = rowStructure(row, 2, false, false),
    newer = { ...socket, traffic: { available: true, upload_bps: 90, reason: 'new sample' } };
  assert.equal(rowStructure({ ...row, rows: [newer], socket: newer }, 2, false, false), key);
  for (const patch of [
    { owners: ['other'] },
    { ownership_category: 'shared' },
    { socket: { remote: 'other' } },
    { state: 'closed' },
    { initiation: { state: 'unknown' } },
  ]) {
    const s = { ...socket, ...patch };
    assert.notEqual(rowStructure({ ...row, rows: [s], socket: s }, 2, false, false), key);
  }
  assert.notEqual(rowStructure(row, 2, true, false), key);
  assert.notEqual(
    rowStructure({ ...row, process: { application: { revision: 'new' } } }, 2, false, false),
    key,
  );
});
