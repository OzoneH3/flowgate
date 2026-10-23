const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseReply } = require('../dist/test/protocol.cjs');
const { hierarchy, activityTree, activityRowCounts, isKernelTimeWait, allRows, flatten, overview, sum } = require('../dist/test/model.cjs');
const { selectionInventory } = require('../dist/test/activity-policy.cjs');
const { POLICY_CAPABILITY, authoritativePolicy } = require('../dist/test/policy.cjs');

const row = (id, extra = {}, socket = {}) => ({
  id, owners: [], ownership: 'No userspace socket inode', ownership_category: 'no-userspace-inode',
  state: 'Time wait', direction: 'Unknown', evidence: 'Kernel inode zero',
  socket: { protocol: 'tcp', state: 6, inode: 0, local: '127.0.0.1:41000', remote: '127.0.0.1:42000', uid: 1000, cookie: id, netns: 'fixture', ...socket },
  traffic: { available: false, state: 'unavailable', partial: true, definition: 'tcp-transport-payload' }, ...extra,
});
const process = (key, uid = 1000) => ({ id: key, pid: uid + key.length, uid, executable: '/synthetic/' + key,
  application: { key, revision: 'revision', name: key, kind: 'native', executable: '/synthetic/' + key } });
const reply = (rows) => ({ version: 1, generation: 'fixture', read_only: true, server_time: '2026-10-23T19:00:00Z',
  activity: { complete: true, rows, processes: {} } });

test('inode evidence preserves zero but never invents it for missing or malformed metadata', () => {
  for (const inode of [0, 1, 0xffffffff]) {
    const parsed = parseReply(reply([row('one', {}, { inode })])).activity.rows[0];
    assert.equal(parsed.socket.inode, inode);
    assert.equal(isKernelTimeWait(parsed), inode === 0);
  }
  for (const inode of [undefined, null, '0', -1, .1, 0x100000000, NaN, Infinity, {}, false]) {
    const parsed = parseReply(reply([row('one', {}, { inode })])).activity.rows[0];
    assert.equal(parsed.socket.inode, undefined);
    assert.equal(isKernelTimeWait(parsed), false);
    assert.equal(hierarchy({ rows: [parsed], processes: {} })[0].kind, 'unidentified');
  }
});

test('only exact unowned TCP TIME_WAIT with consistent evidence is lifecycle', () => {
  assert(isKernelTimeWait(row('positive')));
  for (const state of [1, 2, 3, 7, 8, 10, 12]) assert.equal(isKernelTimeWait(row('state', {}, { state })), false);
  for (const [extra, socket] of [
    [{}, { protocol: 'udp' }], [{}, { inode: 1 }], [{}, { inode: undefined }],
    [{ owners: ['gone'] }, {}], [{ owners: ['a', 'b'], ownership_category: 'shared' }, {}],
    [{ ownership_category: undefined }, {}], [{ ownership_category: 'holder-changed' }, {}],
    [{ runtime_application: {} }, {}], [{ display_application: {} }, {}],
  ]) assert.equal(isKernelTimeWait(row('negative', extra, socket)), false);
});

test('mixed live, lifecycle, shared and unknown-direction rows retain identities and counts', () => {
  const a = process('alpha'), b = process('beta');
  const owned = row('owned-unknown-direction', { owners: ['alpha'], ownership_category: 'visible-holder', state: 'Established',
    initiation: { state: 'unknown', source: 'inet-diag', reason: 'Initiation not observed' } }, { state: 1, inode: 11 });
  const timewait = row('ended');
  const live = row('live', { ownership_category: 'unknown', state: 'Established' }, { state: 1, inode: 22 });
  const shared = row('shared', { owners: ['alpha', 'beta'], ownership_category: 'shared' }, { state: 1, inode: 33 });
  const same = row('same-app-shared', { owners: ['alpha', 'alpha2'], ownership_category: 'shared', display_application: a.application }, { state: 1, inode: 44 });
  const activity = { rows: [timewait, live, shared, same, owned, timewait], processes: { alpha: a, beta: b, alpha2: { ...a, id: 'alpha2' } } };
  const roots = activityTree(activity, []);
  const lifecycle = roots.find(r => r.kind === 'kernel-lifecycle');
  assert.equal(lifecycle.label, 'Kernel TCP lifecycle (1)');
  assert.deepEqual(lifecycle.children.map(r => r.id), ['ended']);
  assert.deepEqual(roots.find(r => r.kind === 'unidentified').rows.map(r => r.id), ['live', 'shared']);
  assert.equal(allRows(roots).find(r => r.id === owned.id).parent.includes('alpha'), true);
  assert.equal(allRows(roots).find(r => r.id === same.id).parent.includes('alpha'), true);
  assert.deepEqual(activityRowCounts(roots), { displayed: 5, lifecycle: 1, unresolved: 2 });
  const leaves = allRows(roots).filter(r => r.kind === 'socket');
  assert.equal(new Set(leaves.map(r => r.id)).size, 5);
  for (const r of leaves) assert.strictEqual(r.socket, activity.rows.find(s => s.id === r.id));
});

test('lifecycle filtering, refresh and sorting do not hide unresolved sockets or transfer identity', () => {
  const ended = row('stable'), live = row('live', { state: 'Established', ownership_category: 'unknown' }, { state: 1, inode: 22 });
  const activity = { rows: [ended, live], processes: {} };
  assert.deepEqual(activityRowCounts(hierarchy(activity, '', 'active')), { displayed: 1, lifecycle: 0, unresolved: 1 });
  assert.equal(hierarchy(activity, '', 'listening').length, 0);
  assert.deepEqual(activityRowCounts(hierarchy(activity, 'time wait')), { displayed: 1, lifecycle: 1, unresolved: 0 });
  for (const desc of [false, true]) {
    const roots = [overview(activity), ...hierarchy(activity), { id: 'inactive', kind: 'inactive-group', rows: [], children: [], label: 'Not running' }];
    assert.deepEqual(flatten(roots, new Set(), 'uploaded', desc).map(v => v.row.kind), ['overview', 'unidentified', 'kernel-lifecycle', 'inactive-group']);
  }
  assert.equal(hierarchy({ ...activity, rows: [live] }).some(r => r.kind === 'kernel-lifecycle'), false);
  const replacement = { ...ended, socket: { ...ended.socket, inode: 55, state: 1 }, ownership_category: 'unknown' };
  const again = hierarchy({ ...activity, rows: [replacement] });
  assert.equal(again[0].kind, 'unidentified');
  assert.equal(again[0].children[0].id, 'stable');
  assert.equal(again[0].children[0].process, undefined);
});

test('new grouping does not invent or reassign measurements or mix sources', () => {
  const tcp = row('tcp'), udp = row('udp', { ownership_category: 'unknown', traffic: { available: true, definition: 'udp-api-reported', uploaded: 19 } }, { protocol: 'udp', state: 7, inode: 44 });
  const roots = hierarchy({ rows: [tcp, udp], processes: {} });
  const leaves = allRows(roots).filter(r => r.kind === 'socket').map(r => r.socket);
  assert.deepEqual(sum(leaves, 'uploaded', 'tcp'), sum([tcp], 'uploaded', 'tcp'));
  assert.deepEqual(sum(leaves, 'uploaded', 'udp'), sum([udp], 'uploaded', 'udp'));
  assert.equal(sum(roots.find(r => r.kind === 'kernel-lifecycle').rows, 'uploaded').value, undefined);
});

test('lifecycle group and children cannot become policy candidates even for an administrator', () => {
  const now = '2026-10-23T19:00:00Z', p = process('alpha');
  const live = row('live', { owners: [p.id], ownership_category: 'visible-holder' }, { state: 1, inode: 42 });
  const activity = { rows: [row('ended'), live], processes: { [p.id]: p }, sequence: 1, collected: now };
  const direction = { rules: [] };
  const application = { ref: 'app', identity: { key: p.application.key, revision: p.application.revision, uid: p.uid },
    process_ids: [p.id], incoming: direction, outgoing: direction };
  for (const capabilities of [[], [POLICY_CAPABILITY, 'process-instance-rules-v1', 'network-zone-policy-v1']]) {
    const state = { observation: { activity, connected: true, generation: 'fixture' }, control: { capabilities, connected: true, generation: 'fixture',
      rules: [], events: [], server_time: '2026-10-23T19:00:00Z', permissions: { role: 'administrator', can_manage_rules: true },
      serverNow: Date.parse(now),
      policy: { complete: true, snapshot: { generation: 'fixture', meaning: 'Current policy' },
        activity_available: true, activity_sequence: '1', activity_collected: now,
        applications: [application], processes: [], zones: [],
        rows: [{ row_id: live.id, status: 'observed_native', application_ref: application.ref }] } } };
    const roots = activityTree(activity, []);
    const liveLeaf = allRows(roots).find(r => r.id === live.id);
    assert.equal(authoritativePolicy(liveLeaf, state).application, application);
    assert.equal(selectionInventory(liveLeaf, state).candidate, live);
    for (const r of allRows([roots.find(r => r.kind === 'kernel-lifecycle')])) {
      assert.equal(r.process, undefined); assert.equal(r.runtimeApplication, undefined); assert.equal(r.policyRows, undefined);
      const inv = selectionInventory(r, state);
      assert.equal(inv.authoritative, capabilities.includes(POLICY_CAPABILITY));
      assert.equal(authoritativePolicy(r, state).reason, 'No supported single-process application identity.');
      assert.equal(inv.candidate, undefined); assert.equal(inv.app, undefined); assert.equal(inv.processPolicy, undefined); assert.equal(inv.zone, undefined);
    }
  }
});
