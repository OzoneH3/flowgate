// Synthetic metadata/state checks. Real receiver semantics belong to backend evidence.
const { test } = require('node:test'),
  assert = require('node:assert/strict');
const { parseProcessTarget, sameProcessTarget } = require('../dist/test/process-rules.cjs');
const { parsePolicyView, authoritativeProcessPolicy } = require('../dist/test/policy.cjs');
global.window = { addEventListener() {} };
const { selectionInventory } = require('../dist/test/activity-policy.cjs');
const binding = {
  instance_id: 'a'.repeat(32),
  session: 'g',
  boot_id: 'boot',
  pid: 9,
  start_ticks: '18446744073709551615',
  uid: 1000,
  netns: 'net:[1]',
  mountns: 'mnt:[2]',
  pidns: 'pid:[3]',
  executable: '/test/native',
  revision: 'rev',
};
const dir = (d, rules = []) => ({
  direction: d,
  configured: rules.length ? 'scoped' : 'absent',
  reason: 'Backend classification',
  rules,
  active_rules: rules.length,
  disabled_rules: 0,
  expired_rules: 0,
  potential_overlapping_actions: false,
  configured_default: { known: false, reason: 'Unknown' },
  runtime_default: { known: false, reason: 'Stopped' },
  enforcement: { state: 'stopped', covered: false, reason: 'Stopped' },
});
const rule = (id, process) => ({
  id,
  version: '18446744073709551615',
  action: 'block',
  priority: 100,
  scope: {
    application: 'app',
    revision: 'rev',
    uid: 1000,
    direction: 'incoming',
    protocol: 'tcp',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
    ...(process ? { process } : {}),
  },
  disabled: false,
  expired: false,
  active: true,
  expires: '0001-01-01T00:00:00Z',
  target_scope: process ? 'process' : 'application',
  target_state: 'active',
  target_reason: 'live',
});
function fixture() {
  const now = new Date().toISOString(),
    p = {
      id: '9:start',
      pid: 9,
      start_ticks: binding.start_ticks,
      uid: 1000,
      application: { key: 'app', revision: 'rev', executable: '/test/native' },
    };
  const pv = {
    snapshot: {
      generation: 'g',
      token: 't',
      sequence: '1',
      evaluated_at: now,
      meaning: 'Current only',
    },
    activity_sequence: '1',
    activity_collected: now,
    activity_available: true,
    complete: true,
    applications: [
      {
        ref: 'appref',
        identity: { key: 'app', revision: 'rev', uid: 1000 },
        process_ids: [p.id],
        incoming: dir('incoming', [rule('app')]),
        outgoing: dir('outgoing'),
      },
    ],
    processes: [
      {
        ref: 'processref',
        process_id: p.id,
        application_ref: 'appref',
        target: binding,
        state: 'active',
        reason: 'live native target',
        precedence: 'matching-process-before-application',
        incoming: dir('incoming', [rule('process', binding)]),
        outgoing: dir('outgoing'),
        application_incoming: dir('incoming', [rule('app')]),
        application_outgoing: dir('outgoing'),
      },
    ],
    rows: [],
  };
  const state = {
    control: {
      connected: true,
      generation: 'g',
      serverNow: Date.now(),
      capabilities: ['policy-explanations-v1', 'process-instance-rules-v1'],
      policy: parsePolicyView(pv),
    },
    observation: {
      connected: true,
      generation: 'g',
      activity: { sequence: 1, collected: now, processes: { [p.id]: p }, rows: [] },
    },
  };
  return { state, row: { id: 'process:9:start', kind: 'process', process: p, rows: [] } };
}
test('process inventory keeps own rules and app fallback independent; app never inherits process override', () => {
  const { state, row } = fixture();
  const inv = selectionInventory(row, state);
  assert.deepEqual(
    inv.rules.map((r) => r.id),
    ['process', 'app'],
  );
  assert.equal(inv.processPolicy.precedence, 'matching-process-before-application');
  assert.equal(inv.rules[0].version, '18446744073709551615');
  const app = selectionInventory({ ...row, kind: 'application' }, state);
  assert.deepEqual(
    app.rules.map((r) => r.id),
    ['app'],
  );
  assert.equal(app.processPolicy, undefined);
});
test('PID reuse, session change and shared rows do not bind; inactive exact target remains inspectable', () => {
  const { state, row } = fixture();
  assert(authoritativeProcessPolicy(row, state));
  assert.equal(
    authoritativeProcessPolicy({ ...row, process: { ...row.process, start_ticks: 'new' } }, state),
    undefined,
  );
  state.control.policy.processes[0].state = 'inactive';
  state.control.policy.processes[0].reason = 'Process exited';
  assert.equal(authoritativeProcessPolicy(row, state).reason, 'Process exited');
  assert.equal(
    authoritativeProcessPolicy(
      {
        ...row,
        kind: 'socket',
        socket: { owners: ['9:start', 'other'], ownership_category: 'shared' },
      },
      state,
    ),
    undefined,
  );
  state.control.generation = 'new';
  assert.equal(authoritativeProcessPolicy(row, state), undefined);
});
test('bridge bindings retain exact start ticks and opaque instance; missing or unsafe binding fails closed', () => {
  assert.deepEqual(parseProcessTarget(binding), binding);
  assert.equal(parseProcessTarget({ ...binding, instance_id: '' }, true).instance_id, '');
  assert(!sameProcessTarget(binding, { ...binding, instance_id: 'b'.repeat(32) }));
  assert.throws(() => parseProcessTarget({ ...binding, instance_id: undefined }));
  assert.throws(() => parseProcessTarget({ ...binding, start_ticks: 9007199254740992 }));
  assert.throws(() => parseProcessTarget({ ...binding, pid: NaN }));
});

test('socket holder witness restricts process scope without transferring to sibling rows or app identity', () => {
  const { state, row } = fixture();
  const socket = { id: 'worker', owners: [row.process.id], ownership_category: 'visible-holder', holder_witness: 'a'.repeat(64) };
  state.control.policy.rows.push({ row_id: socket.id, status: 'observed_native', application_ref: 'appref' });
  const leaf = { ...row, id: socket.id, kind: 'socket', socket, rows: [socket] };
  assert.equal(authoritativeProcessPolicy(leaf, state), undefined);
  const inv = selectionInventory(leaf, state);
  assert.equal(inv.app.identity.key, 'app');
  assert.equal(inv.candidate, socket);
  assert.equal(inv.processCandidate, undefined);
  assert.equal(inv.processPolicy, undefined);
  const witnessedProcess = selectionInventory({ ...row, rows: [socket] }, state);
  assert.equal(witnessedProcess.processPolicy, undefined);
  assert.deepEqual(witnessedProcess.rules.map(r => r.id), ['app']);
  const ordinary = { ...socket, id: 'ordinary', holder_witness: undefined };
  const mixed = selectionInventory({ ...row, rows: [socket, ordinary] }, state);
  assert.equal(mixed.candidate, socket);
  assert.equal(mixed.processCandidate, ordinary);
  assert.equal(mixed.processPolicy.state, 'active');
});

test('Activity parser preserves valid holder restriction, legacy absence, and rejects malformed evidence', () => {
  const { parseReply } = require('../dist/test/protocol.cjs');
  const reply = holder_witness => ({version:1,generation:'g',read_only:true,server_time:'2026-10-23T21:00:00Z',activity:{processes:{},rows:[{id:'row',owners:[],socket:{},holder_witness}]}});
  for (const w of [undefined, '', 'a'.repeat(64)])
    assert.equal(parseReply(reply(w)).activity.rows[0].holder_witness, w || undefined);
  for (const w of [null, false, 1, {}, 'short', 'A'.repeat(64), 'a'.repeat(65)])
    assert.throws(() => parseReply(reply(w)), /Invalid holder witness/);
});
