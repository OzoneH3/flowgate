const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  AutomaticPrompts,
  edgePosition,
  boundDecision,
  requestGroups,
  askSource,
} = require('../dist/test/automatic-prompts.cjs');
const state = (ids, generation = 'g') => ({
  control: {
    connected: true,
    readOnly: false,
    generation,
    permissions: { can_decide: true },
    events: ids.map((id) => ({ id, state: 'awaiting-decision', remainingMs: 1000 })),
  },
});
// 51 identical attempts (same backend request_group), delivered out of order.
const burst = (n = 51, extra = []) => {
  const events = [];
  for (let i = 0; i < n; i++)
    events.push({
      id: 'r' + i,
      request_group: 'same',
      state: 'awaiting-decision',
      remainingMs: 30000,
      first_seen: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
      deadline: new Date(Date.UTC(2026, 0, 1, 0, 1, i)).toISOString(),
    });
  events.reverse();
  return {
    control: {
      connected: true,
      readOnly: false,
      generation: 'g',
      permissions: { can_decide: true },
      events: [...events, ...extra],
    },
  };
};
test('one card per group; dismissal never auto-reopens that group', () => {
  const q = new AutomaticPrompts();
  const first = q.next(state(['a', 'b']), false);
  assert.deepEqual(first, { generation: 'g', id: 'a', group: 'e:a' });
  assert.equal(q.next(state(['a', 'b']), true), undefined);
  // Not dismissed (e.g. still open elsewhere): the same group stays first.
  assert.equal(q.next(state(['a', 'b']), false).id, 'a');
  q.dismiss(first);
  assert.equal(q.next(state(['a', 'b']), false).id, 'b');
  q.dismiss({ generation: 'g', id: 'b', group: 'e:b' });
  assert.equal(q.next(state(['a', 'b']), false), undefined);
  assert.equal(q.next(state(['a'], 'new'), false).id, 'a');
});
test('51 identical attempts are one prompt with a count; decision targets its representative only', () => {
  const s = burst();
  const groups = requestGroups(s.control.events);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].count, 51);
  assert.equal(groups[0].representative.id, 'r0');
  const q = new AutomaticPrompts();
  const ref = q.next(s, false);
  assert.deepEqual(ref, { generation: 'g', id: 'r0', group: 'g:same' });
  // While that card is open, nothing else opens: no prompt storm.
  for (let i = 0; i < 51; i++) assert.equal(q.next(s, true), undefined);
  const d = { generation: 'g', id: 'r0', action: 'allow', scope: 'once' };
  assert.deepEqual(boundDecision(d, ref), d);
  for (const other of ['r1', 'r50'])
    assert.throws(() => boundDecision({ ...d, id: other }, ref), /does not belong/);
  q.dismiss(ref);
  assert.equal(q.next(burst(60), false), undefined);
});
test('settled requests disappear; the open card advances within its group or closes', () => {
  const s = burst(3, [
    {
      id: 'other',
      state: 'awaiting-decision',
      remainingMs: 30000,
      first_seen: '2027-01-01T00:00:00Z',
    },
  ]);
  const q = new AutomaticPrompts(),
    ref = q.next(s, false);
  assert.equal(ref.id, 'r0');
  // A submitted (not yet acknowledged) decision keeps the card.
  s.control.events.find((e) => e.id === 'r0').attempt = { phase: 'submitting', message: '' };
  assert.deepEqual(q.follow(s, ref), ref);
  // Answered once: next representative of the same group, never a fan-out.
  Object.assign(
    s.control.events.find((e) => e.id === 'r0'),
    { state: 'allowed', attempt: undefined },
  );
  assert.deepEqual(q.follow(s, ref), { generation: 'g', id: 'r1', group: 'g:same' });
  // Remember rule settles the rest by re-evaluation, others finalized/expired.
  Object.assign(
    s.control.events.find((e) => e.id === 'r1'),
    {
      state: 'allowed',
      reason: 're-evaluated after policy change',
    },
  );
  Object.assign(
    s.control.events.find((e) => e.id === 'r2'),
    { remainingMs: 0 },
  );
  assert.deepEqual(
    requestGroups(s.control.events).map((g) => g.key),
    ['e:other'],
  );
  assert.equal(q.follow(s, { generation: 'g', id: 'r1', group: 'g:same' }), undefined);
  assert.equal(q.next(s, false).id, 'other');
  assert.equal(q.follow({ ...s, control: { ...s.control, generation: 'new' } }, ref), undefined);
});
test('prompt names the stored Ask rule that asked, else default Ask', () => {
  const e = { id: 'e', ask_rule: { id: 'user:1', version: 2 } };
  const rule = (filter) => ({ id: 'user:1', action: 'ask', filter });
  assert.equal(askSource({ id: 'e' }), 'No matching rule (default Ask)');
  assert.equal(askSource(e), 'Asked by rule user:1');
  assert.equal(
    askSource(e, [rule({ direction: 'outgoing', protocol: '*', remote_address: '*' })]),
    'Asked by rule user:1 (Ask, application, Out)',
  );
  assert.equal(
    askSource(e, [rule({ direction: 'incoming', protocol: 'tcp', remote_address: '10.0.0.1' })]),
    'Asked by rule user:1 (Ask, scoped, In)',
  );
  assert.equal(
    askSource(e, [rule({ direction: 'outgoing', protocol: '*', process: { pid: 4 } })]),
    'Asked by rule user:1 (Ask, process, Out)',
  );
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

test('permission sender is frozen to request and daemon, main retains explicit selection', () => {
  const d = { generation: 'g', id: 'a', action: 'allow', scope: 'once' };
  assert.deepEqual(boundDecision(d, { generation: 'g', id: 'a' }), d);
  assert.throws(() => boundDecision(d, { generation: 'g', id: 'b' }));
  assert.throws(() => boundDecision(d, { generation: 'new', id: 'a' }));
  assert.deepEqual(boundDecision(d), d);
});

test('unknown acknowledgement stays available for reconciliation even after expiry', () => {
  const q = new AutomaticPrompts(),
    s = state(['a', 'b']),
    ref = q.next(s, false);
  Object.assign(s.control.events[0], {
    remainingMs: 0,
    state: 'expired',
    attempt: { phase: 'unknown' },
  });
  assert.deepEqual(q.follow(s, ref), ref);
});

test('automatic popup closes settled and expired retained cards instead of showing disabled actions',()=>{
 for(const status of ['allowed','blocked','expired']){
  const q=new AutomaticPrompts(),s=state(['a']),ref=q.next(s,false);
  Object.assign(s.control.events[0],{state:status,remainingMs:0,request_rule:{available:true}});
  assert.equal(q.follow(s,ref),undefined);
 }
});

test('a hidden answered popup waits for the in-flight remembered result before presenting another request',()=>{
 const q=new AutomaticPrompts(),s=state(['a','b','c']);
 s.control.events[0].attempt={phase:'submitting'};
 assert.equal(q.next(s,false),undefined);
 s.control.events[0].attempt={phase:'unknown'};s.control.reconciling=true;
 assert.equal(q.next(s,false),undefined);
 s.control.reconciling=false;
 for(const e of s.control.events){e.state='allowed';e.remainingMs=0;e.attempt=undefined;}
 assert.equal(q.next(s,false),undefined);
});

test('explicit Remember review keeps its ended request, without retaining unsolicited expired cards', () => {
  const auto=new AutomaticPrompts(), s=state(['old','new']);
  s.control.capabilities=['request-application-rule-v1'];
  const ended=s.control.events[0];
  Object.assign(ended,{state:'expired',remainingMs:0,request_rule:{available:true},reviewFailure:{terminal:true,code:'connection_ended',message:'socket gone'}});
  const ref={generation:'g',id:'old',group:'e:old'};
  assert.equal(auto.follow(s,ref,true),ref);
  assert.equal(auto.follow(s,ref,false),undefined);
  ended.request_rule.available=false;
  assert.equal(auto.follow(s,ref,true),undefined);
  assert.equal(auto.follow({...s,control:{...s.control,generation:'new'}},ref,true),undefined);
});
