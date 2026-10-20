// local-pair-v1: same-host connection pairs (presentation and validation only).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseReply, parseProvenance } = require('../dist/test/protocol.cjs');
const { localPairView, pairResultText, validatePairChoice, parseLocalPeer, counterpart } = require('../dist/test/local-pair.cjs');

const gen = 'g1';
const OUT = 'a'.repeat(32), IN = 'b'.repeat(32);
const ds2 = {
  evidence: 'verified', reason: 'unbroken parent chain', role: 'helper', group: 'g-ds2', stop: 'init', ancestry: [],
  launch: { kind: 'umu', launcher_pid: 10, launcher_start_ticks: '1', launcher_name: 'python3 umu-run', markers: ['umu-run'],
    game: { name: 'DS2.exe', title: 'DEATH STRANDING 2', executable: '/g/DS2.exe', status: 'verified-file', source: 'proton' } },
};
const cupsd = { pid: 764, start_ticks: '900', uid: 0, executable: '/usr/bin/cupsd', application: { key: 'k-cupsd', revision: 'r', name: 'cupsd', executable: '/usr/bin/cupsd', kind: 'native' } };
const rundll = { pid: 1195586, start_ticks: '4782344', uid: 1000, executable: '/c/wine64-preloader', application: { key: 'k-rundll', revision: 'r', name: 'rundll32.exe', executable: '/c/rundll32.exe', kind: 'wine' }, provenance: ds2 };
const target = (label) => ({ kind: 'application', label, once: 'This connection request only', for_a_while: 'x', remember: label, key_basis: 'uid+executable path' });

function raw({ id, direction, peer, state = 'awaiting-decision', owner, local, remote, sockets }) {
  return {
    id, state, reason: 'r', deadline: new Date(Date.now() + 60000).toISOString(), first_seen: '', permission: '', rule: '',
    flow: { direction, protocol: 'tcp', local, remote },
    attribution: { status: 'directly-associated', reason: 'one owner', visibility_complete: true, application: owner.application, owners: [owner], provenance: owner.provenance, permission_target: target(owner.application.name), sockets },
    scope_previews: { once: 'Once' },
    local_peer: peer,
  };
}
const clientPeer = (extra = {}) => ({
  state: 'verified', role: 'client', reason: 'Verified local client', evidence: 'TCP socket [::1]:44104 -> [::1]:631 (Connecting (SYN sent)), cookie c0ffee, inode 5150; one descriptor holder PID 1195586 (start 4782344)',
  owner: rundll, socket: { kind: 'client', protocol: 'tcp', local: '[::1]:44104', remote: '[::1]:631', state: 'Connecting (SYN sent)', cookie: 'c0ffee', inode: 5150 }, ...extra,
});
const serverPeer = (extra = {}) => ({
  state: 'verified', role: 'server', reason: 'Verified local server', owner: cupsd,
  socket: { kind: 'listener', protocol: 'tcp', local: '[::1]:631', remote: '[::]:0', state: 'Listening', cookie: 'beef', inode: 77 }, ...extra,
});
function reply(events, extra = {}) {
  return parseReply({ version: 1, generation: gen, read_only: false, server_time: new Date().toISOString(), capabilities: ['local-pair-v1'], events, ...extra });
}
const caps = ['local-pair-v1'];

test('incoming local request: first view names client game -> server, local line, explicit own target', () => {
  const r = reply([raw({ id: IN, direction: 'incoming', owner: cupsd, local: '[::1]:631', remote: '[::1]:44104', peer: clientPeer(), sockets: [{ protocol: 'tcp', local: '[::1]:631', state: 10, cookie: 'beef', inode: 77 }] })]);
  const e = r.events[0];
  assert.equal(e.local_peer.owner.provenance.launch.game.name, 'DS2.exe');
  const v = localPairView(e, r.events, caps);
  assert.equal(v.title, 'DEATH STRANDING 2 · DS2.exe (via rundll32.exe) → cupsd');
  assert.equal(v.line, 'Incoming to cupsd · TCP · local');
  assert.equal(v.unknown, undefined);
  assert.match(v.target, /incoming to cupsd only\. It is not an outgoing permission for rundll32\.exe/);
  assert.equal(v.sides[0].label, 'Outgoing: rundll32.exe → [::1]:631');
  assert.equal(v.sides[0].phase, 'not-intercepted');
  assert.equal(v.sides[1].label, 'Incoming: cupsd ← rundll32.exe ([::1]:44104)');
  assert.equal(v.pairIds, undefined, 'no pair control without a backend-confirmed counterpart');
  const d = Object.fromEntries(v.details);
  assert.match(d['Local client'], /^rundll32\.exe · PID 1195586 · start 4782344 · UID 1000\n\/c\/rundll32\.exe\nclient socket \[::1\]:44104 → \[::1\]:631 · Connecting \(SYN sent\)\ncookie c0ffee · inode 5150\nLaunch: DEATH STRANDING 2 · DS2\.exe/);
  assert.match(d['This socket'], /cupsd · \[::1\]:631 ← \[::1\]:44104\ncookie beef · inode 77/);
});

test('unknown local client: explicit reason, never a guessed owner', () => {
  const peer = { state: 'unknown', role: 'client', reason: 'Local client unknown: the client socket closed before it could be identified' };
  const r = reply([raw({ id: IN, direction: 'incoming', owner: cupsd, local: '[::1]:631', remote: '[::1]:46838', peer })]);
  const v = localPairView(r.events[0], r.events, caps);
  assert.equal(v.title, 'Unknown local client → cupsd');
  assert.equal(v.unknown, 'Local client unknown: the client socket closed before it could be identified');
  assert.equal(v.sides[1].label, 'Incoming: cupsd ← unknown local client ([::1]:46838)');
  assert.equal(v.pairIds, undefined);
  // A "verified" peer without owner/socket evidence is downgraded.
  assert.equal(parseLocalPeer({ state: 'verified', role: 'client', reason: 'x' }, parseProvenance).state, 'unknown');
  assert.equal(parseLocalPeer({ state: 'trusted', role: 'client' }, parseProvenance), undefined);
});

test('pair: both sides listed with their own verdicts; one side decided is never hidden', () => {
  const out = raw({ id: OUT, direction: 'outgoing', state: 'allowed', owner: rundll, local: '[::1]:44104', remote: '[::1]:631', peer: serverPeer({ correlated_event_id: IN }) });
  const inc = raw({ id: IN, direction: 'incoming', owner: cupsd, local: '[::1]:631', remote: '[::1]:44104', peer: clientPeer({ correlated_event_id: OUT }) });
  const r = reply([out, inc]);
  const e = r.events.find((x) => x.id === IN);
  assert.equal(counterpart(e, r.events).id, OUT);
  const v = localPairView(e, r.events, caps);
  assert.deepEqual(v.sides.map((s) => [s.direction, s.phase, s.status]), [
    ['outgoing', 'allowed', 'Allowed'],
    ['incoming', 'pending', 'Waiting for a decision'],
  ]);
  assert.deepEqual(v.pairIds, [OUT, IN]);
  assert.match(v.pairNote, /a side already decided keeps its verdict/);
  assert.match(Object.fromEntries(v.details)['Paired request'], new RegExp('outgoing request ' + OUT));
  // Only mutual references count: a one-sided id is not a pair.
  const lone = reply([raw({ ...out, id: OUT, direction: 'outgoing', owner: rundll, local: '[::1]:44104', remote: '[::1]:631', peer: serverPeer() }), inc]);
  const v2 = localPairView(lone.events.find((x) => x.id === IN), lone.events, caps);
  assert.equal(v2.sides[0].phase, 'not-intercepted');
  assert.equal(v2.pairIds, undefined);
  // Without the backend capability no pair control is offered.
  assert.equal(localPairView(e, r.events, []).pairIds, undefined);
});

test('outgoing local request before the incoming side exists: Allow both covers both permissions', () => {
  const r = reply([raw({ id: OUT, direction: 'outgoing', owner: rundll, local: '[::1]:44104', remote: '[::1]:631', peer: serverPeer() })]);
  const v = localPairView(r.events[0], r.events, caps);
  assert.equal(v.title, 'DEATH STRANDING 2 · DS2.exe (via rundll32.exe) → cupsd');
  assert.equal(v.line, 'Outgoing to cupsd · TCP · local');
  assert.equal(v.sides[1].phase, 'not-requested');
  assert.match(v.sides[1].status, /Not requested yet/);
  assert.deepEqual(v.pairIds, [OUT]);
  assert.match(v.target, /outgoing for rundll32\.exe only\. It is not an incoming permission for cupsd/);
});

test('decide-pair result shows both verdicts, including a rule that denies the other side', () => {
  const out = raw({ id: OUT, direction: 'outgoing', state: 'allowed', owner: rundll, local: '[::1]:44104', remote: '[::1]:631', peer: serverPeer() });
  const r = reply([], { pair: { events: [out], sentence: 'Allowed both', incoming_admission: { action: 'allow', until: '', local: '[::1]:631', remote: '[::1]:44104', outcome: 'rule', configured_action: 'block', configured_rule: 'deny-cupsd', sentence: 'x' } } });
  assert.equal(pairResultText(r.pair), 'Outgoing: Allowed · Incoming: Denied by rule deny-cupsd (not by this decision)');
  const both = reply([], { pair: { events: [out, raw({ id: IN, direction: 'incoming', state: 'blocked', owner: cupsd, local: '[::1]:631', remote: '[::1]:44104' })], sentence: '' } });
  assert.equal(pairResultText(both.pair), 'Outgoing: Allowed · Incoming: Denied');
  assert.throws(() => reply([], { pair: { events: [] } }));
});

test('pair choice validation', () => {
  assert.deepEqual(validatePairChoice({ generation: gen, ids: [OUT, IN], action: 'allow', scope: 'once' }).ids, [OUT, IN]);
  for (const bad of [
    { generation: gen, ids: [OUT, OUT], action: 'allow', scope: 'once' },
    { generation: gen, ids: [OUT, IN, OUT], action: 'allow', scope: 'once' },
    { generation: gen, ids: [OUT], action: 'allow', scope: 'persistent' },
    { generation: gen, ids: ['../x'], action: 'allow', scope: 'once' },
    { generation: gen, ids: [OUT], action: 'allow', scope: 'once', extra: 1 },
  ])
    assert.throws(() => validatePairChoice(bad));
});

class El {
  constructor(tag) { Object.assign(this, { tagName: tag.toUpperCase(), children: [], text: '', className: '', id: '', dataset: {}, attrs: {}, hidden: false, title: '' }); }
  set textContent(t) { this.children = []; this.text = String(t); }
  get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); }
  append(...nodes) { for (let n of nodes) { if (typeof n === 'string') { const t = new El('#text'); t.text = n; n = t; } this.children.push(n); } }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  *walk() { yield this; for (const c of this.children) yield* c.walk(); }
}
test('request card: Timberborn -> cupsd first view is short; the pair lives in Details only', () => {
  global.document = { createElement: (t) => new El(t) };
  global.Option = class extends El { constructor(l, v) { super('option'); this.text = l; this.value = v; } };
  global.window = { flowgate: { applicationMetadata: async () => ({}) } };
  const { buildRequestCard } = require('../dist/test/prompt-card.cjs');
  const timberborn = { ...ds2, group: 'g-tb', launch: { ...ds2.launch, game: { name: 'Timberborn.exe', title: 'Timberborn', executable: '/g/Timberborn.exe', status: 'verified-file', source: 'proton' } } };
  const helper = { ...rundll, provenance: timberborn };
  const out = raw({ id: OUT, direction: 'outgoing', owner: helper, local: '127.0.0.1:44104', remote: '127.0.0.1:631', peer: serverPeer({ socket: { kind: 'listener', protocol: 'tcp', local: '127.0.0.1:631', remote: '0.0.0.0:0', state: 'Listening', cookie: 'beef', inode: 77 } }), sockets: [{ protocol: 'tcp', local: '127.0.0.1:44104', state: 2, cookie: 'c0ffee', inode: 5150 }] });
  out.attribution.permission_target = { kind: 'helper', label: 'rundll32.exe in prefix ~/pfx (shared by every game using this prefix)', once: 'This connection request only; no rule is saved', for_a_while: 'This process instance only', remember: 'rundll32.exe (/c/rundll32.exe) in prefix ~/pfx, UID 1000, this file revision', shared_with_note: 'Shared by every game using prefix ~/pfx: any program there running this rundll32.exe file is covered, not only Timberborn (Timberborn.exe)', key_basis: 'uid+wine+prefix+executable path; revision = file stamp', prefix: '/home/u/pfx' };
  const r = reply([out]);
  const e = r.events[0];
  const pair = localPairView(e, r.events, caps);
  assert.deepEqual(pair.pairIds, [OUT], 'plain Allow/Deny answers the exact pair (Once)');
  const root = new El('div');
  root.append(...buildRequestCard({ ...e, remainingMs: 60000 }, { name: 'rundll32.exe', rememberMode: true, forAWhile: true, rememberOptions: [], pair }));
  const all = [...root.walk()], byId = (id) => all.find((n) => n.id === id);
  const details = byId('requestMore'), inside = new Set(details.walk());
  const visible = all.filter((n) => !inside.has(n) && !n.hidden);
  const text = visible.map((n) => n.text || '').join(' | ');
  // Required first view.
  assert.equal(byId('requestApplication').textContent.replace('◇', ''), 'Timberborn');
  assert.equal(byId('requestOwner').textContent, 'rundll32.exe');
  assert.equal(byId('requestDestination').textContent, 'To Local printing service (cupsd) · 127.0.0.1:631 · TCP');
  assert.ok(byId('requestStatusLine'));
  assert.equal(byId('detailsToggle').text, 'Details');
  assert.deepEqual(byId('decisionControls').children.map((c) => c.id || c.children.find((x) => x.tagName === 'INPUT')?.id), ['allow', 'block', 'rememberToggle', 'forAWhileToggle']);
  // Nothing about paired hooks, no raw diagnostics in the first view.
  for (const gone of ['Allow both', 'Deny both', 'pairAllow', 'pairBlock', 'localPair'])
    assert.ok(!all.some((n) => n.id === gone || n.text === gone), gone);
  for (const hidden of ['PID', 'cookie', 'inode', '/c/rundll32.exe', 'Incoming', 'uid+wine', 'This request', 'prefix ~/pfx (shared'])
    assert.ok(!text.includes(hidden), 'first view hides ' + hidden);
  // Details: labelled sections; the pair, sockets and rule internals are there.
  const sections = [...details.walk()].filter((n) => n.tagName === 'DETAILS').map((n) => n.dataset.section);
  assert.deepEqual(sections, ['connection', 'application', 'launch', 'local-pair', 'rule', 'status']);
  const d = details.textContent;
  assert.match(d, /Outgoing side.*rundll32\.exe → 127\.0\.0\.1:631/s);
  assert.match(d, /Incoming side.*Not requested yet/s);
  assert.match(d, /cookie c0ffee · inode 5150/);
  assert.match(d, /uid\+wine\+prefix\+executable path/);
  assert.match(d, /not only Timberborn/);
  // Remember is labelled before the click with the helper/prefix scope, never Timberborn-wide.
  assert.equal(byId('rememberScope').textContent, 'Rule for rundll32.exe in prefix ~/pfx · every game using this prefix');
  // Not a local request: no pair rows.
  const plain = reply([raw({ id: OUT, direction: 'outgoing', owner: rundll, local: '10.0.0.2:5000', remote: '1.1.1.1:443' })]).events[0];
  const r2 = new El('div');
  r2.append(...buildRequestCard({ ...plain, remainingMs: 1 }, { name: 'x', rememberMode: false, forAWhile: false, rememberOptions: [], pair: localPairView(plain, [], caps) }));
  assert.ok(![...r2.walk()].some((n) => n.dataset?.section === 'local-pair'));
  assert.equal([...r2.walk()].find((n) => n.id === 'requestDestination').textContent, 'To 1.1.1.1:443 · TCP');
});
