// Simplified permission window: first-view text,
// the concise Remember label, the pair click plan and submission results.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ps = require('../dist/test/prompt-summary.cjs');
const pd = require('../dist/test/prompt-decision.cjs');
const pr = require('../dist/test/permission-results.cjs');

const timberborn = {
  evidence: 'verified', reason: 'r', role: 'helper', group: 'g-tb', stop: 'init', ancestry: [],
  launch: { kind: 'umu', launcher_pid: 10, launcher_start_ticks: '1', launcher_name: 'python3 umu-run', markers: [],
    game: { name: 'Timberborn.exe', title: 'Timberborn', executable: '/g/Timberborn.exe', status: 'verified-file', source: 'steam' } },
};
const rundll = { pid: 7, start_ticks: '1', uid: 1000, executable: '/w/rundll32.exe', application: { key: 'k', revision: 'r', name: 'rundll32.exe', executable: '/w/rundll32.exe' }, provenance: timberborn };
const cupsd = { pid: 764, start_ticks: '9', uid: 0, executable: '/usr/bin/cupsd', application: { key: 'c', revision: 'r', name: 'cupsd', executable: '/usr/bin/cupsd' } };
const ev = (over = {}) => ({
  id: 'a1', state: 'awaiting-decision', reason: 'r', deadline: '', scope_previews: { once: 'Once' },
  flow: { direction: 'outgoing', protocol: 'tcp', local: '127.0.0.1:40000', remote: '127.0.0.1:631' },
  attribution: { status: 'directly-associated', reason: '', visibility_complete: true, application: rundll.application, owners: [rundll], provenance: timberborn },
  local_peer: { state: 'verified', role: 'server', reason: '', owner: cupsd, socket: { kind: 'listener', protocol: 'tcp', local: '127.0.0.1:631', remote: '0.0.0.0:0', state: 'Listening', cookie: 'b', inode: 1 } },
  ...over,
});

test('first view: game title, actual owner, local service destination', () => {
  const s = ps.promptSummary(ev(), 'rundll32.exe');
  assert.deepEqual(s, { title: 'Timberborn', owner: 'rundll32.exe', destination: 'Local printing service (cupsd)', endpoint: '127.0.0.1:631', protocol: 'TCP' });
  assert.equal(ps.destinationLine(s, 'outgoing'), 'To Local printing service (cupsd) · 127.0.0.1:631 · TCP');
  // Unverified peer: never a guessed service name.
  const unknown = ps.promptSummary(ev({ local_peer: { state: 'unknown', role: 'server', reason: 'gone' } }), 'x');
  assert.equal(unknown.destination, 'Local service');
  // An unknown local program keeps its own name.
  const other = ps.promptSummary(ev({ local_peer: { ...ev().local_peer, owner: { ...cupsd, application: { ...cupsd.application, name: 'mydaemon' } } } }), 'x');
  assert.equal(other.destination, 'Local service (mydaemon)');
  // No provenance: the application is the title, no owner line; remote endpoint as destination.
  const plain = ps.promptSummary(ev({ local_peer: undefined, attribution: { ...ev().attribution, provenance: undefined, owners: [{ ...rundll, provenance: undefined }] }, flow: { ...ev().flow, remote: '1.1.1.1:443' } }), 'x');
  assert.deepEqual([plain.title, plain.owner, plain.destination, plain.endpoint], ['rundll32.exe', '', '1.1.1.1:443', '']);
});

test('Remember label: the helper/prefix scope, never the game', () => {
  const helper = { kind: 'helper', label: 'rundll32.exe in prefix …/compatdata/1062090/pfx (shared by every game using this prefix)', prefix: '/home/u/.local/share/Steam/steamapps/compatdata/1062090/pfx', once: '', for_a_while: '', remember: '', key_basis: '' };
  assert.equal(ps.rememberLabel(helper), 'Rule for rundll32.exe in prefix …/1062090/pfx · every game using this prefix');
  assert.equal(ps.rememberLabel({ ...helper, kind: 'application', label: 'Game.exe in prefix ~/pfx', prefix: '/home/u/pfx' }), 'Rule for Game.exe in prefix ~/pfx');
  assert.equal(ps.rememberLabel({ kind: 'application', label: 'curl (every process running this executable)' }), 'Rule for curl');
  assert.equal(ps.rememberLabel({ kind: 'interpreter', label: 'python3 interpreter (every script it runs)' }), 'Rule for python3 interpreter · every script it runs');
  assert.equal(ps.rememberLabel({ kind: 'helper', label: 'steam (every process running steam)' }), 'Rule for steam · every program running it');
  assert.match(ps.rememberLabel(undefined), /^Unavailable/);
});

test('one preview without its verb; overlaps listed separately', () => {
  const r = ps.splitPreview('Allow curl to any address. Overlap: user:1 (block, priority 3). Overlap: user:2 (allow, priority 3). And 4 more overlapping rules.');
  assert.equal(r.preview, 'curl to any address.');
  assert.deepEqual(r.overlaps, ['user:1 (block, priority 3)', 'user:2 (allow, priority 3)', 'and 4 more']);
  assert.deepEqual(ps.splitPreview('Deny x').overlaps, []);
});

test('plain Allow/Deny on a verified pair is one exact Once pair decision; options keep their semantics', () => {
  const base = { generation: 'g', zoneRevision: 'z', capabilities: ['decision-for-a-while-v1'], forAWhile: false, remember: false, fields: { protocol: false, process: false, address: false, port: false }, duration: 0 };
  const e = { ...ev(), remainingMs: 9000 };
  assert.deepEqual(pd.promptPlan(e, 'allow', { ...base, pairIds: ['a1'] }), { kind: 'pair', choice: { generation: 'g', ids: ['a1'], action: 'allow', scope: 'once' } });
  assert.deepEqual(pd.promptPlan(e, 'block', { ...base, pairIds: ['a1', 'b2'] }).choice.ids, ['a1', 'b2']);
  assert.equal(pd.promptPlan(e, 'allow', base).kind, 'decide', 'no pair: single Once');
  const faw = pd.promptPlan(e, 'allow', { ...base, forAWhile: true, pairIds: ['a1'] });
  assert.equal(faw.kind, 'decide');
  assert.equal(faw.decision.scope, 'for-a-while', 'For a while stays a single-process lease');
  const rem = pd.promptPlan(e, 'allow', { ...base, remember: true, pairIds: ['a1'] });
  assert.equal(rem.kind, 'decide');
  assert.notEqual(rem.decision.scope, 'once', 'Remember stays the reviewed rule for this request');
});

test('results: a conflicting rule on the other hook is a warning; lost acks are unknown, never success', () => {
  const pair = { events: [], sentence: 'Allowed both sides', incoming_admission: { action: 'allow', outcome: 'rule', configured_action: 'block', configured_rule: 'user:cupsd-in', until: '', local: '', remote: '', sentence: 'Incoming to cupsd: denied by user:cupsd-in, not by this decision' } };
  const w = pr.pairOutcome(pair, 'allow', 'Outgoing: Allowed · Incoming: Denied by rule user:cupsd-in (not by this decision)');
  assert.equal(w.severity, 'warning');
  assert.match(w.detail, /denied by user:cupsd-in, not by this decision/);
  assert.equal(pr.pairOutcome({ ...pair, incoming_admission: { ...pair.incoming_admission, outcome: 'pair' } }, 'allow', 't').severity, 'ok');
  assert.equal(pr.failureResult(Error('Acknowledgement lost; outcome unknown. No automatic retry.')).severity, 'unknown');
  assert.equal(pr.failureResult(Error('not_a_pair: tuples differ')).severity, 'error');
  assert.equal(pr.attemptResult({ phase: 'unknown', message: 'x' }, 'allow').severity, 'unknown');
  assert.equal(pr.attemptResult({ phase: 'acknowledged', message: 'x', scope: 'once' }, 'block').text, 'Denied once');
  const list = [];
  for (let i = 0; i < 60; i++) pr.pushResult(list, { id: String(i), severity: i % 2 ? 'ok' : 'error' });
  assert.equal(list.length, pr.MAX_RESULTS);
  assert.equal(list[0].id, '59', 'newest first');
  assert.equal(pr.needsReview(list), 25);
});

test('main: a valid submission hides the permission window and is tracked; no pair buttons remain', () => {
  const main = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  for (const op of ['backend.decide(d)', 'backend.decidePair(choice)', 'backend.saveRequestRule(choice)', 'backend.requestForAWhile(choice)'])
    assert.match(main, new RegExp(op.replace(/[().]/g, '\\$&') + ';\\n\\s*promptAnswered\\(e\\.sender\\);\\n\\s*return trackResult'), op);
  const src = ['renderer.ts', 'prompt-card.ts', 'local-pair.ts'].map((f) => fs.readFileSync(path.join(__dirname, '../src', f), 'utf8')).join('\n');
  for (const gone of ['Allow both', 'Deny both', 'pairAllow', 'pairBlock', 'buildPairPanel']) assert.ok(!src.includes(gone), gone);
  const backend = fs.readFileSync(path.join(__dirname, '../src/backend.ts'), 'utf8');
  assert.match(backend, /this\.closedEnded\.add\(settlementKey\(c\.generation, c\.id\)\)/, 'saved ended request leaves the queue');
});

test('main: answering clears the input-release guard (a hidden window never reports the release)', () => {
  const main = fs.readFileSync(path.join(__dirname, '../src/main.ts'), 'utf8');
  const answered = main.slice(main.indexOf('function promptAnswered'), main.indexOf('function trackResult'));
  for (const reset of ['promptPointerDown = false', 'pressedPromptKeys.clear()', 'rendererPromptKeys.clear()'])
    assert.ok(answered.includes(reset), reset);
  assert.match(main, /if \(promptIdle\) \{\n\s*if \(!value\.pointerDown\) promptPointerDown = false;/, 'release tracked while idle');
});

test('Permission card: header, IPv6 endpoints verbatim, program side by direction, backend field values', () => {
  assert.equal(ps.connectionHeader({ direction: 'outgoing', protocol: 'udp' }), 'Outgoing connection - UDP(17)');
  assert.equal(ps.connectionHeader({ direction: 'incoming', protocol: 'tcp' }), 'Incoming connection - TCP(6)');
  assert.deepEqual(ps.splitEndpoint('[2a02:810d:4b3f:e100::1a2b]:51234'), { address: '2a02:810d:4b3f:e100::1a2b', port: '51234' });
  assert.deepEqual(ps.splitEndpoint('[fe80::1%enp5s0]:631'), { address: 'fe80::1%enp5s0', port: '631' });
  assert.deepEqual(ps.splitEndpoint('172.30.0.1:53'), { address: '172.30.0.1', port: '53' });
  assert.deepEqual(ps.splitEndpoint('unix'), { address: 'unix', port: '' });
  // Outgoing Proton helper: game on the From side with its socket owner, the service on To.
  const out = ev();
  const s = ps.promptSummary(out, 'x');
  assert.deepEqual(ps.fromTo(out, s), {
    from: { kind: 'program', name: 'Timberborn', owner: 'rundll32.exe' },
    to: { kind: 'peer', text: 'Local printing service (cupsd)' },
  });
  // Incoming: the peer is From, the program To.
  const inc = ev({ flow: { direction: 'incoming', protocol: 'tcp', local: '[::1]:8080', remote: '[::1]:5000' }, local_peer: undefined });
  const t = ps.fromTo(inc, ps.promptSummary(inc, 'x'));
  assert.deepEqual(t.from, { kind: 'peer', text: '::1' });
  assert.equal(t.to.kind, 'program');
  const f = ps.connectionFields(out);
  assert.deepEqual([f.application, f.executable, f.process], ['rundll32.exe', '/w/rundll32.exe', 'Process 7']);
  assert.deepEqual([f.local, f.remote], [{ address: '127.0.0.1', port: '40000' }, { address: '127.0.0.1', port: '631' }]);
  assert.equal(ps.connectionFields(ev({ attribution: { ...ev().attribution, application: undefined, owners: [] } })).process, 'Unavailable');
});
