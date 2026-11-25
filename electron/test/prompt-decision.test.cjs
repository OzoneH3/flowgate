// Permission-window decisions: For a while (decision-for-a-while-v1), Remember on
// an ended request (request-application-rule-v1) and the compact card. Synthetic
// sockets and a minimal synthetic DOM only; no daemon, no window.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { validateDecision, parseReply } = require('../dist/test/protocol.cjs');
const lease = require('../dist/test/process-lease.cjs');
const {
  promptPlan,
  liveLeaseReason,
  EndedRuleFlow,
  ENDED_RULE_RESULT,
  ENDED_NEEDS_REMEMBER,
  ENDED_PROCESS,
  shortError,
} = require('../dist/test/prompt-decision.cjs');
const { REQUEST_RULE_CAPABILITY, requestRuleChoice } = require('../dist/test/request-rule.cjs');
const { DEFAULT_REMEMBER, REMEMBER_FIELDS_CAPABILITY } = require('../dist/test/decision-remember.cjs');

const CAPS = ['explicit-administrator-v1', REMEMBER_FIELDS_CAPABILITY, REQUEST_RULE_CAPABILITY, lease.FOR_A_WHILE_CAPABILITY];
const awaitingEvent = (over = {}) => ({
  id: 'e1',
  state: 'awaiting-decision',
  reason: 'initial packets retained within queue bounds while the request awaits a decision',
  deadline: new Date(Date.now() + 60000).toISOString(),
  first_seen: new Date().toISOString(),
  permission: '',
  remainingMs: 60000,
  flow: { direction: 'outgoing', protocol: 'tcp', local: '10.1.0.1:40000', remote: '10.1.0.2:443' },
  attribution: {
    application: { key: '', revision: 'r', name: 'curl', executable: '/usr/lib/very/long/path/bin/curl' },
    owners: [{ pid: 4242, start_ticks: '987654', uid: 1000 }],
    status: 'directly-associated',
    reason: 'socket inode held by exactly one process',
    visibility_complete: true,
  },
  scope_previews: { once: 'Once · this TCP connection', persistent: 'Remember', 'for-a-while': 'This process instance' },
  remembered_filter: { application: 'app', revision: 'r', uid: 1000, direction: 'outgoing', protocol: 'tcp', remote_address: '10.1.0.2', local_port: 0, remote_port: 443 },
  ...over,
});
const endedEvent = (over = {}) =>
  awaitingEvent({
    state: 'expired',
    remainingMs: 0,
    reviewFailure: { code: 'stale_decision', message: 'expired', terminal: true },
    request_rule: { available: true, process_state: 'ended', until: new Date(Date.now() + 600000).toISOString() },
    ...over,
  });
const choice = (over = {}) => ({
  generation: 'g',
  zoneRevision: 'zr',
  capabilities: CAPS,
  forAWhile: false,
  remember: false,
  fields: { ...DEFAULT_REMEMBER },
  duration: 0,
  ...over,
});

test('For a while and Remember are mutually exclusive in both directions (one constant)', () => {
  assert.equal(lease.DECISION_OPTIONS_EXCLUSIVE, true);
  let o = { forAWhile: false, remember: false };
  o = lease.toggleDecisionOption(o, 'remember', true);
  assert.deepEqual(o, { forAWhile: false, remember: true });
  o = lease.toggleDecisionOption(o, 'forAWhile', true);
  assert.deepEqual(o, { forAWhile: true, remember: false });
  o = lease.toggleDecisionOption(o, 'remember', true);
  assert.deepEqual(o, { forAWhile: false, remember: true });
  o = lease.toggleDecisionOption(o, 'remember', false);
  assert.deepEqual(o, { forAWhile: false, remember: false });
  // Flippable: non-exclusive keeps both.
  assert.deepEqual(lease.toggleDecisionOption({ forAWhile: true, remember: false }, 'remember', true, false), {
    forAWhile: true,
    remember: true,
  });
  assert.equal(
    lease.FOR_A_WHILE_TOOLTIP,
    'This process and direction, any TCP/UDP peer. Ends on process exit. No rule saved.',
  );
});

test('decision shapes: plain = Once, For a while = exact for-a-while request, capability gated', () => {
  const e = awaitingEvent();
  assert.deepEqual(promptPlan(e, 'allow', choice()), {
    kind: 'decide',
    decision: { generation: 'g', id: 'e1', action: 'allow', scope: 'once' },
    review: false,
  });
  const p = promptPlan(e, 'block', choice({ forAWhile: true }));
  assert.deepEqual(p, {
    kind: 'decide',
    decision: { generation: 'g', id: 'e1', action: 'block', scope: 'for-a-while' },
    review: false,
  });
  assert.deepEqual(validateDecision(p.decision), p.decision);
  assert.throws(() => validateDecision({ ...p.decision, network_zone: 'any', zone_revision: 'zr' }));
  assert.throws(() => validateDecision({ ...p.decision, remember: DEFAULT_REMEMBER }));
  assert.equal(
    promptPlan(e, 'allow', choice({ forAWhile: true, capabilities: CAPS.filter((c) => c !== lease.FOR_A_WHILE_CAPABILITY) })).kind,
    'unavailable',
  );
  assert.equal(lease.forAWhileSupported(['decision-for-a-while-v1']), true);
  assert.equal(lease.forAWhileSupported([]), false);
  // Remember still is the reviewed rule workflow (application-only by default).
  const r = promptPlan(e, 'allow', choice({ remember: true, duration: 300 }));
  assert.equal(r.kind, 'decide');
  assert.equal(r.review, true);
  assert.equal(r.decision.scope, 'application');
  assert.equal(r.decision.duration_seconds, 300);
  assert.deepEqual(r.decision.remember, DEFAULT_REMEMBER);
});

async function backendFixture(t, { caps = CAPS, decide } = {}) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/for-a-while-test-')),
    endpoint = path.join(dir, 's'),
    sent = [];
  let e = awaitingEvent(),
    leases = [];
  delete e.remainingMs;
  const base = () => ({
    version: 1, generation: 'g', read_only: false, mode: 'daemon-monitor', server_time: new Date().toISOString(),
    capabilities: caps,
    permissions: { role: 'administrator', observation_scope: 'machine', policy_scope: 'machine', can_manage_rules: true, can_decide: true },
    events: e ? [e] : [],
    process_leases: leases,
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw);
      sent.push(q);
      const r = base();
      if (q.operation === 'decide') Object.assign(r, decide(q, { setEvent: (v) => (e = v), setLeases: (v) => (leases = v) }));
      s.end(JSON.stringify(r) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  t.after(() => {
    b.stop();
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { b, sent };
}

test('For a while is sent as exactly {generation,id,action,scope}; leases are listed', async (t) => {
  const until = new Date(Date.now() + 15000).toISOString();
  const { b, sent } = await backendFixture(t, {
    decide: (q, f) => {
      const decided = { ...awaitingEvent(), state: 'allowed', reason: 'for a while', lease: { id: 'L1', until } };
      delete decided.remainingMs;
      f.setEvent(undefined);
      f.setLeases([{ id: 'L1', action: 'allow', direction: 'outgoing', application: 'app', application_name: 'curl', executable: '/usr/bin/curl', uid: 1000, pid: 4242, start: '987654', until, remaining_ms: 15000, seconds: 15, event_id: 'e1' }]);
      return { decision: decided };
    },
  });
  const result = await b.decide({ generation: 'g', id: 'e1', action: 'allow', scope: 'for-a-while' });
  assert.equal(result.phase, 'acknowledged');
  assert.equal(result.scope, 'for-a-while');
  const q = sent.find((x) => x.operation === 'decide');
  assert.deepEqual(q, { version: 1, operation: 'decide', generation: 'g', id: 'e1', action: 'allow', scope: 'for-a-while' });
  await b.pollControl();
  const c = b.view().control;
  assert.equal(c.processLeases.length, 1);
  assert.equal(c.processLeases[0].application, 'curl');
  assert.ok(lease.leaseHolds(c, 'e1'));
  assert.ok(!sent.some((x) => /rule/.test(x.operation)), 'For a while never touches rules');
});

test('For a while: capability absent sends nothing; process_scope_unavailable leaves the request answerable', async (t) => {
  {
    const { b, sent } = await backendFixture(t, { caps: CAPS.filter((c) => c !== lease.FOR_A_WHILE_CAPABILITY), decide: () => ({}) });
    await assert.rejects(b.decide({ generation: 'g', id: 'e1', action: 'allow', scope: 'for-a-while' }), /unsupported/);
    assert.ok(!sent.some((x) => x.operation === 'decide'));
    assert.equal(b.view().control.processLeases, undefined);
  }
  const { b, sent } = await backendFixture(t, {
    decide: (q) =>
      q.scope === 'for-a-while'
        ? { error: 'For a while needs exactly one verified owning process (2 visible)', error_code: 'process_scope_unavailable' }
        : { decision: { ...awaitingEvent(), state: 'allowed', reason: 'once' } },
  });
  await assert.rejects(
    b.decide({ generation: 'g', id: 'e1', action: 'allow', scope: 'for-a-while' }),
    (err) => /^process_scope_unavailable: /.test(err.message),
  );
  assert.equal(b.view().control.events.find((x) => x.id === 'e1').attempt, undefined);
  assert.match(shortError('process_scope_unavailable: x'), /Uncheck it to decide once/);
  // Still answerable once.
  assert.equal((await b.decide({ generation: 'g', id: 'e1', action: 'allow', scope: 'once' })).phase, 'acknowledged');
  assert.equal(sent.filter((x) => x.operation === 'decide').length, 2);
});

test('lease line shows remaining time and disappears at expiry or when the lease vanishes', () => {
  const now = Date.parse('2026-10-19T12:00:00Z');
  const parsed = lease.parseProcessLeases([
    { id: 'L1', action: 'block', direction: 'incoming', application: 'k', application_name: 'curl', executable: '/usr/bin/curl', uid: 1000, pid: 77, start: '55', until: '2026-10-19T12:00:12Z', remaining_ms: 12000, event_id: 'e1' },
    { id: 'L2', action: 'allow', direction: 'outgoing', application: 'k', executable: '/x', uid: 1000, pid: 78, start: '56', until: '2026-10-19T11:59:59Z', remaining_ms: 0, event_id: 'e2' },
    { id: 'bad', action: 'maybe', pid: 1, until: 'x' },
  ]);
  assert.equal(parsed.length, 2, 'malformed entry dropped individually');
  assert.equal(lease.leaseLine(parsed[0], now), 'For a while: Deny · process 77 · In · 12 s left');
  assert.deepEqual(lease.activeLeases(parsed, now).map((l) => l.id), ['L1']);
  assert.deepEqual(lease.activeLeases(parsed, now + 12000), []);
  const details = Object.fromEntries(lease.leaseDetails(parsed[0]));
  assert.equal(details.Application, 'curl');
  assert.equal(details.Executable, '/usr/bin/curl');
  assert.equal(details.Process, 'PID 77 · start 55');
  assert.equal(details.UID, '1000');
  assert.equal(details.Direction, 'Incoming');
  assert.match(details.Expires, /2026-10-19T12:00:12Z/);
  // Card relevance: own decision or the same process instance.
  const e = awaitingEvent({ id: 'other', attribution: { ...awaitingEvent().attribution, owners: [{ pid: 77, start_ticks: '55', uid: 1000 }] } });
  assert.deepEqual(lease.leasesForRequest(parsed, e, now).map((l) => l.id), ['L1']);
  assert.deepEqual(lease.leasesForRequest(parsed, awaitingEvent({ id: 'unrelated' }), now), []);
  // Hold: listed lease, or the decided event's own reference before the next list.
  assert.ok(lease.leaseHolds({ processLeases: parsed, serverNow: now, events: [] }, 'e1'));
  assert.ok(!lease.leaseHolds({ processLeases: parsed, serverNow: now + 12000, events: [] }, 'e1'));
  assert.ok(!lease.leaseHolds({ processLeases: [], serverNow: now, events: [] }, 'e1'), 'vanished lease releases the card');
  assert.ok(lease.leaseHolds({ processLeases: [], serverNow: now, events: [{ id: 'e1', lease: { id: 'L9', until: '2026-10-19T12:00:05Z' } }] }, 'e1'));
  assert.equal(lease.parseProcessLeases('nope'), undefined);
});

test('ended request: Remember + Allow/Deny routes to request-rule with fields and duration preserved', () => {
  const e = endedEvent();
  const fields = { address: true, port: false, protocol: true, process: false };
  const allow = promptPlan(e, 'allow', choice({ remember: true, fields, duration: 3600 }));
  assert.equal(allow.kind, 'request-rule');
  assert.deepEqual(allow.choice, requestRuleChoice({ generation: 'g', id: 'e1', action: 'allow' }, fields, 3600, 'zr'));
  assert.deepEqual(allow.choice.remember, fields);
  assert.equal(allow.choice.duration_seconds, 3600);
  assert.equal(allow.choice.scope, 'application');
  const deny = promptPlan(e, 'block', choice({ remember: true, fields }));
  assert.equal(deny.choice.action, 'block');
  assert.equal(deny.choice.scope, 'persistent');
  // Process cannot apply to an ended instance: explicit, never silently dropped.
  assert.deepEqual(promptPlan(e, 'allow', choice({ remember: true, fields: { ...fields, process: true } })), {
    kind: 'unavailable',
    note: ENDED_PROCESS,
  });
});

test('ended request: plain Allow/Deny and For a while never create a rule or a decision', () => {
  const e = endedEvent();
  for (const action of ['allow', 'block']) {
    assert.deepEqual(promptPlan(e, action, choice()), { kind: 'unavailable', note: ENDED_NEEDS_REMEMBER });
    // Without request-for-a-while-v1 (or with an exited process) For a while is unavailable.
    assert.deepEqual(promptPlan(e, action, choice({ forAWhile: true })), { kind: 'unavailable', note: 'Unavailable: this request has ended.' });
  }
  assert.equal(ENDED_NEEDS_REMEMBER, 'Check Remember to save a rule for future connections.');
  // Without a retained identity nothing at all is possible.
  assert.equal(promptPlan(endedEvent({ request_rule: undefined }), 'allow', choice({ remember: true })).kind, 'unavailable');
});

test('ended request save: exact result text, lost acknowledgement retried with the same token, no duplicate', async () => {
  const rules = new Map(),
    calls = [];
  let lose = 1,
    tokens = 0;
  const bridge = {
    async requestRulePreview(c) {
      calls.push(['preview', c.action]);
      return { token: 'tok-' + ++tokens + '-' + c.action, expires_at: new Date(Date.now() + 20000).toISOString(), event_id: c.id, action: c.action, scope_preview: 'Future connections only', summary: `${c.action === 'allow' ? 'Allow' : 'Deny'} curl · Out · any address`, rule: {}, replaces: null };
    },
    async requestRuleSave(c) {
      calls.push(['save', c.preview_token]);
      const replayed = rules.has(c.preview_token);
      if (!replayed) rules.set(c.preview_token, c);
      if (lose-- > 0) throw Error("Error invoking remote method 'request-rule:save': Error: Save acknowledgement lost; use Check result");
      return { message: 'Saved: …', replayed };
    },
  };
  const flow = new EndedRuleFlow(bridge),
    now = Date.now(),
    c = requestRuleChoice({ generation: 'g', id: 'e1', action: 'allow' }, { ...DEFAULT_REMEMBER, port: true }, 600, 'zr'),
    d = { ...c, action: 'block' };
  assert.equal((await flow.save(c, now)).phase, 'refused', 'never saved without a review');
  await flow.review(c);
  await flow.review(d);
  assert.ok(flow.fresh(c, now) && flow.fresh(d, now));
  const first = await flow.save(c, now);
  assert.equal(first.phase, 'unknown');
  assert.notEqual(first.text, ENDED_RULE_RESULT);
  assert.equal((await flow.save(d, now)).phase, 'refused', 'the other action waits for the unconfirmed save');
  flow.clearReviews(); // review expired / selections re-reviewed: the pinned receipt still wins
  const second = await flow.save(c, now + 60000);
  assert.equal(second.phase, 'saved');
  assert.equal(second.text, 'Rule saved for future connections; this request has ended.');
  assert.equal(ENDED_RULE_RESULT, 'Rule saved for future connections; this request has ended.');
  const third = await flow.save(c, now);
  assert.equal(third.text, ENDED_RULE_RESULT);
  const saves = calls.filter(([k]) => k === 'save');
  assert.equal(saves.length, 2, 'a repeated click after success does not reach the backend');
  assert.ok(saves.every(([, token]) => token === saves[0][1]), 'retry reused the same token');
  assert.equal(rules.size, 1, 'exactly one rule');
  assert.ok(!/allowed/i.test(second.text));
});

// ---- minimal synthetic DOM for the compact card ----
class El {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.parent = null;
    this.text = '';
    this.className = '';
    this.id = '';
    this.dataset = {};
    this.attrs = {};
    this.hidden = false;
    this.title = '';
  }
  set textContent(t) {
    this.children = [];
    this.text = String(t);
  }
  get textContent() {
    return this.text + this.children.map((c) => c.textContent).join('');
  }
  append(...nodes) {
    for (let n of nodes) {
      if (typeof n === 'string') {
        const t = new El('#text');
        t.text = n;
        n = t;
      }
      n.parent = this;
      this.children.push(n);
    }
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }
}
function card(over = {}, options = {}) {
  global.document = { createElement: (t) => new El(t) };
  global.Option = class extends El {
    constructor(label, value) {
      super('option');
      this.text = label;
      this.value = value;
    }
  };
  global.window = { flowgate: { applicationMetadata: async () => ({}) } };
  const { buildRequestCard } = require('../dist/test/prompt-card.cjs');
  const { rememberOptions } = require('../dist/test/decision-remember.cjs');
  const e = awaitingEvent(over);
  const nodes = buildRequestCard(e, { name: 'curl', rememberMode: true, forAWhile: true, rememberOptions: rememberOptions(e, 'curl'), ...options });
  const root = new El('div');
  root.append(...nodes);
  const all = [...root.walk()],
    byId = (id) => all.find((n) => n.id === id);
  return { root, all, byId, e };
}

test('compact card: first view is short, everything technical behind one Details', () => {
  const { root, all, byId, e } = card();
  // Details is a separate view (hidden section of expandable groups) behind one link.
  const view = byId('requestMore');
  assert.equal(view.tagName, 'SECTION');
  assert.ok(view.hidden);
  assert.equal(byId('detailsToggle').text, 'Details');
  assert.ok(all.filter((n) => n.tagName === 'DETAILS').every((d) => [...view.walk()].includes(d)));
  const details = [view];
  const inside = new Set(details[0].walk());
  for (const id of ['rememberSummary', 'requestResult', 'decisionNote', 'decisionReview'])
    assert.ok(inside.has(byId(id)), `${id} stays in Details so outcome updates cannot resize the compact card`);
  const visible = all
    .filter((n) => !inside.has(n))
    .map((n) => n.text)
    .join(' ');
  for (const hidden of [e.attribution.application.executable, '987654', 'UID', e.reason, e.deadline, 'socket inode', 'Once · this TCP connection'])
    assert.ok(!visible.includes(hidden), `compact view hides ${hidden}`);
  const technical = details[0].textContent;
  for (const shown of [e.attribution.application.executable, 'PID 4242 · start 987654 · UID 1000', e.reason, e.deadline, 'socket inode'])
    assert.ok(technical.includes(shown), `Details lists ${shown}`);
  for (const shown of ['Outgoing connection - TCP(6)', 'curl', '10.1.0.2', 'Port:', '443', 'Process 4242'])
    assert.ok(visible.includes(shown), `compact view shows ${shown}`);
  // Decision order: Allow | Deny | Remember | For a while.
  const controls = byId('decisionControls');
  const order = controls.children.map((c) => c.id || c.children.find((x) => x.tagName === 'INPUT')?.id);
  assert.deepEqual(order, ['allow', 'block', 'rememberToggle', 'forAWhileToggle']);
  assert.equal(byId('forAWhileToggle').parent.title, lease.FOR_A_WHILE_TOOLTIP);
  assert.ok(byId('rememberPanel').hidden, 'Remember panel collapsed until checked');
  assert.ok(byId('forAWhileNote').hidden);
  assert.ok(byId('rememberDuration'));
  assert.equal(byId('rememberDuration').children.length, 8, 'all eight expiry durations');
  // Controls and the expiry duration share the sticky dock.
  const dock = byId('decisionDock');
  assert.ok([...dock.walk()].includes(byId('allow')) && [...dock.walk()].includes(byId('rememberDuration')));
  // The ended-request rule section is gone.
  for (const id of ['saveRequestRule', 'requestRuleSection', 'requestRuleAction', 'requestRuleSummary'])
    assert.equal(byId(id), undefined);
  assert.ok(!root.textContent.includes('Save application rule'));
  assert.ok(!root.textContent.includes('Rule for future connections'));
});

test('compact card: For a while absent without the capability', () => {
  const { byId } = card({}, { forAWhile: false });
  assert.equal(byId('forAWhileToggle'), undefined);
  assert.ok(byId('rememberToggle'));
});

test('no Save application rule UI remains in the renderer or style', () => {
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8'),
    css = fs.readFileSync(path.join(__dirname, '../src/style.css'), 'utf8');
  for (const gone of ['saveRequestRule', 'requestRuleSection', 'requestRuleAction', 'Save application rule', 'Rule for future connections'])
    assert.ok(!src.includes(gone), gone);
  assert.ok(!/\.request-rule\b/.test(css));
});

test('permission card keeps countdown and ended status in popup Details', () => {
  const pd = require('../dist/test/prompt-decision.cjs');
  assert.equal(pd.endedStatusLine(pd.ENDED_PROCESS, 'x'), pd.ENDED_PROCESS);
  assert.equal(pd.endedStatusLine('', pd.ENDED_RULE_RESULT), pd.ENDED_RULE_RESULT);
  assert.equal(pd.endedStatusLine(null, undefined), 'This connection has ended.');
  const fs = require('node:fs'), path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  const slot = src.slice(src.indexOf("const expiry = document.querySelector<HTMLElement>('.expiry');"), src.indexOf('measurePrompt();', src.indexOf("const expiry = document.querySelector<HTMLElement>('.expiry');")));
  assert.match(slot, /if \(expiry && \(!keepPresentation \|\| promptID\)\)/);
  assert.match(slot, /endedStatusLine\(\$\('decisionNote'\)\?\.textContent, \$\('requestResult'\)\?\.textContent\)/);
  assert.match(slot, /expiry\.title = endedLine;/);
  assert.doesNotMatch(src, /Allow future connections/);
  assert.ok(!/disabled|onclick|submit/.test(slot));
  const css = fs.readFileSync(path.join(__dirname, '../src/permission-popup.css'), 'utf8');
  assert.match(css, /\.expiry\.ended \{[^}]*white-space: nowrap; overflow: hidden; text-overflow: ellipsis;/);
  // Header build version: no state access before the first publication.
  assert.match(src, /headerVersion\(guiBuild, state\?\.control\.connected \? state\.control\.daemonBuild : undefined\)/);
});

test('attribution categories stay in Details and preserve the original evidence and controls', () => {
  const baseline = card();
  const controls = c => ['allow', 'block', 'rememberToggle', 'forAWhileToggle'].map(id => ({
    id, disabled: !!c.byId(id).disabled, checked: !!c.byId(id).checked,
  }));
  for (const [code, label] of [[undefined, undefined], ['native_owner_observed', 'Native owner observed'], ['future_category', 'Unrecognized attribution category']]) {
    const evidence = { ...awaitingEvent().attribution, reason_code: code };
    const c = card({ attribution: evidence });
    const detail = c.byId('requestMore');
    const category = c.all.find(n => n.tagName === 'DT' && n.textContent === 'Attribution category');
    if (code) {
      assert(category);
      const value = category.parent.children[category.parent.children.indexOf(category) + 1];
      assert.equal(value.textContent, label);
      assert.equal(value.title, code);
      assert([...detail.walk()].includes(category));
    } else assert.equal(category, undefined);
    assert(detail.textContent.includes(evidence.reason));
    assert(detail.textContent.includes(evidence.status));
    assert.deepEqual(controls(c), controls(baseline));
  }
});


test('runtime hints, worker owners and absent lease previews cannot submit a process lease', () => {
  for (const change of [
    e => { e.attribution.permission_target = { kind: 'runtime-unverified', for_a_while: 'Unavailable: runtime execution unverified' }; },
    e => { e.attribution.application.hosted = { state: 'unverified' }; },
    e => { e.attribution.owners[0].thread_group_pid = 1234; },
    e => { delete e.scope_previews['for-a-while']; },
    e => { e.attribution.owners = []; },
  ]) {
    const e = awaitingEvent(); change(e);
    assert.ok(liveLeaseReason(e, CAPS));
    assert.equal(promptPlan(e, 'allow', choice({ forAWhile: true })).kind, 'unavailable');
    assert.equal(promptPlan(e, 'block', choice({ forAWhile: true })).kind, 'unavailable');
    assert.equal(promptPlan(e, 'allow', choice()).decision.scope, 'once');
  }
  const e = awaitingEvent(); e.attribution.owners[0].thread_group_pid = 4242;
  assert.equal(liveLeaseReason(e, CAPS), '');
  assert.equal(promptPlan(e, 'allow', choice({ forAWhile: true, forAWhileSeconds: 3600 })).decision.duration_seconds, 3600);
});


test('wire parsing retains the offered lease scope and the runtime refusal target', () => {
  const raw = awaitingEvent();
  raw.attribution.permission_target = { kind: 'runtime-unverified', label: 'runtime', once: 'Once',
    for_a_while: 'Unavailable: hosted execution unverified', remember: 'Unavailable', key_basis: 'none' };
  const reply = parseReply({ version: 1, generation: 'g', read_only: false, server_time: new Date().toISOString(), events: [raw] });
  assert.equal(reply.events[0].scope_previews['for-a-while'], raw.scope_previews['for-a-while']);
  assert.equal(reply.events[0].attribution.permission_target.kind, 'runtime-unverified');
  assert.match(liveLeaseReason(reply.events[0], CAPS), /Unavailable/);
});

test('unverified runtime process offer survives parsing without enabling application scopes', () => {
 const e = awaitingEvent();
 e.attribution.permission_target = {kind:'runtime-unverified', label:'runtime', remember:'This process only', for_a_while:'This process only'};
 e.scope_previews = {once:'Once', 'process-remember':'Verified process only', 'for-a-while':'Verified process only'};
 const reply = parseReply({version:1,read_only:false,generation:'g',server_time:new Date().toISOString(),events:[e]});
 assert.equal(reply.events[0].scope_previews['process-remember'],'Verified process only');
 assert.equal(reply.events[0].scope_previews.application,undefined);
 assert.equal(liveLeaseReason(reply.events[0],CAPS),'');
 delete reply.events[0].scope_previews['process-remember'];
 assert.notEqual(liveLeaseReason(reply.events[0],CAPS),'');
});
