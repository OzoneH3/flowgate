// Synthetic API/receipt faults. Real receiver evidence belongs to isolated journey.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { validateDecision } = require('../dist/test/protocol.cjs');
const {
  REMEMBER_ZONE_CAPABILITY,
  REMEMBER_FIELDS_CAPABILITY,
  REMEMBER_DURATIONS,
  DEFAULT_REMEMBER,
  rememberDecision,
  rememberKey,
  rememberOptions,
  rememberReviewText,
  rememberFieldsSupported,
  sameRememberedRule,
} = require('../dist/test/decision-remember.cjs');
async function setup(
  t,
  {
    lost = false,
    mismatch = false,
    unknown = false,
    cap = true,
    status = 'committed',
    broader = false,
    wrongExpiry = false,
    fields = false,
    replaces = null,
    ignoreFields = false,
    projected = false,
    receiptProjected = false,
    previewError,
    receiptChecks = [],
    gate,
  } = {},
) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/remember-test-')),
    endpoint = path.join(dir, 's');
  const deadline = new Date(Date.now() + 60000).toISOString();
  let commits = 0,
    previews = 0,
    queries = 0;
  const issued = new Map(),
    sent = [];
  const e = {
    id: 'e',
    state: 'awaiting-decision',
    deadline,
    flow: {
      direction: 'incoming',
      protocol: 'udp',
      local: '10.1.0.1:40',
      remote: '10.1.0.2:50',
      network_scope: unknown
        ? { state: 'unavailable', reason: 'Unknown' }
        : { state: 'known', zone: 'local', revision: 'zr' },
    },
    attribution: {
      application: { key: 'app', revision: 'exe-r', name: 'app', executable: '/test' },
      owners: [],
      status: 'directly-associated',
    },
    scope_previews: {
      once: 'Once UDP tuple',
      application: 'Legacy Any network',
      ...(fields ? { persistent: 'Persistent' } : {}),
    },
    remembered_filter: {
      application: 'app',
      revision: 'exe-r',
      uid: 1000,
      direction: 'incoming',
      protocol: 'udp',
      remote_address: '10.1.0.2',
      remote: '',
      local_port: 40,
      remote_port: 50,
    },
  };
  // Mutable daemon state for in-flight changes (generation, listed requests).
  const fx = { generation: 'g', events: null };
  const base = () => ({
    version: 1,
    generation: fx.generation,
    read_only: false,
    mode: 'daemon-monitor',
    server_time: new Date().toISOString(),
    capabilities: [
      'explicit-administrator-v1',
      ...(cap ? [REMEMBER_ZONE_CAPABILITY] : []),
      ...(fields ? [REMEMBER_FIELDS_CAPABILITY] : []),
    ],
    permissions: {
      role: 'administrator',
      observation_scope: 'machine',
      policy_scope: 'machine',
      can_manage_rules: true,
      can_decide: true,
    },
    network_zones: {
      model: 'configured-prefix-v1',
      revision: 'zr',
      local_prefixes: ['10.1.0.0/24'],
      internet_prefixes: [],
      reason: 'Test',
    },
    events: fx.events ?? [e],
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw),
        r = base();
      sent.push(q);
      if (q.operation === 'decision-preview') {
        previews++;
        if (previewError) {
          s.end(JSON.stringify({ ...r, error_code: Array.isArray(previewError) ? previewError[Math.min(previews-1, previewError.length-1)] : previewError, error: 'Exact revalidation refusal' }) + '\n');
          return;
        }
        const rule = {
          id: 'reserved-' + previews,
          version: 1,
          schema: q.network_zone === 'any' ? 2 : 4,
          executable: '/test',
          created: new Date().toISOString(),
          action: q.action,
          disabled: false,
          expires: new Date(Date.now() + 3600000).toISOString(),
          priority: 100,
          filter: {
            application: 'app',
            revision: 'exe-r',
            uid: 1000,
            direction: 'incoming',
            protocol: 'udp',
            remote_address: '10.1.0.2',
            local_port: 40,
            remote_port: 50,
            ...(q.network_zone === 'any' ? {} : { network_zone: q.network_zone }),
          },
        };
        if (broader) {
          rule.filter.remote_address = '*';
          rule.filter.local_port = 0;
        }
        if (wrongExpiry) rule.expires = '0001-01-01T00:00:00Z';
        if (q.remember && !ignoreFields) {
          if (!q.remember.address) rule.filter.remote_address = '*';
          if (!q.remember.port) rule.filter.local_port = rule.filter.remote_port = 0;
          if (!q.remember.protocol) rule.filter.protocol = '*';
          rule.expires =
            q.scope === 'persistent'
              ? '0001-01-01T00:00:00Z'
              : new Date(Date.parse(rule.created) + q.duration_seconds * 1000).toISOString();
        }
        if (replaces) {
          rule.id = replaces.id;
          rule.version = replaces.version + 1;
        }
        const p = {
          token: 'token-' + previews,
          expires_at: new Date(Date.now() + 20000).toISOString(),
          event_id: 'e',
          action: q.action,
          scope: q.scope,
          network_zone: mismatch ? 'internet' : q.network_zone,
          zone_revision: 'zr',
          generation: 'g',
          scope_preview: 'Exact backend review',
          connection_network: e.flow.network_scope,
          rule,
          ...(q.remember
            ? {
                remember: q.remember,
                duration_seconds: q.duration_seconds,
                summary: `${q.action === 'allow' ? 'Allow' : 'Deny'} app · In · any address · any port · TCP+UDP · all zones · persistent`,
                replaces,
              }
            : {}),
        };
        issued.set(p.token, p);
        r.decision_preview = p;
      } else if (q.operation === 'decide') {
        commits++;
        const p = issued.get(q.preview_token);
        r.decision = { ...e, state: q.action === 'allow' ? 'allowed' : 'blocked' };
        r.saved_rule = projected ? { ...p?.rule, follows_updates: true } : p?.rule;
        if (lost) {
          s.destroy();
          return;
        }
      } else if (q.operation === 'decision-status') {
        queries++;
        const p = issued.get(q.preview_token);
        if (gate) {
          // The test decides when (and with which state) this reply is sent.
          gate(queries).then((state) => {
            if (state === 'drop') return void s.destroy(); // reply lost
            const g = base();
            g.decision_receipt = { state, preview: p, ...(state === 'committed' ? { decision: { ...e, state: 'allowed' }, saved_rule: p.rule } : {}) };
            s.end(JSON.stringify(g) + '\n');
          });
          return;
        }
        r.decision_receipt = {
          state: status,
          preview: p,
          ...(status === 'committed'
            ? { decision: { ...e, state: 'allowed' }, saved_rule: receiptProjected ? { ...p.rule, follows_updates: true } : p.rule }
            : {}),
        };
      }
      s.end(JSON.stringify(r) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, () => {});
  // Automatic receipt checks are opted into per test (deterministic counts).
  b.receiptCheckDelays = receiptChecks;
  await b.pollControl();
  t.after(() => {
    b.stop();
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const d = {
    generation: 'g',
    id: 'e',
    action: 'allow',
    scope: 'application',
    network_zone: 'local',
    zone_revision: 'zr',
  };
  return { b, d, e, fx, sent, counts: () => ({ commits, previews, queries }) };
}
test('zone choice is previewed once, exact reviewed rule is committed', async (t) => {
  const { b, d, counts } = await setup(t);
  const p = await b.previewDecision(d);
  assert.equal((await b.previewDecision(d)).token, p.token);
  const result = await b.decide({ ...d, preview_token: p.token });
  assert.equal(result.phase, 'acknowledged');
  assert.equal(result.rule.filter.network_zone, 'local');
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 0 });
  await assert.rejects(() => b.decide({ ...d, preview_token: p.token }));
});
test('wrong preview zone and unknown connection cannot create named permission', async (t) => {
  const a = await setup(t, { mismatch: true });
  await assert.rejects(() => a.b.previewDecision(a.d));
  assert.equal(a.counts().commits, 0);
  const b = await setup(t, { unknown: true });
  await assert.rejects(() => b.b.previewDecision(b.d));
  assert.equal(b.counts().previews, 0);
});
test('capability absence refuses new fields; Once never carries zone/token', async (t) => {
  const { b, d, counts } = await setup(t, { cap: false });
  await assert.rejects(() => b.previewDecision(d));
  assert.throws(() => validateDecision({ ...d, scope: 'once' }));
  assert.equal(counts().commits, 0);
});
test('lost ACK receipt resolves original outcome without resending Decide', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true });
  const p = await b.previewDecision(d);
  assert.equal((await b.decide({ ...d, preview_token: p.token })).phase, 'unknown');
  await b.pollControl();
  const result = await b.reconcileDecision({ generation: 'g', id: 'e', preview_token: p.token });
  assert.equal(result.phase, 'acknowledged');
  assert.equal(result.rule.id, p.rule.id);
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 1 });
});
const attemptOf = (b) => b.view().control.events.find((x) => x.id === 'e')?.attempt;
const until = async (fn, label) => {
  for (let i = 0; i < 400; i++) { if (fn()) return; await new Promise((r) => setImmediate(r)); await new Promise((r) => setTimeout(r, 1)); }
  throw Error('condition not reached: ' + label);
};
// A test-controlled reply: gate(n) returns a promise released by hand.
const gates = () => {
  const held = [];
  return { held, gate: (n) => new Promise((release) => held.push({ n, release })) };
};
const rememberAny = { address: true, port: false, protocol: false, process: false };
test('lost Remember acknowledgement is confirmed automatically from its receipt, never resent', async (t) => {
  const { b, d, counts } = await setup(t, { fields: true, lost: true, receiptChecks: [0, 0, 0] });
  const choice = { ...d, scope: 'persistent', network_zone: 'any', remember: rememberAny };
  const p = await b.previewDecision(choice);
  const first = await b.decide({ ...choice, preview_token: p.token });
  assert.equal(first.phase, 'unknown');
  assert.equal(first.reconcile, p.token);
  await b.receiptChecksSettled();
  const a = attemptOf(b);
  assert.equal(a.phase, 'acknowledged');
  assert.equal(a.rule.id, p.rule.id);
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 1 });
});
test('automatic receipt check keeps a still-pending outcome unknown (bounded, no resend)', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true, status: 'pending', receiptChecks: [0, 0, 0] });
  const p = await b.previewDecision(d);
  assert.equal((await b.decide({ ...d, preview_token: p.token })).phase, 'unknown');
  await b.receiptChecksSettled();
  const a = attemptOf(b);
  assert.equal(a.phase, 'unknown');
  assert.equal(a.reconcile, p.token); // Check result remains available
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 3 });
});
test('automatic receipt check stops on a receipt that does not match the review', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true, status: 'unexpected', receiptChecks: [0, 0, 0] });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  await b.receiptChecksSettled();
  assert.equal(attemptOf(b).phase, 'unknown');
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 1 });
});
test('a late pending receipt never overwrites a confirmation (automatic and manual overlap)', async (t) => {
  const g = gates();
  const { b, d, counts } = await setup(t, { lost: true, receiptChecks: [0], gate: g.gate });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  await until(() => g.held.length === 1, 'automatic query in flight');
  const manual = b.reconcileDecision({ generation: 'g', id: 'e', preview_token: p.token });
  await until(() => g.held.length === 2, 'manual query in flight');
  g.held[1].release('committed');
  assert.equal((await manual).phase, 'acknowledged');
  g.held[0].release('pending'); // the older reply arrives last
  await b.receiptChecksSettled();
  assert.equal(attemptOf(b).phase, 'acknowledged');
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 2 });
});
test('a receipt arriving after a generation change, removal or stop records nothing', async (t) => {
  for (const change of ['generation', 'removed', 'stopped']) {
    const g = gates();
    const x = await setup(t, { lost: true, receiptChecks: [0], gate: g.gate });
    const p = await x.b.previewDecision(x.d);
    await x.b.decide({ ...x.d, preview_token: p.token });
    await until(() => g.held.length === 1, change + ': query in flight');
    if (change === 'generation') { x.fx.generation = 'g2'; await x.b.pollControl(); }
    if (change === 'removed') { x.fx.events = []; await x.b.pollControl(); }
    if (change === 'stopped') x.b.stop();
    g.held[0].release('committed');
    await x.b.receiptChecksSettled();
    const a = attemptOf(x.b);
    assert.ok(!a || a.phase !== 'acknowledged', change + ': stale receipt revived the card');
    assert.equal(x.counts().commits, 1, change);
  }
});
test('an unreadable receipt reply is retried within the bound, then confirms', async (t) => {
  const g = gates();
  const { b, d, counts } = await setup(t, { lost: true, receiptChecks: [0, 0, 0], gate: g.gate });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  await until(() => g.held.length === 1, 'first query');
  g.held[0].release('drop'); // reply lost while connected (slow/failed transport)
  await until(() => g.held.length === 2, 'second query after an unreadable reply');
  g.held[1].release('committed');
  await b.receiptChecksSettled();
  assert.equal(attemptOf(b).phase, 'acknowledged');
  assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 2 });
});
test('a receipt query failing after stop schedules no further check', async (t) => {
  const g = gates();
  const { b, d, counts } = await setup(t, { lost: true, receiptChecks: [0, 60000], gate: g.gate });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  await until(() => g.held.length === 1, 'query in flight');
  b.stop();
  b.state.control.connected = false; // the path that used to keep retrying
  g.held[0].release('drop');
  await b.receiptChecksSettled(); // would wait 60 s if a new delay were scheduled
  assert.equal(b.receiptWaits.size, 0);
  assert.equal(counts().queries, 1);
  assert.equal(attemptOf(b).phase, 'unknown');
});
test('a decision answered after stop starts no receipt check', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true, receiptChecks: [0] });
  const p = await b.previewDecision(d);
  const pending = b.decide({ ...d, preview_token: p.token });
  b.stop();
  await pending;
  await b.receiptChecksSettled();
  assert.equal(b.receiptChecks.size, 0);
  assert.equal(counts().queries, 0);
});
test('stop cancels a scheduled receipt check before any query', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true, receiptChecks: [60000] });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  b.stop();
  await b.receiptChecksSettled(); // resolves now, not after 60 s
  assert.equal(counts().queries, 0);
});
test('pending receipt stays unknown, changed token/action cannot be committed', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true, status: 'pending' });
  const p = await b.previewDecision(d);
  await assert.rejects(() => b.decide({ ...d, action: 'block', preview_token: p.token }));
  await b.decide({ ...d, preview_token: p.token });
  await b.pollControl();
  assert.equal(
    (await b.reconcileDecision({ generation: 'g', id: 'e', preview_token: p.token })).phase,
    'unknown',
  );
  assert.equal(counts().commits, 1);
});
test('expired review needs explicit fresh preview and cannot save old token', async (t) => {
  const { b, d, counts } = await setup(t);
  const p = await b.previewDecision(d),
    now = b.now.bind(b);
  b.now = () => now() + 25000;
  await assert.rejects(() => b.decide({ ...d, preview_token: p.token }));
  assert.equal(counts().commits, 0);
});
test('receipt query refuses foreign request or token before transport', async (t) => {
  const { b, d, counts } = await setup(t, { lost: true });
  const p = await b.previewDecision(d);
  await b.decide({ ...d, preview_token: p.token });
  await assert.rejects(() =>
    b.reconcileDecision({ generation: 'g', id: 'other', preview_token: p.token }),
  );
  await assert.rejects(() =>
    b.reconcileDecision({ generation: 'g', id: 'e', preview_token: 'other' }),
  );
  assert.equal(counts().queries, 0);
});

test('preview cannot broaden backend remembered peer/service or change lifetime', async (t) => {
  for (const options of [{ broader: true }, { wrongExpiry: true }]) {
    const x = await setup(t, options);
    await assert.rejects(() => x.b.previewDecision(x.d));
    assert.equal(x.counts().commits, 0);
  }
});

const base = { generation: 'g', id: 'e', action: 'allow' };
const fieldsDecision = (choice, action = 'allow') =>
  rememberDecision({ ...base, action }, choice, 'zr');
test('Remember defaults to the application only and No expiry = persistent', () => {
  assert.deepEqual(DEFAULT_REMEMBER, {
    address: false,
    port: false,
    protocol: false,
    process: false,
  });
  const d = fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 });
  assert.deepEqual(d, {
    generation: 'g',
    id: 'e',
    action: 'allow',
    scope: 'persistent',
    network_zone: 'any',
    zone_revision: 'zr',
    remember: { address: false, port: false, protocol: false, process: false },
  });
  assert.equal('duration_seconds' in d, false);
  assert.deepEqual(validateDecision(d), d);
});
test('each Create rule for checkbox maps to exactly its request field', () => {
  for (const field of ['address', 'port', 'protocol', 'process']) {
    const d = fieldsDecision({ fields: { ...DEFAULT_REMEMBER, [field]: true }, duration: 0 });
    for (const k of ['address', 'port', 'protocol', 'process'])
      assert.equal(d.remember[k], k === field, field + ' -> ' + k);
  }
});
test('the eight expiry durations map to scope and duration_seconds', () => {
  assert.deepEqual(
    REMEMBER_DURATIONS.map((d) => [d.label, d.seconds]),
    [
      ['No expiry', 0],
      ['1 minute', 60],
      ['5 minutes', 300],
      ['10 minutes', 600],
      ['30 minutes', 1800],
      ['1 hour', 3600],
      ['6 hours', 21600],
      ['12 hours', 43200],
    ],
  );
  for (const { seconds } of REMEMBER_DURATIONS.slice(1)) {
    const d = fieldsDecision({ fields: DEFAULT_REMEMBER, duration: seconds });
    assert.equal(d.scope, 'application');
    assert.equal(d.duration_seconds, seconds);
    validateDecision(d);
  }
  assert.throws(() => fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 120 }));
  // Contract shape is enforced before transport.
  const d = fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 });
  assert.throws(() => validateDecision({ ...d, duration_seconds: 60 }));
  assert.throws(() => validateDecision({ ...d, scope: 'application' }));
  assert.throws(() => validateDecision({ ...d, scope: 'once' }));
  assert.throws(() => validateDecision({ ...d, remember: { address: true } }));
  assert.throws(() =>
    validateDecision({
      generation: 'g',
      id: 'e',
      action: 'allow',
      scope: 'once',
      remember: d.remember,
    }),
  );
});
test('any checkbox or expiry-duration change invalidates the reviewed preview', () => {
  const choice = { fields: DEFAULT_REMEMBER, duration: 0 },
    keys = new Set([rememberKey(choice)]);
  for (const k of ['address', 'port', 'protocol', 'process'])
    keys.add(rememberKey({ ...choice, fields: { ...DEFAULT_REMEMBER, [k]: true } }));
  for (const { seconds } of REMEMBER_DURATIONS.slice(1))
    keys.add(rememberKey({ ...choice, duration: seconds }));
  assert.equal(keys.size, 1 + 4 + 7);
});
test('Create rule for labels follow the request (incoming uses the local service port)', () => {
  const event = (direction, owners) => ({
    flow: {
      direction,
      protocol: 'tcp',
      local: '10.0.0.1:40',
      remote: '[2001:db8::2]:443',
    },
    attribution: { owners, visibility_complete: true },
  });
  const out = rememberOptions(event('outgoing', [{ pid: 1260 }]), 'curl');
  assert.deepEqual(
    out.map((o) => [o.field, o.label, o.available]),
    [
      ['application', 'curl', true],
      ['protocol', 'TCP', true],
      ['process', 'Process 1260', true],
      ['address', 'Remote address 2001:db8::2', true],
      ['port', 'Remote port 443', true],
    ],
  );
  const inc = rememberOptions(event('incoming', []), 'srv');
  assert.equal(inc.find((o) => o.field === 'port').label, 'Local port 40');
  assert.equal(inc.find((o) => o.field === 'process').available, false);
});
test('fields capability: application-only Remember previews, shows summary and commits exactly', async (t) => {
  const { b, sent, counts } = await setup(t, { fields: true });
  assert.equal(rememberFieldsSupported(b.view().control.capabilities), true);
  const d = fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 });
  const p = await b.previewDecision(d);
  assert.equal(p.rule.filter.remote_address, '*');
  assert.equal(p.rule.filter.protocol, '*');
  assert.deepEqual(p.remember, d.remember);
  const block = await b.previewDecision(
    fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 }, 'block'),
  );
  assert.match(rememberReviewText(p, block), /^Rule: app · In · any address/);
  const result = await b.decide({ ...d, preview_token: p.token });
  assert.equal(result.phase, 'acknowledged');
  const decide = sent.find((q) => q.operation === 'decide');
  assert.deepEqual(decide.remember, d.remember);
  assert.equal(decide.network_zone, 'any');
  assert.equal('duration_seconds' in decide, false);
  assert.equal(counts().commits, 1);
});
test('temporary Remember sends duration_seconds; changed choice cannot reuse a token', async (t) => {
  const { b, sent, counts } = await setup(t, { fields: true });
  const d = fieldsDecision({ fields: { ...DEFAULT_REMEMBER, address: true }, duration: 300 });
  const p = await b.previewDecision(d);
  assert.equal(p.rule.filter.remote_address, '10.1.0.2');
  assert.equal(sent.at(-1).duration_seconds, 300);
  const changed = fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 300 });
  await assert.rejects(() => b.decide({ ...changed, preview_token: p.token }));
  const longer = fieldsDecision({ fields: { ...DEFAULT_REMEMBER, address: true }, duration: 600 });
  await assert.rejects(() => b.decide({ ...longer, preview_token: p.token }));
  assert.equal(counts().commits, 0);
  assert.equal((await b.decide({ ...d, preview_token: p.token })).phase, 'acknowledged');
});
test('preview that ignores the chosen fields is refused', async (t) => {
  const { b, counts } = await setup(t, { fields: true, ignoreFields: true });
  await assert.rejects(() =>
    b.previewDecision(fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 })),
  );
  assert.equal(counts().commits, 0);
});
test('preview replacing a rule is shown as update; the event Ask rule as Ask replacement', async (t) => {
  const { b } = await setup(t, { fields: true, replaces: { id: 'user:ask', version: 2 } });
  const allow = await b.previewDecision(fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 }));
  const block = await b.previewDecision(
    fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 }, 'block'),
  );
  assert.equal(allow.rule.version, 3);
  assert.match(
    rememberReviewText(allow, block, { id: 'user:ask', version: 2 }),
    /replaces Ask rule user:ask \(Ask → Allow\/Deny\)$/,
  );
  assert.match(rememberReviewText(allow, block), /updates existing rule user:ask$/);
  assert.equal(rememberReviewText(allow, undefined), '');
});
test('without decision-remember-fields-v1 Remember fields are refused (legacy path kept)', async (t) => {
  const { b, d, counts } = await setup(t);
  assert.equal(rememberFieldsSupported(b.view().control.capabilities), false);
  await assert.rejects(() =>
    b.previewDecision(fieldsDecision({ fields: DEFAULT_REMEMBER, duration: 0 })),
  );
  const p = await b.previewDecision(d);
  assert.equal((await b.decide({ ...d, preview_token: p.token })).phase, 'acknowledged');
  assert.equal(counts().commits, 1);
});

test('terminal preview refusal stays bound to original request through stale polling; no Once fallback', async (t) => {
  const { b, d, counts } = await setup(t, { previewError: 'identity_changed' });
  await assert.rejects(() => b.previewDecision(d), /Exact revalidation refusal/);
  let e = b.view().control.events.find(e => e.id === d.id);
  assert.deepEqual(e.reviewFailure, { code: 'identity_changed', message: 'Exact revalidation refusal', terminal: true });
  assert.equal(e.attempt, undefined, 'preview failure must not pretend a decision was submitted');
  await b.pollControl();
  e = b.view().control.events.find(e => e.id === d.id);
  assert.equal(e.reviewFailure.code, 'identity_changed');
  await assert.rejects(() => b.previewDecision(d), /no longer actionable/);
  await assert.rejects(() => b.decide({ generation: d.generation, id: d.id, action: 'allow', scope: 'once' }));
  assert.equal(counts().previews, 1);
  assert.equal(counts().commits, 0);
  b.reply.events = [];
  assert.equal(b.view().control.events[0].attribution.application.key, 'app');
  b.state.control.generation = 'new';
  assert.equal(b.view().control.events.length, 0, 'no cross-generation old details');
});
test('recoverable review conflict does not terminally disable a valid pending request', async (t) => {
  const { b, d, counts } = await setup(t, { previewError: 'policy_conflict' });
  await assert.rejects(() => b.previewDecision(d));
  assert.equal(b.view().control.events[0].reviewFailure, undefined);
  await assert.rejects(() => b.previewDecision(d));
  assert.equal(counts().previews, 2);
});
test('review lifecycle wording never calls an unknown fingerprint mismatch an executable change', () => {
  const { terminalReviewFailure, reviewFailureSummary } = require('../dist/test/decision-remember.cjs');
  assert.match(reviewFailureSummary(terminalReviewFailure('connection_ended', 'Socket closed')), /Connection ended/);
  assert.match(reviewFailureSummary(terminalReviewFailure('identity_changed', 'Mismatch')), /can no longer be verified/);
  assert.equal(terminalReviewFailure('zone_conflict', 'Re-review'), undefined);
});

test('future application source uses a fresh sibling observation, never the old PID or display label', () => {
  const { freshApplicationRuleSource } = require('../dist/test/decision-remember.cjs');
  const now = new Date().toISOString();
  const app = { key: 'app', revision: 'r', executable: '/test', name: 'original' };
  const original = {
    id: 'old', state: 'expired', flow: { direction: 'outgoing' },
    attribution: { application: app, owners: [{ pid: 10, start_ticks: 'old' }] },
    remembered_filter: { uid: 1000 },
  };
  const p = { id: '20:new', pid: 20, uid: 1000, application: { ...app, name: 'friendly' } };
  const socket = { id: 'new-socket', owners: [p.id], ownership_category: 'visible-holder' };
  const state = {
    observation: { connected: true, generation: 'g', activity: { sequence: 1, collected: now, rows: [socket], processes: { [p.id]: p } } },
    control: {
      connected: true, readOnly: false, generation: 'g', mode: 'daemon-monitor', serverNow: Date.parse(now),
      capabilities: ['explicit-administrator-v1', 'observed-rule-create-v1'],
      permissions: { role: 'administrator', can_manage_rules: true },
      policy: {
        snapshot: { generation: 'g', valid_until: new Date(Date.now()+30000).toISOString() },
        activity_available: true, activity_sequence: '1', activity_collected: now,
        applications: [{ ref: 'a', identity: { key: 'app', revision: 'r', uid: 1000 }, process_ids: [p.id] }],
        rows: [{ row_id: socket.id, status: 'observed_native', application_ref: 'a' }],
      },
    },
  };
  assert.deepEqual(freshApplicationRuleSource(state, original), {
    generation: 'g', row_id: 'new-socket', process_id: '20:new', direction: 'outgoing', target_scope: 'application',
  });
  p.application = { ...app, revision: 'replacement' };
  assert.equal(freshApplicationRuleSource(state, original), undefined);
  p.application = { ...app }; p.uid = 1001;
  assert.equal(freshApplicationRuleSource(state, original), undefined);
  p.uid = 1000; socket.owners.push('shared');
  assert.equal(freshApplicationRuleSource(state, original), undefined);
  socket.owners.pop(); state.control.policy.snapshot.generation = 'other';
  assert.equal(freshApplicationRuleSource(state, original), undefined);
});

test('paired previews retain the precise closure cause instead of a generic subsequent stale reply', async (t) => {
  const { b, d } = await setup(t, { previewError: ['connection_ended', 'stale_decision'] });
  await Promise.allSettled([b.previewDecision(d), b.previewDecision({ ...d, action: 'block' })]);
  assert.equal(b.view().control.events[0].reviewFailure.code, 'connection_ended');
});

test('Wine table broker is never offered as the Windows process-scoped target',()=>{
 const e={flow:{direction:'outgoing',protocol:'tcp',local:'127.0.0.1:4000',remote:'127.0.0.1:80'},attribution:{owners:[{pid:42}],visibility_complete:true,runtime_table:{broker_pid:42}}};
 assert.equal(rememberOptions(e,'Alpha.exe').find(o=>o.field==='process').available,false);
});

test('IP-specific Remember accepts a saved-rule acknowledgement with derived update metadata', async (t) => {
 const { b, d, counts } = await setup(t, { fields: true, projected: true });
 const choice = { ...d, remember: { address: true, port: false, protocol: false, process: false }, duration_seconds: 3600 };
 const p = await b.previewDecision(choice);
 assert.equal(p.rule.filter.remote_address, '10.1.0.2');
 const result = await b.decide({ ...choice, preview_token: p.token });
 assert.equal(result.phase, 'acknowledged', result.message);
 assert.equal(result.rule.filter.remote_address, '10.1.0.2');
 assert.equal(result.rule.follows_updates, true);
 assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 0 });
});

test('lost IP-specific Remember acknowledgement reconciles projected receipt without another save', async (t) => {
 const { b, d, counts } = await setup(t, { fields: true, lost: true, receiptProjected: true });
 const choice = { ...d, remember: { address: true, port: false, protocol: false, process: false }, duration_seconds: 3600 };
 const p = await b.previewDecision(choice);
 assert.equal((await b.decide({ ...choice, preview_token: p.token })).phase, 'unknown');
 const receipt = await b.reconcileDecision({ generation: 'g', id: 'e', preview_token: p.token });
 assert.equal(receipt.phase, 'acknowledged');
 assert.equal(receipt.rule.filter.remote_address, '10.1.0.2');
 assert.deepEqual(counts(), { commits: 1, previews: 1, queries: 1 });
});

test('Remember acknowledgement comparison ignores only the derived update label', async (t) => {
 const { b, d } = await setup(t, { fields: true });
 const p = await b.previewDecision({ ...d, remember: { address: true, port: true, protocol: true, process: false }, duration_seconds: 3600 });
 const projected = { ...p.rule, follows_updates: true };
 assert.equal(sameRememberedRule(projected, p.rule), true);
 for (const patch of [
  { action: 'block' }, { priority: 101 }, { disabled: true },
  { expires: '0001-01-01T00:00:00Z' }, { share_with_root: true },
  { root_application: 'root-key' }, { id: 'other' }, { version: 2 },
  ...Object.entries({ application: 'other', revision: 'other', uid: 0, direction: 'outgoing', protocol: '*', remote_address: '*', local_port: 0, remote_port: 0, network_zone: 'internet' })
    .map(([field,value]) => ({ filter: { ...p.rule.filter, [field]: value } })),
 ]) {
  assert.equal(sameRememberedRule({ ...projected, ...patch }, p.rule), false, JSON.stringify(patch));
 }
});
