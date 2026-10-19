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
  const base = () => ({
    version: 1,
    generation: 'g',
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
    events: [e],
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw),
        r = base();
      sent.push(q);
      if (q.operation === 'decision-preview') {
        previews++;
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
        r.saved_rule = p?.rule;
        if (lost) {
          s.destroy();
          return;
        }
      } else if (q.operation === 'decision-status') {
        queries++;
        const p = issued.get(q.preview_token);
        r.decision_receipt = {
          state: status,
          preview: p,
          ...(status === 'committed'
            ? { decision: { ...e, state: 'allowed' }, saved_rule: p.rule }
            : {}),
        };
      }
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
  const d = {
    generation: 'g',
    id: 'e',
    action: 'allow',
    scope: 'application',
    network_zone: 'local',
    zone_revision: 'zr',
  };
  return { b, d, e, sent, counts: () => ({ commits, previews, queries }) };
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
test('Remember defaults to the application only and Do not delete = persistent', () => {
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
test('the eight deletion times map to scope and duration_seconds', () => {
  assert.deepEqual(
    REMEMBER_DURATIONS.map((d) => [d.label, d.seconds]),
    [
      ['Do not delete', 0],
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
test('any checkbox or deletion-time change invalidates the reviewed preview', () => {
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
