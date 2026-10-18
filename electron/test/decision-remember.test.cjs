// Synthetic API/receipt faults. Real receiver evidence belongs to isolated journey.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const { validateDecision } = require('../dist/test/protocol.cjs');
const { REMEMBER_ZONE_CAPABILITY } = require('../dist/test/decision-remember.cjs');
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
  } = {},
) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/remember-test-')),
    endpoint = path.join(dir, 's');
  const deadline = new Date(Date.now() + 60000).toISOString();
  let commits = 0,
    previews = 0,
    queries = 0;
  const issued = new Map();
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
    scope_previews: { once: 'Once UDP tuple', application: 'Legacy Any network' },
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
    capabilities: ['explicit-administrator-v1', ...(cap ? [REMEMBER_ZONE_CAPABILITY] : [])],
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
  return { b, d, counts: () => ({ commits, previews, queries }) };
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
