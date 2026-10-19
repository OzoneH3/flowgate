const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { ZoneMigration, parseZoneMigration } = require('../dist/test/zone-migration.cjs');
const { parseRule } = require('../dist/test/protocol.cjs');
const {
  parseNetworkZones,
  zoneRuleLabel,
  zoneDefinitionDetails,
} = require('../dist/test/network-zones.cjs');
const base = () => ({
  id: 'legacy',
  version: 3,
  schema: 4,
  created: '2026-01-01T00:00:00Z',
  expires: '2027-01-01T00:00:00Z',
  executable: '/native/app',
  action: 'allow',
  disabled: false,
  priority: 42,
  filter: {
    application: 'app',
    revision: 'rev',
    uid: 1000,
    direction: 'outgoing',
    protocol: 'tcp',
    remote_address: '1.2.3.4',
    local_port: 0,
    remote_port: 443,
    network_zone: 'internet',
  },
});
const target = { generation: 'g', id: 'legacy', version: 3 };
const config = {
  model: 'automatic-peer-v1',
  revision: 'z1',
  registry_version: 'iana1',
  network_revision: 'net1',
  network_state: 'available',
  local_prefixes: [],
  internet_prefixes: [],
  reason: 'Backend evidence',
};
const candidate = (r) => ({
  ...structuredClone(r),
  version: r.version + 1,
  schema: 6,
  filter: { ...r.filter, zone_model: 'automatic-peer-v1' },
});
const preview = (r) => ({
  token: 'token',
  expires_at: new Date(Date.now() + 30000).toISOString(),
  rule_id: r.id,
  old_version: r.version,
  zone_revision: 'z1',
  old_model: 'configured-prefix-v1',
  new_model: 'automatic-peer-v1',
  old_prefixes: ['1.2.3.0/24'],
  new_prefixes: ['0.0.0.0/0'],
  added_prefixes: ['0.0.0.0/1'],
  removed_prefixes: [],
  samples: [
    { address: '1.2.3.4', old_zone: 'internet', new_zone: 'internet', reason: 'Backend reason' },
  ],
  scope_preview: 'Exact backend scope; future updates apply',
  rule: candidate(r),
});
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/zm-')),
    socket = path.join(dir, 's');
  const original = base(),
    c = {
      connected: true,
      readOnly: false,
      generation: 'g',
      permissions: { can_manage_rules: true, can_manage_machine_rules: true },
      capabilities: ['zone-migration-v1', 'automatic-network-zones-v1'],
      networkZones: structuredClone(config),
      rules: [original],
    };
  const f = { c, original, requests: [], mode: 'normal', hold: undefined, inventory: undefined };
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      f.requests.push(q);
      const response = () => {
        const body = {
          version: 1,
          generation: 'g',
          read_only: false,
          mode: 'host-enforcement',
          server_time: new Date().toISOString(),
        };
        if (q.operation === 'zone-migration-preview') body.zone_migration = f.p = preview(original);
        if (q.operation === 'zone-migration-save') {
          f.inventory = candidate(original);
          if (f.mode === 'lost') {
            s.destroy();
            return;
          }
          body.saved_rule = structuredClone(f.inventory);
          body.scope_preview = f.p.scope_preview;
          if (f.mode === 'widen') body.saved_rule.filter.remote_address = '*';
        }
        if (q.operation === 'list') body.rules = f.inventory ? [f.inventory] : [];
        s.end(JSON.stringify(body) + '\n');
      };
      if (q.operation === 'zone-migration-preview' && f.mode === 'hold') f.hold = response;
      else response();
    }),
  );
  await new Promise((r) => server.listen(socket, r));
  const backend = {
    controller: socket,
    now: () => Date.now(),
    view: () => ({ control: c }),
    ruleMutation: async (fn) => fn(),
  };
  f.service = new ZoneMigration(backend);
  t.after(async () => {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return f;
}
test('parser preserves legacy4 model absence, schema6 explicit model and automatic metadata without inventing Internet coverage', () => {
  const old = parseRule(base());
  assert.equal(old.schema, 4);
  assert(!('zone_model' in old.filter));
  const current = parseRule(candidate(base()));
  assert.equal(current.filter.zone_model, 'automatic-peer-v1');
  assert.throws(() => parseRule({ ...base(), schema: 6 }));
  assert.throws(() =>
    parseRule({ ...base(), filter: { ...base().filter, zone_model: 'unknown' } }),
  );
  assert.deepEqual(parseNetworkZones(config), config);
  assert.match(zoneRuleLabel(old), /legacy/);
  assert.match(zoneRuleLabel(current), /automatic/);
  assert.match(zoneDefinitionDetails(config), /overrides, not exhaustive/);
});
test('migration rejects widened identity, endpoint, action, absolute expiry and version before confirmation', () => {
  const now = Date.now();
  assert.equal(parseZoneMigration(preview(base()), base(), target, 'z1', now).rule.version, 4);
  for (const mutate of [
    (r) => (r.filter.remote_address = '*'),
    (r) => (r.filter.remote_port = 0),
    (r) => (r.filter.application = 'other'),
    (r) => (r.action = 'block'),
    (r) => (r.expires = '0001-01-01T00:00:00Z'),
    (r) => (r.version = 5),
  ]) {
    const p = preview(base());
    mutate(p.rule);
    assert.throws(() => parseZoneMigration(p, base(), target, 'z1', now));
  }
  const expired = preview(base());
  expired.expires_at = new Date(now - 1).toISOString();
  assert.throws(() => parseZoneMigration(expired, base(), target, 'z1', now));
});
test('explicit migration confirms exact ACK once; old rule and fixed request fields preserved', async (t) => {
  const f = await fixture(t);
  const v = await f.service.preview(target);
  assert.equal(v.canConfirm, true);
  assert.equal(f.requests.length, 1);
  const result = await f.service.confirm(v.preview.token);
  assert.equal(result.phase, 'acknowledged');
  await assert.rejects(() => f.service.confirm(v.preview.token));
  assert.deepEqual(f.requests[1], {
    version: 1,
    operation: 'zone-migration-save',
    generation: 'g',
    id: 'legacy',
    expected_version: 3,
    zone_revision: 'z1',
    preview_token: 'token',
  });
  assert(!('zone_model' in f.original.filter));
});
test('changed network revision, generation, rule or authority fences confirm without a save', async (t) => {
  for (const mutate of [
    (c) => (c.networkZones.revision = 'z2'),
    (c) => (c.generation = 'g2'),
    (c) => c.rules[0].version++,
    (c) => (c.permissions.can_manage_rules = false),
    (c) => (c.connected = false),
  ]) {
    const f = await fixture(t);
    const v = await f.service.preview(target);
    mutate(f.c);
    assert.equal(f.service.view().canConfirm, false);
    await assert.rejects(() => f.service.confirm(v.preview.token));
    assert(!f.requests.some((q) => q.operation === 'zone-migration-save'));
  }
});
test('read started before network change cannot become actionable after its response', async (t) => {
  const f = await fixture(t);
  f.mode = 'hold';
  const work = f.service.preview(target);
  while (!f.hold) await new Promise((r) => setImmediate(r));
  f.c.networkZones.revision = 'z2';
  f.hold();
  const result = await work;
  assert.equal(result.phase, 'rejected');
  assert.equal(result.canConfirm, false);
});
test('explicit capability and machine grants required; no old-daemon fallthrough', async (t) => {
  for (const mutate of [
    (c) => (c.capabilities = []),
    (c) => delete c.permissions.can_manage_rules,
    (c) => {
      c.rules[0].filter.all_uids = true;
      c.permissions.can_manage_machine_rules = false;
    },
  ]) {
    const f = await fixture(t);
    mutate(f.c);
    await assert.rejects(() => f.service.preview(target));
    assert.equal(f.requests.length, 0);
  }
});
test('lost ACK or mismatched saved scope remains unknown; reconcile reads exact inventory with no mutation replay', async (t) => {
  for (const mode of ['lost', 'widen']) {
    const f = await fixture(t);
    f.mode = mode;
    const v = await f.service.preview(target);
    const result = await f.service.confirm(v.preview.token);
    assert.equal(result.phase, 'unknown');
    await assert.rejects(() => f.service.confirm(v.preview.token));
    await assert.rejects(() => f.service.preview(target));
    assert.equal((await f.service.reconcile()).phase, 'acknowledged');
    assert.equal(f.requests.filter((q) => q.operation === 'zone-migration-save').length, 1);
  }
});
test('external deletion after lost ACK is not disguised as success or retried', async (t) => {
  const f = await fixture(t);
  f.mode = 'lost';
  const v = await f.service.preview(target);
  await f.service.confirm(v.preview.token);
  f.inventory = undefined;
  assert.equal((await f.service.reconcile()).phase, 'unknown');
  assert.equal(f.requests.filter((q) => q.operation === 'zone-migration-save').length, 1);
});
test('ordinary edit of legacy4 or automatic6 preserves original model and absolute expiry', async (t) => {
  const { Rules } = require('../dist/test/rules.cjs');
  for (const automatic of [false, true]) {
    const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/ze-')),
      socket = path.join(dir, 's'),
      original = automatic ? candidate(base()) : base();
    let request;
    const server = net.createServer((s) =>
      s.once('data', (b) => {
        request = JSON.parse(b);
        s.end(
          JSON.stringify({
            version: 1,
            generation: 'g',
            read_only: false,
            mode: 'daemon-monitor',
            server_time: new Date().toISOString(),
            saved_rule: { ...request.rule, version: original.version + 1 },
            scope_preview: 'Unchanged classifier',
          }) + '\n',
        );
      }),
    );
    await new Promise((r) => server.listen(socket, r));
    t.after(async () => {
      await new Promise((r) => server.close(r));
      fs.rmSync(dir, { recursive: true, force: true });
    });
    const backend = {
      controller: socket,
      pollControl: async () => {},
      now: () => Date.now(),
      view: () => ({
        control: {
          connected: true,
          readOnly: false,
          generation: 'g',
          permissions: { can_manage_rules: true },
          networkZones: config,
          rules: [original],
          events: [],
        },
      }),
    };
    const client = new Rules(backend),
      d = await client.draft({ id: original.id });
    await client.preview({
      token: d.token,
      action: 'block',
      protocol: 'tcp',
      remote_address: '1.2.3.4',
      local_port: 0,
      remote_port: 443,
      priority: 42,
      disabled: false,
      expiry: 'preserve',
    });
    assert.equal(request.rule.schema, original.schema);
    assert.equal(request.rule.filter.zone_model, original.filter.zone_model);
    assert.equal(request.rule.expires, original.expires);
    assert.equal(request.zone_revision, 'z1');
  }
});

test('legacy empty Any peer may canonicalize to explicit star only, never widen an endpoint',()=>{
 const old=base();old.filter.remote_address='';const p=preview(old);p.rule.filter.remote_address='*';
 assert.equal(parseZoneMigration(p,old,target,'z1',Date.now()).rule.filter.remote_address,'*');
 old.filter.remote='1.2.3.4:443';assert.throws(()=>parseZoneMigration(p,old,target,'z1',Date.now()));
});
