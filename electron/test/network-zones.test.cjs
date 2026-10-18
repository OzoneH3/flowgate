const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { ZoneRules } = require('../dist/test/zone-rules.cjs');
const { parseNetworkZones } = require('../dist/test/network-zones.cjs');
const config = {
  model: 'configured-prefix-v1',
  revision: 'r',
  local_prefixes: ['127.0.0.0/8'],
  internet_prefixes: [],
  reason: 'Configured only',
};
test('zone definitions are bounded configuration, never inferred public-address membership', () => {
  assert.deepEqual(parseNetworkZones(config), config);
  assert.throws(() => parseNetworkZones({ ...config, model: 'public-ip-guess' }));
  assert.throws(() => parseNetworkZones({ ...config, local_prefixes: Array(513).fill('x') }));
});
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/zone-contract-')),
    endpoint = path.join(dir, 's');
  let mode = 'ack',
    stored = [],
    saved,
    requests = [],
    now = Date.now();
  const state = {
    control: {
      connected: true,
      readOnly: false,
      generation: 'g',
      permissions: { can_manage_rules: true, can_manage_machine_rules: true },
      capabilities: ['network-zone-policy-v1'],
      networkZones: config,
      rules: [],
    },
  };
  const response = (extra) => ({
    version: 1,
    generation: 'g',
    read_only: false,
    mode: 'daemon-monitor',
    server_time: new Date(now).toISOString(),
    ...extra,
  });
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      requests.push(q.operation);
      if (q.operation === 'zone-rule-preview') {
        const d = q.observed_draft;
        saved = {
          id: 'reserved',
          version: 1,
          schema: 4,
          created: new Date(now).toISOString(),
          executable: '',
          action: d.action,
          disabled: d.disabled,
          priority: 100,
          expires: d.expires,
          filter: {
            application: '',
            revision: '',
            uid: 0,
            all_programs: true,
            all_uids: true,
            network_zone: mode === 'mismatch' ? 'internet' : 'local',
            direction: d.direction,
            protocol: d.protocol,
            remote_address: d.remote_address,
            local_port: d.local_port,
            remote_port: d.remote_port,
          },
        };
        s.end(
          JSON.stringify(
            response({
              zone_preview: {
                token: 'preview',
                expires_at: new Date(now + 30000).toISOString(),
                rule: saved,
                scope_preview: 'Local Network · all programs / all users',
                network_zones: config,
              },
            }),
          ) + '\n',
        );
      } else if (q.operation === 'zone-rule-save') {
        stored = [saved];
        if (mode === 'lost') {
          s.destroy();
          return;
        }
        s.end(JSON.stringify(response({ saved_rule: saved })) + '\n');
      } else s.end(JSON.stringify(response({ rules: stored })) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  t.after(async () => {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const backend = {
    controller: endpoint,
    view: () => state,
    now: () => now,
    pollControl: async () => {},
  };
  const client = new ZoneRules(backend);
  return { client, state, requests, mode: (v) => (mode = v), now: (v) => (now = v) };
}
const source = {
  generation: 'g',
  revision: 'r',
  zone: 'local',
  scope: 'machine',
  direction: 'incoming',
};
const edit = (token) => ({
  token,
  action: 'block',
  protocol: '*',
  remote_address: '*',
  local_port: 0,
  remote_port: 0,
  priority: 100,
  disabled: false,
  expiry: 'permanent',
  network_zone: 'local',
});
test('machine zone creation is explicit, preview bound and receipt never replays', async (t) => {
  const f = await fixture(t),
    d = await f.client.draft(source),
    p = await f.client.preview(edit(d.token));
  assert(p.verifiedRule.filter.all_programs);
  assert(p.verifiedRule.filter.all_uids);
  assert.equal(p.verifiedRule.filter.application, '');
  const result = await f.client.save(p.receipt);
  assert.equal(result.phase, 'acknowledged');
  await assert.rejects(f.client.save(p.receipt));
  assert.equal(f.requests.filter((x) => x === 'zone-rule-save').length, 1);
});
test('machine permission, zone revision, preview target and expiry reject stale authority', async (t) => {
  const f = await fixture(t);
  f.state.control.permissions.can_manage_machine_rules = false;
  await assert.rejects(f.client.draft(source), /administrator/);
  f.state.control.permissions.can_manage_machine_rules = true;
  await assert.rejects(f.client.draft({ ...source, revision: 'old' }), /changed/);
  const d = await f.client.draft(source);
  f.mode('mismatch');
  await assert.rejects(f.client.preview(edit(d.token)), /changed/);
  f.mode('ack');
  const p = await f.client.preview(edit(d.token));
  f.now(Date.now() + 31000);
  await assert.rejects(f.client.save(p.receipt), /expired/);
  assert(!f.requests.includes('zone-rule-save'));
});
test('lost zone acknowledgement reconciles exact reserved rule without a second save', async (t) => {
  const f = await fixture(t),
    d = await f.client.draft(source),
    p = await f.client.preview(edit(d.token));
  f.mode('lost');
  const lost = await f.client.save(p.receipt);
  assert.equal(lost.phase, 'unknown');
  assert.equal((await f.client.reconcile(lost.reconcile)).phase, 'acknowledged');
  assert.equal(f.requests.filter((x) => x === 'zone-rule-save').length, 1);
});

test('zone inventory requires matching generation/configuration and unexpired backend snapshot', () => {
  const { authoritativeZonePolicy } = require('../dist/test/policy.cjs');
  const row = { kind: 'network', id: 'network:local' };
  const z = { zone: 'local', incoming: {}, outgoing: {} };
  const c = {
    connected: true,
    generation: 'g',
    serverNow: 100,
    capabilities: ['network-zone-policy-v1'],
    networkZones: config,
    policy: {
      network_zones: config,
      snapshot: { generation: 'g', valid_until: new Date(200).toISOString() },
      zones: [z],
    },
  };
  assert.equal(authoritativeZonePolicy(row, { control: c }), z);
  assert.equal(authoritativeZonePolicy(row, { control: { ...c, generation: 'other' } }), undefined);
  assert.equal(authoritativeZonePolicy(row, { control: { ...c, serverNow: 300 } }), undefined);
  assert.equal(
    authoritativeZonePolicy(row, {
      control: { ...c, networkZones: { ...config, revision: 'new' } },
    }),
    undefined,
  );
});

test('permission loss after preview never submits and readonly access cannot draft', async (t) => {
  const f = await fixture(t),
    d = await f.client.draft(source),
    p = await f.client.preview(edit(d.token));
  f.state.control.permissions.can_manage_rules = false;
  await assert.rejects(f.client.save(p.receipt), /read-only/);
  await assert.rejects(f.client.draft(source), /read-only/);
  assert(!f.requests.includes('zone-rule-save'));
});

test('initiation event evidence retains explicit generation and never infers unknown direction', () => {
  const { parseReply } = require('../dist/test/protocol.cjs');
  const { initiationPresentation } = require('../dist/test/initiation.cjs');
  const reply = parseReply({
    version: 1,
    generation: 'g',
    mode: 'daemon-monitor',
    read_only: false,
    server_time: new Date().toISOString(),
    activity: {
      sequence: 1,
      collected: new Date().toISOString(),
      processes: {},
      tcp_initiation: {
        state: 'failed',
        generation: 'events1',
        reason: 'EPERM',
        partial: true,
        lost_events: 0,
        collected: new Date().toISOString(),
      },
      rows: [
        {
          id: 'r',
          owners: [],
          socket: { protocol: 'tcp', local: '127.0.0.1:1', remote: '127.0.0.1:2', state: 1 },
          initiation: {
            state: 'known',
            direction: 'incoming',
            generation: 'events1',
            source: 'cgroup-sockops-passive-established',
            observed_at: new Date().toISOString(),
            reason: 'Kernel cookie event',
          },
          traffic: { available: false },
        },
      ],
    },
  });
  assert.equal(reply.activity.tcp_initiation.state, 'failed');
  assert.equal(reply.activity.rows[0].initiation.generation, 'events1');
  assert.equal(initiationPresentation(reply.activity.rows[0]).direction, 'incoming');
  assert.equal(
    initiationPresentation({
      ...reply.activity.rows[0],
      initiation: { state: 'unknown', source: 'none', reason: 'Before attachment' },
    }).direction,
    '',
  );
});
