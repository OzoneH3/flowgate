const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { Essential } = require('../dist/test/essential.cjs');
const { parseRule } = require('../dist/test/protocol.cjs');
const { essentialDefaults, essentialRuleLabel } = require('../dist/test/essential-model.cjs');
const rule = () => ({
  schema: 5,
  id: 'essential:dns',
  version: 1,
  created: '2026-10-19T00:00:00Z',
  expires: '0001-01-01T00:00:00Z',
  disabled: false,
  priority: 100,
  executable: '/fixture/resolved',
  action: 'allow',
  preset: {
    name: 'essential-system-networking',
    component: 'dns-upstream',
    entry_id: 'one',
    revision: 'discovery-v1',
    digest: 'digest',
  },
  filter: {
    application: 'app',
    revision: 'binary1',
    uid: 974,
    direction: 'outgoing',
    protocol: 'udp',
    remote_address: '192.0.2.53',
    remote_port: 53,
    local_port: 0,
    local_address: '192.0.2.1',
    interface_index: 2,
    interface_name: 'fixture0',
  },
});
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/essential-')),
    endpoint = dir + '/api';
  const f = {
    generation: 'one',
    active: false,
    cap: true,
    permit: true,
    options: essentialDefaults(),
    rules: [],
    calls: [],
    drop: false,
    hold: undefined,
    bad: false,
    error: undefined,
    preview: undefined,
    receipt: undefined,
  };
  const status = () => ({
    revision: 'discovery-v1',
    components: [
      {
        id: 'dns-upstream',
        title: 'DNS upstream',
        state: 'ready',
        essential: true,
        details: ['Exact detected upstream'],
        revision: 'binary1',
      },
    ],
    rule_ids: f.rules.map((r) => r.id),
    issues: [],
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw);
      f.calls.push(q);
      let response = {
        version: 1,
        generation: f.generation,
        read_only: false,
        mode: 'daemon-monitor',
        server_time: new Date().toISOString(),
        rules: f.rules,
      };
      if (q.operation !== 'essential-status' && !q.essential_options) {
        response.error_code = 'invalid_request';
        response.error = 'Explicit essential_options required';
        s.end(JSON.stringify(response) + '\n');
        return;
      }
      if (q.operation === 'essential-status') {
        response.essential_status = status();
        if (q.preview_token) {
          if (f.receipt) response.essential_receipt = f.receipt;
          else {
            response.error_code = 'receipt_unknown';
            response.error = 'No committed receipt';
          }
        }
      }
      if (q.operation.endsWith('preview')) {
        const remove = q.operation === 'essential-remove-preview';
        f.preview = {
          ...status(),
          token: 'token-' + f.calls.length,
          expires_at: new Date(Date.now() + 30000).toISOString(),
          operation: remove ? 'remove' : 'apply',
          options: remove ? essentialDefaults() : q.essential_options,
          rules: remove ? f.rules : [rule()],
          preserved_rule_ids: [],
        };
        response.essential_preview = f.preview;
      }
      if (['essential-apply', 'essential-remove'].includes(q.operation)) {
        if (f.error) {
          response.error_code = f.error;
          response.error = 'Fixture conflict';
        } else {
          const p = f.preview;
          const remove = p.operation === 'remove';
          f.rules = remove ? [] : p.rules;
          f.receipt = {
            token: p.token,
            operation: p.operation,
            rule_ids: remove ? [] : p.rules.map((r) => r.id),
            rules: remove ? [] : p.rules,
            removed_rule_ids: remove ? p.rules.map((r) => r.id) : [],
          };
          response.essential_receipt = structuredClone(f.receipt);
          if (f.bad) response.essential_receipt.rules[0].filter.remote_port = 0;
          if (f.drop) {
            f.drop = false;
            s.end();
            return;
          }
        }
      }
      const send = () => s.end(JSON.stringify(response) + '\n');
      if (f.hold && q.operation === 'essential-preview') {
        f.hold(send);
        return;
      }
      send();
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const control = () => ({
    connected: true,
    readOnly: false,
    generation: f.generation,
    capabilities: f.cap ? ['essential-system-networking-v1'] : [],
    permissions: { role: 'administrator', policy_scope: 'machine', can_manage_rules: f.permit },
    serverNow: Date.now(),
    enforcement: { state: f.active ? 'active' : 'stopped', profile: 'both' },
    rules: f.rules,
  });
  const backend = {
    controller: endpoint,
    view: () => ({ control: control() }),
    pollControl: async () => {},
    ruleMutation: async (fn) => fn(),
  };
  const essential = new Essential(backend);
  t.after(() => {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { f, essential, backend };
}
test('strict schema5 metadata preserves peer/service/interface scope and cannot enter old editor', async () => {
  const raw = rule();
  raw.filter = {
    ...raw.filter,
    application: '',
    revision: '',
    all_programs: true,
    all_uids: true,
    peer_service: { application: 'local-stub', revision: 'stub-v1', uid: 974 },
  };
  const r = parseRule(raw);
  assert.equal(r.preset.component, 'dns-upstream');
  assert.equal(r.filter.peer_service.revision, 'stub-v1');
  assert.equal(r.filter.interface_index, 2);
  assert.match(essentialRuleLabel(r), /All programs.*local service/);
  const { Rules } = require('../dist/test/rules.cjs');
  const editor = new Rules({
    controller: '/fixture',
    pollControl: async () => {},
    view: () => ({
      control: {
        connected: true,
        readOnly: false,
        permissions: { can_manage_rules: true },
        rules: [r],
      },
    }),
  });
  await assert.rejects(editor.draft({ id: r.id }), /Preset-owned/);
  assert.throws(() => parseRule({ ...raw, schema: 2 }));
  assert.throws(() => parseRule({ ...raw, preset: { ...raw.preset, digest: '' } }));
  assert.throws(() => parseRule({ ...raw, filter: { ...raw.filter, new_scope: 'unsupported' } }));
});
test('explicit preview then exact apply/remove; optional defaults off, no protection operation', async (t) => {
  const { f, essential: e } = await fixture(t);
  let v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  assert.equal(v.phase, 'review');
  assert(v.canApply);
  assert.equal(f.rules.length, 0);
  v = await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(v.phase, 'confirmed');
  assert.equal(f.rules.length, 1);
  v = await e.action('remove-preview', { generation: 'one' });
  assert.equal(v.preview.rules.length, 1);
  v = await e.action('remove', { generation: 'one', token: v.preview.token });
  assert.equal(v.phase, 'confirmed');
  assert.equal(f.rules.length, 0);
  assert(f.calls.every((q) => q.operation.startsWith('essential-')));
});
test('no grant/old capability sends nothing; changed option/token or expiry sends no apply', async (t) => {
  const { f, essential: e } = await fixture(t);
  f.permit = false;
  await assert.rejects(e.action('preview', { generation: 'one', options: essentialDefaults() }));
  f.permit = true;
  f.cap = false;
  await assert.rejects(e.action('status', { generation: 'one' }));
  assert.equal(f.calls.length, 0);
  f.cap = true;
  let v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: { ...essentialDefaults(), tailscale: true },
  });
  assert.equal(f.calls.filter((q) => q.operation === 'essential-apply').length, 0);
  v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  e.view().preview.expires_at = '2000-01-01T00:00:00Z';
  await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(f.rules.length, 0);
});
test('lost apply acknowledgement reconciles exact receipt with one mutation; mismatch stays unknown', async (t) => {
  const { f, essential: e } = await fixture(t);
  let v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  f.drop = true;
  v = await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(v.phase, 'unknown');
  await assert.rejects(e.action('preview', { generation: 'one', options: essentialDefaults() }));
  v = await e.action('reconcile', { generation: 'one', token: v.preview.token });
  assert.equal(v.phase, 'confirmed');
  assert.equal(f.calls.filter((q) => q.operation === 'essential-apply').length, 1);
  v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  f.bad = true;
  v = await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(v.phase, 'unknown');
  assert.match(v.message, /differs/);
});
test('generation change while preview pending discards response; conflict does not claim success', async (t) => {
  const { f, essential: e } = await fixture(t);
  let send;
  f.hold = (fn) => (send = fn);
  const p = e.action('preview', { generation: 'one', options: essentialDefaults() });
  while (!send) await new Promise((r) => setImmediate(r));
  f.generation = 'two';
  send();
  let v = await p;
  assert.equal(v.preview, undefined);
  assert.equal(v.canApply, false);
  f.hold = undefined;
  v = await e.action('preview', { generation: 'two', options: essentialDefaults() });
  f.error = 'policy_conflict';
  v = await e.action('apply', {
    generation: 'two',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(v.phase, 'error');
  assert.match(v.message, /policy_conflict/);
  assert.equal(f.rules.length, 0);
});
test('administrator companion may read status but cannot preview or mutate', async (t) => {
  const { f, essential: e, backend } = await fixture(t);
  const endpoint = backend.controller;
  backend.controller = undefined;
  backend.observer = endpoint;
  backend.view = () => ({
    control: { connected: false, generation: '', rules: [] },
    observation: {
      connected: true,
      generation: f.generation,
      capabilities: ['essential-system-networking-v1'],
      permissions: { role: 'administrator', policy_scope: 'machine', can_manage_rules: false },
    },
  });
  assert.equal(e.view().permitted, false);
  assert(e.view().canStatus);
  const v = await e.action('status', { generation: 'one' });
  assert.equal(v.status.components.length, 1);
  await assert.rejects(e.action('preview', { generation: 'one', options: essentialDefaults() }));
  assert.deepEqual(
    f.calls.map((q) => q.operation),
    ['essential-status'],
  );
});
test('receipt mismatch, unknown receipt and remove lost ACK never replay or delete a different rule', async (t) => {
  const { f, essential: e } = await fixture(t);
  let v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  v = await e.action('remove-preview', { generation: 'one' });
  f.drop = true;
  v = await e.action('remove', { generation: 'one', token: v.preview.token });
  assert.equal(v.phase, 'unknown');
  const receipt = f.receipt;
  f.receipt = undefined;
  v = await e.action('reconcile', { generation: 'one', token: v.preview.token });
  assert.equal(v.phase, 'unknown');
  assert.match(v.message, /receipt_unknown/);
  f.receipt = receipt;
  v = await e.action('reconcile', { generation: 'one', token: v.preview.token });
  assert.equal(v.phase, 'confirmed');
  assert.equal(f.calls.filter((q) => q.operation === 'essential-remove').length, 1);
});
test('actual active/unknown protection disables Apply without an automatic Stop', async (t) => {
  const { f, essential: e, backend } = await fixture(t);
  let v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  f.active = true;
  assert.equal(e.view().canApply, false);
  assert.match(e.view().message, /Stop protection explicitly/);
  await e.action('apply', {
    generation: 'one',
    token: v.preview.token,
    options: essentialDefaults(),
  });
  assert.equal(f.rules.length, 0);
  assert(f.calls.every((q) => q.operation.startsWith('essential-')));
  f.active = false;
  v = await e.action('preview', { generation: 'one', options: essentialDefaults() });
  const original = backend.view;
  backend.view = () => {
    const s = original();
    delete s.control.enforcement;
    return s;
  };
  assert.equal(e.view().canApply, false);
});
