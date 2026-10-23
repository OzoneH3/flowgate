// Not-running rules popup: an action/enabled change keeps the stored rule's complete scope.
// Real Rules draft → preview → save over a synthetic Unix-socket daemon; no host daemon.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { Rules } = require('../dist/test/rules.cjs');
const workspace = path.resolve(__dirname, '../../.workspace');
const { changeStoredRule } = require('../dist/test/inactive-rules.cjs');

const stored = (filter, extra = {}) => ({
  id: 'user:a', version: 1, schema: filter.remote ? 1 : 2, created: '2026-01-01T00:00:00Z', expires: '0001-01-01T00:00:00Z',
  executable: '/opt/synthetic-a', action: 'allow', priority: 100, disabled: false, ...extra,
  filter: { application: 'synthetic-a', revision: 'rev-a', uid: 1000, direction: 'outgoing', protocol: 'tcp', ...filter },
});

// One synthetic daemon per test. `review` may alter the rule the daemon reports for a preview.
async function harness(rules, review = (r) => r) {
  const dir = fs.mkdtempSync(path.join(workspace, 'inactive-rule-scope-test-'));
  const socket = path.join(dir, 's');
  const sent = [];
  const control = { connected: true, readOnly: false, generation: 'g1', rules, events: [], capabilities: [] };
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      sent.push(q);
      const saved = { ...(q.operation === 'rule-preview' ? review(structuredClone(q.rule)) : q.rule), version: 2 };
      s.end(JSON.stringify({ version: 1, generation: control.generation, mode: 'daemon-monitor', read_only: false,
        server_time: new Date().toISOString(), saved_rule: saved, scope_preview: 'Synthetic reviewed scope' }) + '\n');
    }),
  );
  await new Promise((r) => server.listen(socket, r));
  const backend = { controller: socket, pollControl: async () => {}, now: () => Date.now(), view: () => ({ control }) };
  const r = new Rules(backend);
  global.window = { flowgate: { ruleDraft: (s) => r.draft(s), rulePreview: (e) => r.preview(e), ruleSave: (x) => r.save(x) } };
  return {
    sent, control,
    ops: () => sent.map((q) => q.operation),
    saved: () => sent.filter((q) => q.operation === 'rule-save').map((q) => q.rule),
    close: () => new Promise((r) => server.close(() => { fs.rmSync(dir, { recursive: true, force: true }); r(); })),
  };
}

for (const [label, remote, address] of [['IPv4', '198.51.100.8:443', '198.51.100.8'], ['IPv6', '[2001:db8::8]:443', '2001:db8::8']]) {
  test(`legacy ${label} endpoint: action and enable edits keep the exact address and port`, async () => {
    for (const [action, disabled, start] of [['block', false, false], ['allow', false, true]]) {
      const rule = stored({ remote }, { disabled: start });
      const h = await harness([rule]);
      try {
        await changeStoredRule(rule, action, disabled);
        assert.deepEqual(h.ops(), ['rule-preview', 'rule-save']);
        const [s] = h.saved();
        assert.deepEqual([s.action, s.disabled], [action, disabled]);
        assert.deepEqual([s.filter.remote_address, s.filter.remote_port, s.filter.local_port, s.filter.remote], [address, 443, 0, '']);
        assert.deepEqual([s.filter.application, s.filter.revision, s.filter.uid, s.filter.direction, s.filter.protocol], ['synthetic-a', 'rev-a', 1000, 'outgoing', 'tcp']);
        assert.deepEqual([s.priority, s.expires, s.executable], [100, '0001-01-01T00:00:00Z', '/opt/synthetic-a']);
      } finally {
        await h.close();
      }
    }
  });
}

test('modern rule: priority, expiry, ports and root sharing are preserved', async () => {
  const expires = new Date(Date.now() + 86400000).toISOString();
  const rule = stored({ remote_address: '203.0.113.0/24', remote_port: 53, local_port: 5353, protocol: 'udp' }, { priority: 7, expires, share_with_root: true });
  const h = await harness([rule]);
  try {
    await changeStoredRule(rule, 'block', true);
    const [s] = h.saved();
    assert.deepEqual([s.filter.remote_address, s.filter.remote_port, s.filter.local_port, s.filter.protocol], ['203.0.113.0/24', 53, 5353, 'udp']);
    assert.deepEqual([s.priority, s.expires, s.share_with_root, s.action, s.disabled], [7, expires, true, 'block', true]);
  } finally {
    await h.close();
  }
});

test('malformed legacy endpoint is refused before any preview', async () => {
  const rule = stored({ remote: 'not-an-endpoint' });
  const h = await harness([rule]);
  try {
    await assert.rejects(changeStoredRule(rule, 'block', false), /Legacy endpoint cannot be edited safely/);
    assert.deepEqual(h.ops(), []);
  } finally {
    await h.close();
  }
});

test('a preview with any changed authority or scope field is refused with zero saves', async () => {
  const tamper = {
    'wildcard endpoint': (r) => ((r.filter.remote_address = '*'), (r.filter.remote_port = 0), r),
    'remote port': (r) => ((r.filter.remote_port = 444), r),
    'local port': (r) => ((r.filter.local_port = 1), r),
    'legacy remote': (r) => ((r.filter.remote = '198.51.100.9:443'), r),
    protocol: (r) => ((r.filter.protocol = '*'), r),
    uid: (r) => ((r.filter.uid = 0), r),
    direction: (r) => ((r.filter.direction = 'incoming'), r),
    application: (r) => ((r.filter.application = 'synthetic-b'), r),
    revision: (r) => ((r.filter.revision = 'rev-b'), r),
    'all programs': (r) => ((r.filter.all_programs = true), r),
    'all users': (r) => ((r.filter.all_uids = true), r),
    'network zone': (r) => ((r.filter.network_zone = 'local'), r),
    'zone model': (r) => ((r.filter.zone_model = 'automatic-peer-v1'), r),
    'local address': (r) => ((r.filter.local_address = '10.0.0.1'), r),
    'interface name': (r) => ((r.filter.interface_name = 'eth0'), r),
    'interface index': (r) => ((r.filter.interface_index = 2), r),
    'peer service': (r) => ((r.filter.peer_service = { application: 'synthetic-b', revision: 'rev-b', uid: 1000 }), r),
    process: (r) => ((r.filter.process = { instance_id: 'i', session: 's', boot_id: 'b', pid: 7, start_ticks: '1' }), r),
    'root application': (r) => ((r.root_application = 'root-key'), r),
    'root sharing': (r) => ((r.share_with_root = true), r),
    invocation: (r) => ((r.invocation = { mode: 'file', name: 'other', path: '/opt/other', revision: 'x' }), r),
    preset: (r) => ((r.preset = { name: 'essential-system-networking', component: 'c', entry_id: 'e', revision: 'r', digest: 'd' }), r),
    executable: (r) => ((r.executable = '/opt/synthetic-b'), r),
    id: (r) => ((r.id = 'user:b'), r),
    priority: (r) => ((r.priority = 99), r),
    expiry: (r) => ((r.expires = '2030-01-01T00:00:00Z'), r),
    schema: (r) => ((r.schema = 4), r),
  };
  for (const [name, review] of Object.entries(tamper)) {
    const rule = stored({ remote: '198.51.100.8:443' });
    const h = await harness([rule], review);
    try {
      // Whichever layer refuses (reply parser, Rules.preview or this check), nothing is saved.
      const reason = await changeStoredRule(rule, 'block', false).then(() => 'saved', (e) => String(e.message));
      assert.notEqual(reason, 'saved', name);
      assert.deepEqual(h.ops(), ['rule-preview'], name);
      if (process.env.FLOWGATE_SCOPE_EVIDENCE) console.log(JSON.stringify({ tamper: name, refused: reason }));
    } finally {
      await h.close();
    }
  }
});

test('daemon omitting zero-valued optional fields and echoing derived fields still saves once', async () => {
  const invocation = { mode: 'file', name: 'tool', path: '/opt/tool', revision: 'x' };
  const rule = stored({ remote_address: '198.51.100.8', remote_port: 443, all_programs: false, local_port: 0, remote: '' }, { invocation, share_with_root: true, root_application: 'root-key' });
  const h = await harness([rule], (r) => {
    delete r.filter.all_programs;
    delete r.filter.local_port;
    delete r.filter.remote;
    return r;
  });
  try {
    await changeStoredRule(rule, 'block', false);
    assert.deepEqual(h.ops(), ['rule-preview', 'rule-save']);
    const [s] = h.saved();
    assert.deepEqual([s.invocation, s.share_with_root, s.root_application], [invocation, true, 'root-key']);
  } finally {
    await h.close();
  }
});

test('version and generation races send no save', async () => {
  const listed = stored({ remote: '198.51.100.8:443' });
  const h = await harness([{ ...listed, version: 2 }]);
  try {
    await assert.rejects(changeStoredRule(listed, 'block', false), /changed since it was listed; nothing was saved/);
    assert.deepEqual(h.ops(), []);
  } finally {
    await h.close();
  }
  const g = await harness([listed]);
  const draft = global.window.flowgate.ruleDraft;
  global.window.flowgate.ruleDraft = async (s) => {
    const d = await draft(s);
    g.control.generation = 'g2';
    return d;
  };
  try {
    await assert.rejects(changeStoredRule(listed, 'block', false), /Generation changed/);
    assert.deepEqual(g.ops(), []);
  } finally {
    await g.close();
  }
});
