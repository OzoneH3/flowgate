// Synthetic API/receipt faults for request-application-rule-v1. Real receiver
// evidence belongs to the isolated journey.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { Backend } = require('../dist/test/backend.cjs');
const {
  REQUEST_RULE_CAPABILITY,
  requestRuleChoice,
  validateRequestRule,
  requestRuleAvailable,
  processInstanceEnded,
} = require('../dist/test/request-rule.cjs');
const { DEFAULT_REMEMBER } = require('../dist/test/decision-remember.cjs');

async function setup(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/request-rule-test-')),
    endpoint = path.join(dir, 's');
  const sent = [];
  let listed = true,
    lose = 1,
    saved;
  const e = {
    id: 'e', state: 'expired', reason: 'decision timed out; retry creates a new request',
    deadline: new Date(Date.now() - 1000).toISOString(), first_seen: new Date().toISOString(), permission: '',
    flow: { direction: 'outgoing', protocol: 'tcp', local: '10.1.0.1:40000', remote: '10.1.0.2:443' },
    attribution: { application: { key: 'app', revision: 'r', name: 'app', executable: '/opt/app' }, owners: [{ pid: 7, start_ticks: '1', uid: 1000 }], status: 'directly-associated', reason: '', visibility_complete: true },
    scope_previews: {},
    remembered_filter: { application: 'app', revision: 'r', uid: 1000, direction: 'outgoing', protocol: 'tcp', remote_address: '10.1.0.2', local_port: 0, remote_port: 443 },
    request_rule: { available: true, process_state: 'ended', until: new Date(Date.now() + 600000).toISOString() },
  };
  const base = () => ({
    version: 1, generation: 'g', read_only: false, mode: 'daemon-monitor', server_time: new Date().toISOString(),
    capabilities: ['explicit-administrator-v1', REQUEST_RULE_CAPABILITY],
    permissions: { role: 'administrator', observation_scope: 'machine', policy_scope: 'machine', can_manage_rules: true, can_decide: true },
    network_zones: { model: 'configured-prefix-v1', revision: 'zr', local_prefixes: [], internet_prefixes: [], reason: 'Test' },
    events: listed ? [e] : [],
  });
  const rule = (q) => ({
    id: 'user:new', version: 1, schema: 2, executable: '/opt/app', created: new Date().toISOString(), action: q.action, disabled: false,
    expires: '0001-01-01T00:00:00Z', priority: 100,
    filter: { application: 'app', revision: 'r', uid: 1000, direction: 'outgoing', protocol: q.remember.protocol ? 'tcp' : '*', remote_address: q.remember.address ? '10.1.0.2' : '*', local_port: 0, remote_port: q.remember.port ? 443 : 0 },
  });
  const server = net.createServer((s) =>
    s.once('data', (raw) => {
      const q = JSON.parse(raw), r = base();
      sent.push(q);
      if (q.operation === 'request-rule-preview')
        r.request_rule_preview = { token: 'tok', expires_at: new Date(Date.now() + 20000).toISOString(), event_id: 'e', action: q.action, scope_preview: 'Future connections only: …', summary: 'Allow app · Out · any address · any port · TCP+UDP · all zones · persistent', rule: rule(q), replaces: null };
      else if (q.operation === 'request-rule-save') {
        if (!saved) saved = rule(q);
        else r.replayed = true;
        r.saved_rule = saved;
        if (lose-- > 0) return void s.destroy();
      }
      s.end(JSON.stringify(r) + '\n');
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  const b = new Backend(endpoint, endpoint, () => {});
  await b.pollControl();
  t.after(() => { b.stop(); server.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  return { b, sent, drop: () => (listed = false) };
}

test('ended request keeps identity; application-only rule saves once despite a lost ACK; never decides', async (t) => {
  const { b, sent, drop } = await setup(t);
  drop(); // backend forgets the event after its deadline; the UI retains it
  await b.pollControl();
  const ev = b.view().control.events.find((x) => x.id === 'e');
  assert.ok(ev && requestRuleAvailable(ev, b.view().control.capabilities) && processInstanceEnded(ev));
  const choice = requestRuleChoice({ generation: 'g', id: 'e', action: 'allow' }, DEFAULT_REMEMBER, 0, 'zr');
  const p = await b.previewRequestRule(choice);
  assert.equal(p.rule.filter.protocol, '*');
  assert.equal(p.rule.filter.remote_address, '*');
  assert.equal(p.rule.filter.remote_port, 0);
  await assert.rejects(b.saveRequestRule({ ...choice, preview_token: p.token }), /acknowledgement lost/);
  const first = await b.saveRequestRule({ ...choice, preview_token: p.token });
  assert.equal(first.rule.id, 'user:new');
  assert.match(first.message, /future connections; the ended request was not allowed/);
  const again = await b.saveRequestRule({ ...choice, preview_token: p.token });
  assert.ok(again.replayed);
  const saves = sent.filter((q) => q.operation === 'request-rule-save');
  assert.equal(saves.length, 2, 'repeated click after success did not reach the backend');
  assert.ok(saves.every((q) => q.preview_token === 'tok'), 'a fresh creation was sent');
  assert.ok(!sent.some((q) => q.operation === 'decide' || q.operation === 'decision-preview'));
});

test('strict IPC payload: explicit fields, no smuggled keys, token only for save', () => {
  const ok = requestRuleChoice({ generation: 'g', id: 'e', action: 'ask' }, { ...DEFAULT_REMEMBER, port: true }, 300, 'zr');
  assert.deepEqual(validateRequestRule(ok), ok);
  assert.throws(() => validateRequestRule({ ...ok, pid: 7 }));
  assert.throws(() => validateRequestRule({ ...ok, remember: { address: true } }));
  assert.throws(() => validateRequestRule({ ...ok, preview_token: 't' }));
  assert.throws(() => validateRequestRule(ok, true));
  assert.throws(() => validateRequestRule({ ...ok, action: 'once' }));
});

test('sandbox identity_unverifiable is one permanent concise error (request-sandbox-identity-v1)', () => {
  const rr = require('../dist/test/request-rule.cjs');
  const msg = 'identity_unverifiable: No reusable application identity: The process ran in another mount namespace and exited; no host-visible file has device 50 inode 12; mountns: mnt:[4026532900] → daemon mnt:[4026531841]; executable: /tmp/pv/app → not host-visible. No rule saved. Start the app again and choose Remember while its request is open.';
  assert.equal(rr.IDENTITY_UNVERIFIABLE_TEXT, 'This sandboxed app exited before FlowGate retained a reusable identity.');
  assert.ok(rr.identityUnverifiable(msg));
  assert.ok(!rr.identityUnverifiable('executable_changed: Application identity cannot be validated'));
  const src = fs.readFileSync(path.join(__dirname, '../src/renderer.ts'), 'utf8');
  // No Refresh review and no automatic re-review for a permanently ended identity.
  assert.match(src, /refresh\.hidden = rememberMode\(\)\n\s+\? .*\|\| !!unverifiable/);
  assert.match(src, /!ruleChecking && !unverifiable &&/);
  assert.match(src, /ruleUnverifiable\.has\(e\.id\)\) return;/);
  assert.match(src, /ruleMode && unverifiable\n\s+\? IDENTITY_UNVERIFIABLE_TEXT/);
});
