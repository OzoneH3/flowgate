// Synthetic contract faults. Real native creation is exercised separately on Wayland.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { ObservedRules } = require('../dist/test/observed-rules.cjs');
async function fixture(t) {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/observed-contract-')),
    endpoint = path.join(dir, 's');
  let now = Date.now(),
    generation = 'g',
    mode = 'ack',
    previews = 0,
    saves = 0,
    permissions = { can_manage_rules: true, can_decide: false },
    rules = [],
    requests = [],
    captured;
  const application = { key: 'app', revision: 'rev', executable: '/native/app', name: 'native' },
    process = { id: '1:start', pid: 1, start_ticks: '10', uid: 1000, application };
  const target = {
    instance_id: 'a'.repeat(32),
    session: 'g',
    boot_id: 'boot',
    pid: 1,
    start_ticks: '10',
    uid: 1000,
    netns: 'net:[1]',
    mountns: 'mnt:[2]',
    pidns: 'pid:[3]',
    executable: '/native/app',
    revision: 'rev',
  };
  const state = {
    control: {
      connected: true,
      generation,
      readOnly: false,
      permissions,
      capabilities: ['observed-rule-create-v1'],
      rules: [],
      enforcement: { state: 'stopped' },
    },
    observation: {
      connected: true,
      generation,
      activity: {
        processes: { '1:start': process },
        rows: [{ id: 'row', owners: ['1:start'], socket: { protocol: 'tcp' } }],
      },
    },
  };
  const reply = (extra) => ({
    version: 1,
    generation,
    read_only: false,
    mode: 'daemon-monitor',
    server_time: new Date(now).toISOString(),
    ...extra,
  });
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      requests.push(q);
      if (q.operation === 'observed-rule-preview') {
        previews++;
        const d = q.observed_draft;
        const replace = ['replace', 'badreplace'].includes(mode);
        const rule = {
          id: replace ? 'own' : 'created-' + previews,
          version: replace ? (mode === 'badreplace' ? 9 : 4) : 1,
          schema: d.target_scope === 'process' ? 3 : 2,
          created: new Date(now).toISOString(),
          executable: application.executable,
          action: d.action,
          disabled: d.disabled,
          priority: 100,
          expires: d.expires,
          filter: {
            ...(d.target_scope === 'process'
              ? {
                  process: {
                    ...target,
                    instance_id: mode === 'wrongtarget' ? 'b'.repeat(32) : target.instance_id,
                  },
                }
              : {}),
            application: 'app',
            revision: mode === 'identity' ? 'changed' : 'rev',
            uid: 1000,
            direction: d.direction,
            protocol: mode === 'narrowed' ? 'tcp' : d.protocol,
            remote_address: d.remote_address,
            local_port: d.local_port,
            remote_port: d.remote_port,
            remote: '',
          },
        };
        captured = {
          token: 'preview-' + previews,
          expires_at: new Date(now + 30000).toISOString(),
          rule,
          application,
          process_id: '1:start',
          pid: 1,
          principal_uid: 1000,
          scope_preview: 'Synthetic exact scope',
          enforcement: { state: 'stopped', covered: false, reason: 'Stopped' },
          replaces: replace ? { id: 'own', version: 3 } : null,
        };
        s.end(JSON.stringify(reply({ observed_preview: captured })) + '\n');
      } else if (q.operation === 'observed-rule-save') {
        saves++;
        assert.equal(q.preview_token, captured.token);
        assert.equal(q.observed_draft.direction, captured.rule.filter.direction);
        if (mode === 'failure')
          return s.end(
            JSON.stringify(reply({ error: 'disk failed', error_code: 'persistence_failed' })) +
              '\n',
          );
        rules = [captured.rule];
        if (mode === 'lost') return s.destroy();
        s.end(
          JSON.stringify(
            reply({ saved_rule: captured.rule, scope_preview: captured.scope_preview }),
          ) + '\n',
        );
      } else throw Error('Unexpected operation ' + q.operation);
    }),
  );
  await new Promise((r) => server.listen(endpoint, r));
  t.after(() => {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const backend = {
    controller: endpoint,
    view: () => state,
    now: () => now,
    pollControl: async () => {
      state.control.rules = rules;
    },
  };
  return {
    target,
    engine: new ObservedRules(backend),
    state,
    counts: () => ({ previews, saves }),
    requests,
    mode: (v) => (mode = v),
    advance: (ms) => (now += ms),
    changeGeneration: () => {
      generation = 'new';
      state.control.generation = 'new';
    },
    source: { generation: 'g', row_id: 'row', process_id: '1:start', direction: 'incoming' },
  };
}
const fields = (token) => ({
  token,
  action: 'block',
  protocol: 'tcp',
  remote_address: '*',
  local_port: 0,
  remote_port: 0,
  priority: 100,
  disabled: false,
  expiry: 'preserve',
  creation_scope: 'application',
});
test('creation permissions, explicit scope, identity and direction; read-only cannot draft', async (t) => {
  const f = await fixture(t);
  f.state.control.permissions.can_manage_rules = false;
  await assert.rejects(f.engine.draft(f.source), /read-only/);
  f.state.control.permissions.can_manage_rules = true;
  f.state.control.capabilities = [];
  await assert.rejects(f.engine.draft(f.source), /update required/);
  f.state.control.capabilities = ['observed-rule-create-v1'];
  await assert.rejects(f.engine.draft({ ...f.source, process_id: 'shared' }), /single-holder/);
  const d = await f.engine.draft({ ...f.source, direction: 'outgoing' });
  assert(!('endpoint' in d));
  await assert.rejects(
    f.engine.preview({ ...fields(d.token), creation_scope: 'custom' }),
    /explicitly choose/,
  );
  const p = await f.engine.preview(fields(d.token));
  assert.equal(p.verifiedRule.filter.direction, 'outgoing');
  const result = await f.engine.save(p.receipt);
  assert.equal(result.phase, 'acknowledged');
  assert.equal(result.rule.filter.direction, 'outgoing');
  assert.equal(f.counts().saves, 1);
  await assert.rejects(f.engine.save(p.receipt));
});
test('new preview invalidates old receipt; expiry/generation/identity changes send no save', async (t) => {
  const f = await fixture(t),
    d = await f.engine.draft(f.source),
    a = await f.engine.preview(fields(d.token)),
    b = await f.engine.preview({ ...fields(d.token), action: 'allow' });
  await assert.rejects(f.engine.save(a.receipt));
  f.advance(31000);
  await assert.rejects(f.engine.save(b.receipt), /expired/);
  assert.equal(f.counts().saves, 0);
  const c = await f.engine.preview(fields(d.token));
  f.changeGeneration();
  await assert.rejects(f.engine.save(c.receipt), /Generation/);
  assert.equal(f.counts().saves, 0);
});
test('identity changed in verification refuses preview; persistence failure needs renewed preview', async (t) => {
  const f = await fixture(t),
    d = await f.engine.draft(f.source);
  f.mode('identity');
  await assert.rejects(f.engine.preview(fields(d.token)), /identity changed/);
  f.mode('failure');
  const p = await f.engine.preview(fields(d.token));
  const r = await f.engine.save(p.receipt);
  assert.equal(r.phase, 'rejected');
  assert.match(r.message, /persistence_failed/);
  await assert.rejects(f.engine.save(p.receipt));
});
test('lost save acknowledgement locks draft and reconciles unique ID without replay', async (t) => {
  const f = await fixture(t),
    d = await f.engine.draft(f.source),
    p = await f.engine.preview(fields(d.token));
  f.mode('lost');
  const results = await Promise.allSettled([f.engine.save(p.receipt), f.engine.save(p.receipt)]);
  const unknown = results.find((r) => r.status === 'fulfilled').value;
  assert.equal(unknown.phase, 'unknown');
  assert.equal(f.counts().saves, 1);
  await assert.rejects(f.engine.preview(fields(d.token)), /outstanding save/);
  const result = await f.engine.reconcile(unknown.reconcile);
  assert.equal(result.phase, 'acknowledged');
  assert.match(result.message, /Authoritative rules confirm/);
  assert.equal(f.counts().saves, 1);
});

test('process creation is capability-gated and binds exact instance across previews/ACK/reconciliation', async (t) => {
  const f = await fixture(t);
  const source = { ...f.source, target_scope: 'process' };
  await assert.rejects(f.engine.draft(source), /update required/);
  f.state.control.capabilities.push('process-instance-rules-v1');
  f.state.control.policy = {
    applications: [],
    processes: [{ process_id: '1:start', state: 'active', target: f.target }],
  };
  const d = await f.engine.draft(source);
  assert.equal(d.targetScope, 'process');
  const p = await f.engine.preview(fields(d.token));
  assert.deepEqual(p.verifiedRule.filter.process, f.target);
  f.mode('wrongtarget');
  await assert.rejects(f.engine.preview(fields(d.token)), /binding changed/);
  f.mode('lost');
  const q = await f.engine.preview(fields(d.token));
  const result = await f.engine.save(q.receipt);
  assert.equal(result.phase, 'unknown');
  const reconciled = await f.engine.reconcile(result.reconcile);
  assert.equal(reconciled.phase, 'acknowledged');
  assert.deepEqual(reconciled.rule.filter.process, f.target);
  assert.equal(f.counts().saves, 1);
});

test('lost process capability and exited instance send no save and never widen target', async (t) => {
  const f = await fixture(t);
  f.state.control.capabilities.push('process-instance-rules-v1');
  const d = await f.engine.draft({ ...f.source, target_scope: 'process' }),
    p = await f.engine.preview(fields(d.token));
  f.state.control.capabilities = ['observed-rule-create-v1'];
  await assert.rejects(f.engine.save(p.receipt), /capability lost/);
  assert.equal(f.counts().saves, 0);
  f.state.control.capabilities.push('process-instance-rules-v1');
  delete f.state.observation.activity.processes['1:start'];
  await assert.rejects(f.engine.save(p.receipt), /no longer available/);
  assert.equal(f.counts().saves, 0);
});
// NetLimiter quick setter (application-policy-v1): the canonical own rule, never a scoped rule.
const policyFields = (token, action = 'allow') => ({
  token,
  action,
  protocol: '*',
  remote_address: '*',
  local_port: 0,
  remote_port: 0,
  priority: 100,
  disabled: false,
  expiry: 'permanent',
  creation_scope: 'policy',
});
test('application policy is capability-gated and sends application_policy with the canonical scope', async (t) => {
  const f = await fixture(t);
  // A narrow remembered rule exists; the app-level Allow must not target or edit it.
  const narrow = {
    id: 'narrow',
    version: 1,
    schema: 2,
    created: new Date().toISOString(),
    executable: '/native/app',
    action: 'block',
    disabled: false,
    priority: 100,
    expires: '0001-01-01T00:00:00Z',
    filter: {
      application: 'app',
      revision: 'rev',
      uid: 1000,
      direction: 'outgoing',
      protocol: 'tcp',
      remote_address: '1.1.1.1',
      local_port: 0,
      remote_port: 0,
    },
  };
  f.state.control.rules = [narrow];
  let d = await f.engine.draft({ ...f.source, direction: 'outgoing' });
  await assert.rejects(f.engine.preview(policyFields(d.token)), /application-policy-v1/);
  f.state.control.capabilities.push('application-policy-v1');
  for (const bad of [
    { protocol: 'tcp' },
    { remote_address: '1.1.1.1' },
    { remote_port: 443 },
    { expiry: 'hour' },
  ])
    await assert.rejects(
      f.engine.preview({ ...policyFields(d.token), ...bad }),
      /TCP\+UDP, any endpoint, persistent/,
    );
  assert.equal(f.counts().previews, 0);
  const p = await f.engine.preview(policyFields(d.token));
  assert.equal(p.replaces, null);
  const sent = f.requests.at(-1);
  assert.equal(sent.operation, 'observed-rule-preview');
  assert.deepEqual(sent.observed_draft, {
    direction: 'outgoing',
    protocol: '*',
    action: 'allow',
    remote_address: '*',
    local_port: 0,
    remote_port: 0,
    disabled: false,
    application_policy: true,
    expires: '0001-01-01T00:00:00Z',
  });
  const result = await f.engine.save(p.receipt);
  assert.equal(result.phase, 'acknowledged');
  assert.notEqual(result.rule.id, 'narrow');
  assert.equal(f.requests.at(-1).observed_draft.application_policy, true);
  assert(f.requests.every((q) => !JSON.stringify(q).includes('"narrow"')));
});
test('application policy updates the own rule in place only as the backend replaces it; non-canonical previews refuse', async (t) => {
  const f = await fixture(t);
  f.state.control.capabilities.push('application-policy-v1');
  f.mode('replace');
  let d = await f.engine.draft(f.source);
  const p = await f.engine.preview(policyFields(d.token, 'block'));
  assert.deepEqual(p.replaces, { id: 'own', version: 3 });
  assert.equal(p.verifiedRule.id, 'own');
  assert.equal((await f.engine.save(p.receipt)).phase, 'acknowledged');
  f.mode('badreplace');
  d = await f.engine.draft(f.source);
  await assert.rejects(f.engine.preview(policyFields(d.token)), /not the canonical/);
  f.mode('narrowed');
  d = await f.engine.draft(f.source);
  await assert.rejects(f.engine.preview(policyFields(d.token)), /not the canonical/);
  assert.equal(f.counts().saves, 1);
});
test('stored Ask needs stored-ask-v1; with it the application policy action is ask', async (t) => {
  const f = await fixture(t);
  f.state.control.capabilities.push('application-policy-v1');
  let d = await f.engine.draft(f.source);
  await assert.rejects(f.engine.preview(policyFields(d.token, 'ask')), /stored-ask-v1/);
  await assert.rejects(f.engine.preview({ ...fields(d.token), action: 'ask' }), /stored-ask-v1/);
  assert.equal(f.counts().previews, 0);
  f.state.control.capabilities.push('stored-ask-v1');
  const p = await f.engine.preview(policyFields(d.token, 'ask'));
  assert.equal(f.requests.at(-1).observed_draft.action, 'ask');
  assert.equal(p.verifiedRule.action, 'ask');
});

test('runtime row drafts bind Windows application and prohibit broker process scope',async(t)=>{
 const f=await fixture(t);
 const row=f.state.observation.activity.rows[0];
 row.socket.cookie='cookie';
 row.runtime_application={uid:1000,application:{key:'windows-image',revision:'pe-stamp',executable:'/prefix/Alpha.exe',name:'Alpha.exe'},evidence:{broker_pid:1,broker_start_ticks:'10',uid:1000,socket_cookie:'cookie'}};
 f.state.observation.activity.processes['1:start'].application={key:'',revision:'',executable:'/runtime/wineserver',name:'wineserver'};
 const d=await f.engine.draft(f.source);
 assert.equal(d.rule.filter.application,'windows-image');
 assert.equal(d.rule.executable,'/prefix/Alpha.exe');
 row.owners=['client','1:start']; row.ownership_category='shared';
 f.state.observation.activity.processes.client={id:'client',pid:2,start_ticks:'20',uid:1000,application:row.runtime_application.application};
 assert.equal((await f.engine.draft(f.source)).rule.filter.application,'windows-image');
 await assert.rejects(f.engine.draft({...f.source,process_id:'client'}),/single-holder/);
 row.runtime_application.evidence.broker_start_ticks='reused';
 await assert.rejects(f.engine.draft(f.source),/single-holder/);
 row.runtime_application.evidence.broker_start_ticks='10';
 f.state.control.capabilities.push('process-instance-rules-v1');
 await assert.rejects(f.engine.draft({...f.source,target_scope:'process'}),/not a Linux process rule/);
});
