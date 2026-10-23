// Synthetic API failure cases supplement real namespace receiver verification.
const { test } = require('node:test'),
  assert = require('node:assert/strict'),
  net = require('node:net'),
  fs = require('node:fs'),
  path = require('node:path');
const { Rules } = require('../dist/test/rules.cjs');
test('expired rule preserves immutable identity/absolute expiry; ambiguous save cannot replay receipt', async () => {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/ru-')),
    socket = path.join(dir, 's');
  const rule = {
    id: 'saved',
    version: 4,
    created: '2020-01-01T00:00:00Z',
    expires: '2021-01-01T00:00:00Z',
    schema: 2,
    executable: '/long/own/app',
    filter: {
      application: 'key',
      revision: 'revision',
      uid: 1000,
      direction: 'incoming',
      protocol: 'udp',
      remote_address: '::1',
      local_port: 44001,
      remote_port: 0,
    },
    priority: 0,
    action: 'allow',
    disabled: true,
  };
  const capabilities = [];
  let saves = 0,
    preview;
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      if (q.operation === 'rule-save') {
        saves++;
        s.destroy();
        return;
      }
      preview = q;
      s.end(
        JSON.stringify({
          version: 1,
          generation: 'g',
          mode: 'host-enforcement',
          read_only: false,
          server_time: new Date().toISOString(),
          saved_rule: { ...q.rule, version: 5 },
          scope_preview: 'Authoritative synthetic preview',
        }) + '\n',
      );
    }),
  );
  await new Promise((r) => server.listen(socket, r));
  try {
    const backend = {
      controller: socket,
      pollControl: async () => {},
      now: () => Date.now(),
      view: () => ({
        control: { connected: true, readOnly: false, generation: 'g', capabilities, rules: [rule], events: [] },
      }),
    };
    const rules = new Rules(backend),
      d = await rules.draft({ id: 'saved' });
    const e = {
      token: d.token,
      action: 'block',
      protocol: 'udp',
      remote_address: '::1',
      local_port: 44001,
      remote_port: 0,
      priority: 10,
      disabled: false,
      expiry: 'preserve',
    };
    await assert.rejects(() => rules.preview({ ...e, application: 'injected' }));
    await assert.rejects(() => rules.preview({ ...e, share_with_root: true }), /Backend update/);
    capabilities.push('explicit-root-sharing-v1');
    await rules.preview({ ...e, share_with_root: true });
    assert.equal(preview.rule.share_with_root, true);
    await rules.preview({ ...e, share_with_root: false });
    assert.equal(preview.rule.share_with_root, undefined);
    const p = await rules.preview(e);
    assert.equal(preview.rule.share_with_root, undefined, 'no implicit sharing');
    assert.equal(preview.rule.expires, rule.expires);
    assert.equal(preview.rule.filter.application, 'key');
    assert.equal(preview.expected_version, 4);
    const result = await rules.save(p.receipt);
    assert.equal(result.phase, 'unknown');
    await assert.rejects(() => rules.save(p.receipt));
    assert.equal(saves, 1);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test('stored Ask rule is read-only without stored-ask-v1: never re-saved as Allow/Deny; editable as Ask with it', async () => {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/ru-')),
    socket = path.join(dir, 's');
  const rule = {
    id: 'ask-rule',
    version: 2,
    created: '2020-01-01T00:00:00Z',
    expires: '0001-01-01T00:00:00Z',
    schema: 2,
    executable: '/app',
    filter: {
      application: 'key',
      revision: 'revision',
      uid: 1000,
      direction: 'outgoing',
      protocol: '*',
      remote_address: '*',
      local_port: 0,
      remote_port: 0,
    },
    priority: 100,
    action: 'ask',
    disabled: false,
  };
  const sent = [];
  const server = net.createServer((s) =>
    s.once('data', (b) => {
      const q = JSON.parse(b);
      sent.push(q);
      s.end(
        JSON.stringify({
          version: 1,
          generation: 'g',
          mode: 'host-enforcement',
          read_only: false,
          server_time: new Date().toISOString(),
          saved_rule: { ...q.rule, version: 3 },
          scope_preview: 'Synthetic',
        }) + '\n',
      );
    }),
  );
  await new Promise((r) => server.listen(socket, r));
  try {
    const control = {
      connected: true,
      readOnly: false,
      generation: 'g',
      rules: [rule],
      events: [],
      capabilities: [],
    };
    const rules = new Rules({
      controller: socket,
      pollControl: async () => {},
      now: () => Date.now(),
      view: () => ({ control }),
    });
    const edit = (token, action, disabled = false) => ({
      token,
      action,
      protocol: '*',
      remote_address: '*',
      local_port: 0,
      remote_port: 0,
      priority: 100,
      disabled,
      expiry: 'preserve',
    });
    const d = await rules.draft({ id: 'ask-rule' });
    for (const [action, disabled] of [
      ['allow', false],
      ['block', false],
      ['ask', true],
    ])
      await assert.rejects(() => rules.preview(edit(d.token, action, disabled)), /stored-ask-v1/);
    assert.equal(sent.length, 0);
    control.capabilities = ['stored-ask-v1'];
    await rules.preview(edit(d.token, 'ask', true));
    assert.equal(sent.at(-1).rule.action, 'ask');
    assert.equal(sent.at(-1).rule.disabled, true);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('closed application: create Internet Deny from saved identity, preserve LAN rule, reject stale classification', async () => {
  const dir = fs.mkdtempSync(path.resolve(__dirname, '../../.workspace/offline-rule-'));
  const socket = path.join(dir, 'api');
  const basis = {id:'basis', version:3, schema:2, created:'2026-01-01T00:00:00Z', expires:'0001-01-01T00:00:00Z', executable:'/prefix-a/Alpha.exe', action:'allow', disabled:false, priority:100,
    filter:{application:'alpha-prefix-a',revision:'rev-a',uid:1000,direction:'outgoing',protocol:'*',remote_address:'*'}};
  const control = {connected:true,readOnly:false,generation:'g',capabilities:['rule-from-basis-v1','network-zone-policy-v1','automatic-network-zones-v1'], networkZones:{model:'automatic-peer-v1',revision:'z1'},rules:[basis],events:[]};
  let sent=[];
  const server=net.createServer(s=>s.once('data',b=>{
    const q=JSON.parse(b); sent.push(q);
    s.end(JSON.stringify({version:1,generation:'g',mode:'host-enforcement',read_only:false,server_time:new Date().toISOString(),saved_rule:{...q.rule,id:q.id||'new',version:q.id?4:1},scope_preview:'fixture'})+'\n');
  }));
  await new Promise(r=>server.listen(socket,r));
  try {
    const rules=new Rules({controller:socket,pollControl:async()=>{},now:()=>Date.now(),view:()=>({control})});
    const d=await rules.draft({basis:{rule:'basis',direction:'outgoing',networkZone:'internet'}});
    assert.equal(d.rule.priority,100,'same priority lets Deny take precedence over broad Allow');
    const edit={token:d.token,action:'block',protocol:'*',remote_address:'*',local_port:0,remote_port:0,priority:d.rule.priority,disabled:false,expiry:'permanent',network_zone:'internet'};
    const p=await rules.preview(edit);
    assert.equal(p.verifiedRule.schema,6);
    assert.deepEqual(JSON.parse(JSON.stringify(p.verifiedRule.filter)),{...basis.filter,network_zone:'internet',zone_model:'automatic-peer-v1',remote:'',local_port:0,remote_port:0});
    assert.equal(sent.at(-1).basis_rule_id,'basis');
    assert.equal(sent.at(-1).zone_revision,'z1');
    assert.equal(basis.action,'allow');assert.equal(basis.filter.network_zone,undefined);
    control.networkZones.revision='z2';
    const before=sent.length;
    await assert.rejects(()=>rules.save(p.receipt),/classification changed/);
    await assert.rejects(()=>rules.preview(edit),/classification changed/);
    assert.equal(sent.length,before,'stale preview/save sends nothing');
    // Existing zone rules remain editable without any live process/event.
    const existing={...basis,id:'internet',schema:6,filter:{...basis.filter,network_zone:'internet',zone_model:'automatic-peer-v1'}};
    control.rules.push(existing);
    const saved=await rules.draft({id:'internet'});
    const edited=await rules.preview({...edit,token:saved.token,expiry:'preserve'});
    assert.equal(sent.at(-1).id,'internet');
    assert.equal(sent.at(-1).expected_version,3);
    assert.equal(sent.at(-1).rule.filter.network_zone,'internet');
    await assert.rejects(()=>rules.preview({...edit,token:saved.token,network_zone:'local'}),/immutable/);
    const finalPreview=await rules.preview({...edit,token:saved.token,expiry:'preserve'});
    assert.equal((await rules.save(finalPreview.receipt)).phase,'acknowledged');
  } finally { await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true}); }
});
