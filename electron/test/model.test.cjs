const { test } = require('node:test');
const assert = require('node:assert/strict');
const { hierarchy, sum, flatten } = require('../dist/test/model.cjs');
function row(id, owners = [], traffic = {}) {
  return {
    id,
    owners,
    state: 'Established',
    socket: { protocol: 'tcp', state: 1, local: '[::1]:80', remote: '[::1]:90' },
    traffic: { available: true, definition: 'tcp', uploaded: 10, upload_bps: 2, ...traffic },
  };
}
test('shared/unknown counted once and incompatible sources never summed', () => {
  const a = {
    rows: [row('one', ['a', 'b']), row('one', ['a', 'b']), row('two', [], { definition: 'udp' })],
    processes: {},
  };
  const roots = hierarchy(a);
  assert.equal(roots.length, 1);
  assert.equal(roots[0].id, 'unidentified');
  assert.equal(roots[0].rows.length, 2);
  assert.equal(sum(roots[0].rows, 'uploaded').mixed, true);
  assert.equal(sum(roots[0].rows, 'uploaded').value, undefined);
});
test('numeric sort, partial and unavailable counters', () => {
  const roots = hierarchy({
    rows: [
      row('slow', [], { uploaded: 2 }),
      row('fast', [], { uploaded: 100 }),
      row('none', [], { available: false }),
    ],
    processes: {},
  });
  assert.deepEqual(
    flatten(roots, new Set(['unidentified']), 'uploaded', true)
      .slice(1)
      .map((v) => v.row.id),
    ['fast', 'slow', 'none'],
  );
  assert.equal(sum(roots[0].rows, 'uploaded').partial, true);
});
test('tree branches end at the last visible sibling in the current sort order', () => {
  const node = (id, children = []) => ({ id, label: id, children, rows: [] });
  const roots = [node('host', [node('app', [node('process', [node('socket')])]), node('other')])];
  const expanded = new Set(['host', 'app', 'process']);
  const guides = (descending) => flatten(roots, expanded, 'name', descending)
    .map(({ row: r, branches }) => [r.id, branches]);
  assert.deepEqual(guides(false), [
    ['host', []], ['app', [true]], ['process', [true, false]],
    ['socket', [true, false, false]], ['other', [false]],
  ]);
  assert.deepEqual(guides(true), [
    ['host', []], ['other', [true]], ['app', [false]], ['process', [false, false]],
    ['socket', [false, false, false]],
  ]);
  expanded.delete('app');
  assert.deepEqual(guides(false), [['host', []], ['app', [true]], ['other', [false]]]);
});
test('reassociation preserves backend socket ID; groups use executable identity', () => {
  const r = row('stable', []);
  const a = {
    rows: [r],
    processes: {
      p: {
        id: 'p',
        pid: 7,
        executable: '/a',
        application: { key: 'a', revision: 'r', name: 'same' },
      },
    },
  };
  assert.equal(hierarchy(a)[0].children[0].id, 'stable');
  r.owners = ['p'];
  assert.equal(hierarchy(a)[0].children[0].children[0].id, 'stable');
});
test('explicit display association groups shared sockets once; unresolved and inode-zero remain Unidentified', () => {
  const application = {
    key: 'native',
    revision: 'r',
    name: 'native app',
    executable: '/long/native/app',
  };
  const processes = {
    a: { id: 'a', pid: 11, uid: 1000, executable: application.executable, application },
    b: {
      id: 'b',
      pid: 12,
      uid: 1000,
      thread_group_pid: 10,
      executable: application.executable,
      application,
    },
  };
  const shared = {
    ...row('shared', ['a', 'b']),
    display_application: application,
    ownership_category: 'shared',
  };
  const unknown = { ...row('unknown'), ownership_category: 'unknown' },
    zero = { ...row('zero'), ownership_category: 'no-userspace-inode' };
  const a = { rows: [shared, unknown, zero, shared], processes };
  const roots = hierarchy(a);
  assert.equal(roots.length, 2);
  assert.equal(roots[0].children[0].id, 'shared');
  assert.equal(roots[0].rows.length, 1);
  assert.equal(sum(roots[0].rows, 'uploaded').value, 10);
  assert.equal(roots[1].id, 'unidentified');
  assert.equal(roots[1].rows.length, 2);
  delete shared.display_application;
  const regrouped = hierarchy(a);
  assert.equal(regrouped.length, 1);
  assert(regrouped[0].children.some((r) => r.id === 'shared'));
  assert.equal(sum(regrouped[0].rows, 'uploaded').value, 30);
  const worker = hierarchy({ rows: [row('worker', ['b'])], processes })[0].children[0];
  assert.match(worker.label, /Worker TID 12 \(process 10\)/);
  const { ownershipExplanation } = require('../dist/test/model.cjs');
  assert.match(ownershipExplanation('no-userspace-inode'), /No userspace inode/);
  assert.match(ownershipExplanation('unknown'), /do not prove/);
});
test('rate sorting uses numbers across units and leaves unavailable last in both directions', () => {
  const roots = hierarchy({
    rows: [
      row('small', [], { upload_bps: 900, download_bps: 900 }),
      row('large', [], { upload_bps: 2048, download_bps: 2048 }),
      row('missing', [], { available: false, upload_bps: undefined, download_bps: undefined }),
    ],
    processes: {},
  });
  for (const key of ['upload_bps', 'download_bps'])
    for (const desc of [true, false])
      assert.deepEqual(
        flatten(roots, new Set(['unidentified']), key, desc)
          .slice(1)
          .map((v) => v.row.id),
        desc ? ['large', 'small', 'missing'] : ['small', 'large', 'missing'],
      );
});

test('overview/source selection deduplicates sockets and preserves missing-source coverage', () => {
  const { overview } = require('../dist/test/model.cjs');
  const tcp = row('tcp', [], { definition: 'tcp-transport-payload', upload_bps: 120 });
  const udp = {
    ...row('udp', [], { definition: 'udp-api-reported', upload_bps: 70 }),
    socket: { protocol: 'udp' },
  };
  const missing = { ...row('missing', [], { available: false }), socket: { protocol: 'udp' } };
  const root = overview({ rows: [tcp, tcp, udp, missing] });
  assert.equal(root.rows.length, 3);
  assert.equal(root.kind, 'overview');
  assert.equal(root.process, undefined);
  assert.equal(sum(root.rows, 'upload_bps').value, undefined);
  assert.equal(sum(root.rows, 'upload_bps', 'tcp').value, 120);
  assert.deepEqual(sum(root.rows, 'upload_bps', 'udp'), {
    value: 70,
    partial: true,
    mixed: false,
    known: 1,
    count: 2,
  });
});

test('network rows stay pinned in fixed order and never invent totals', () => {
  const model = require('../dist/test/model.cjs');
  const rows = model.networkOverviews();
  rows.push({id:'app:z',kind:'application',label:'AAA',rows:[],children:[]});
  for (const key of ['name','upload_bps','download_bps']) for (const descending of [true,false]) {
    assert.deepEqual(model.flatten(rows,new Set(),key,descending).slice(0,2).map(x=>x.row.id),['network:internet','network:local']);
  }
  assert.equal(model.sum(rows[0].rows,'uploaded').value,undefined);
});

test('Windows runtime application owns its row while broker FD evidence stays intact',()=>{
 const {inactiveApplications}=require('../dist/test/model.cjs');
 const app={key:'pe',revision:'pe-rev',name:'Alpha.exe',executable:'/prefix/Alpha.exe'};
 const r=row('cookie',['broker']);r.runtime_application={application:app,uid:1000,evidence:{broker_pid:42}};
 const roots=hierarchy({rows:[r],processes:{broker:{id:'broker',uid:1000,pid:42,application:{key:'',revision:'',name:'wineserver'},executable:'/runtime/wineserver'}}});
 assert.equal(roots[0].id,'app:pe|pe-rev|uid:1000');
 assert.equal(roots[0].process,undefined);
 assert.deepEqual(r.owners,['broker']);
 assert.equal(inactiveApplications([{executable:app.executable,filter:{application:'pe',revision:'pe-rev',uid:1000}}],roots).length,0);
 assert.equal(inactiveApplications([{executable:'/usr/bin/python',filter:{application:'python',revision:'r',uid:1000}}],roots).length,1);
});

test('same verified Windows executable uses one application row for direct and broker sockets',()=>{
 const app={kind:'wine',key:'pe',revision:'r',name:'Alpha.exe',display_name:'Alpha · via wineserver',executable:'/p/Alpha.exe'};
 const direct=row('direct',['client']),broker=row('broker',['server']);
 broker.runtime_application={application:app,uid:1000,evidence:{}};
 const provenance={evidence:'verified',group:'launch',role:'game',launch:{game:{status:'verified-file',name:'Alpha.exe'},kind:'umu'}};
 const processes={client:{id:'client',pid:12,uid:1000,application:app,executable:'/runtime/wine',provenance},server:{id:'server',pid:13,uid:1000,application:{name:'wineserver'},executable:'/runtime/wineserver'}};
 for(const rows of [[direct,broker],[broker,direct]]){
  const roots=hierarchy({rows,processes});assert.equal(roots.length,1);assert.equal(roots[0].label,'Alpha.exe');assert.equal(roots[0].rows.length,2);assert.equal(roots[0].runtimeApplication.application.key,'pe');
 }
});

test('retained requests remain visible without claiming a live socket or merging authority', () => {
  const { activityTree }=require('../dist/test/model.cjs');
  const request=(id,key='app',uid=1000)=>({id,state:'awaiting-decision',remainingMs:1000,first_seen:'2026-01-01T00:00:00Z',attribution:{application:{key,revision:'r',name:'Runtime',executable:'/bin/runtime'},owners:[{uid}]}});
  const a={rows:[],processes:{}};
  const events=[request('a'),request('b'),request('c','other'),request('d','app',1001)];
  const rows=activityTree(a,[], '', 'all',undefined,undefined,events);
  assert.equal(rows.length,1);
  assert.equal(rows[0].kind,'program');
  assert.equal(rows[0].children.length,3);
  assert.equal(rows[0].requestEvent,undefined);
  assert.equal(rows[0].children[0].requestEvent.id,'a');
  assert.equal(rows[0].process,undefined);
  assert.equal(rows[0].inactive,undefined);
  assert.equal(rows[0].rows.length,0);
  assert.equal(activityTree(a,[],'missing','all',undefined,undefined,events).length,0);
  assert.equal(activityTree(a,[],'','active',undefined,undefined,events).length,0);
  const rule={filter:{application:'app',revision:'r',uid:1000},executable:'/bin/runtime'};
  const withRule=activityTree(a,[rule],'','all',undefined,undefined,[request('a')]);
  assert.equal(withRule.length,1);assert.equal(withRule[0].inactive.rules,1);assert.equal(withRule[0].requestEvent.id,'a');
  const terminal={...request('old'),state:'expired',remainingMs:0,first_seen:'2026-01-02T00:00:00Z'};
  assert.equal(activityTree(a,[],'','all',undefined,undefined,[terminal,request('live')])[0].requestEvent.id,'live');
});
