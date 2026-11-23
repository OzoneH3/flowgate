const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),net=require('node:net');
const {parseUpload,replaceCap,uploadTarget,uploadSummary,limitCoverage,UPLOAD_CAPABILITY,UPLOAD_RATE_UNITS,uploadRateBits,uploadRateValue}=require('../dist/test/upload-shaping.cjs');
const {UploadShapingClient}=require('../dist/test/upload-shaping-client.cjs');
const cap={uid:1000,application:'native-alpha',bits_per_second:8000000};
const snap=(extra={})=>({version:1,applied_version:1,enabled:true,interface:'lab0',status:'Partial',configured_caps:[cap],...extra});
test('full replacement preserves independent caps and last removal disables by empty result',()=>{
 const s=snap({configured_caps:[cap,{...cap,uid:1001}]});
 assert.deepEqual(replaceCap(s,{expected_version:1,target:cap,bits_per_second:32000000}),[{...cap,uid:1001},{...cap,bits_per_second:32000000}]);
 assert.deepEqual(replaceCap(snap(),{expected_version:1,target:cap,bits_per_second:null}),[]);
 assert.throws(()=>replaceCap(s,{expected_version:2,target:cap,bits_per_second:null}),/changed/);
 assert.throws(()=>replaceCap(s,{expected_version:1,target:cap,bits_per_second:0}),/rate/);
 assert.throws(()=>replaceCap(s,{expected_version:1,target:cap}),/Invalid/);
 assert.equal(parseUpload(snap({enabled:false,configured_caps:null})).configured_caps.length,0);
});
test('candidate targets require native verified identity, never runtime/shared display',()=>{
 const r={kind:'application',label:'A',process:{uid:1000,application:{key:'a',revision:'r',kind:'native'}}};
 assert.equal(uploadTarget(r,{observation:{connected:true}}).application,'a');
 assert.equal(uploadTarget({...r,displayApplication:{}},{observation:{connected:true}}),undefined);
 assert.equal(uploadTarget({...r,process:{...r.process,application:{...r.process.application,kind:'wine'}}},{observation:{connected:true}}),undefined);
 assert.equal(uploadTarget({...r,kind:'socket'},{observation:{connected:true}}),undefined);
 assert.equal(uploadSummary({supported:true,snapshot:snap({status:'Active'})},cap),'8 Mbit/s · Partial');
 assert.equal(uploadSummary({supported:true,snapshot:snap({applied_version:0})},cap),'Pending');
});
async function harness(t){
 const dir=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/ul-')),sock=path.join(dir,'s');let current=snap(),drop=false;const calls=[];
 const server=net.createServer(s=>s.once('data',data=>{const r=JSON.parse(data);calls.push(r);if(r.operation==='upload-configure'){current=snap({version:current.version+1,applied_version:current.version,status:'Applying',enabled:r.upload_config.enabled,configured_caps:r.upload_config.caps});if(drop){s.end();return;}}
 s.end(JSON.stringify({version:1,generation:'g1',read_only:false,server_time:new Date().toISOString(),upload_shaping:current})+'\n');}));
 await new Promise(r=>server.listen(sock,r));t.after(()=>new Promise(r=>server.close(()=>{fs.rmSync(dir,{recursive:true,force:true});r();})));
 const state={control:{connected:true,generation:'g1',readOnly:false,permissions:{role:'administrator'},capabilities:[UPLOAD_CAPABILITY]},observation:{connected:true,activity:{processes:{a:{uid:1000,application:{key:'native-alpha',revision:'r1',kind:'native'}}}}}};
 return {client:new UploadShapingClient({controller:sock,view:()=>state}),state,calls,setSnapshot:v=>current=v,drop:()=>drop=true};
}
test('CAS configure is firewall-independent; lost receipt never replayed and status reconciles',async t=>{
 const h=await harness(t);const edit={generation:'g1',expected_version:1,target:cap,bits_per_second:null};h.drop();
 await assert.rejects(h.client.configure(edit),/no automatic retry/);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,1);
 assert.deepEqual(h.calls[1].upload_config,{enabled:false,caps:[]});
 const now=await h.client.read();assert.equal(now.snapshot.version,2);assert.equal(now.snapshot.configured_caps.length,0);
 await assert.rejects(h.client.configure(edit),/changed/);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,1);
 assert.ok(h.calls.every(c=>['upload-status','upload-configure'].includes(c.operation)));
});
test('read-only and stale generation cannot submit',async t=>{
 const h=await harness(t);h.state.control.readOnly=true;
 await assert.rejects(h.client.configure({}),/administrator write/);
 h.state.control.readOnly=false;
 await assert.rejects(h.client.configure({generation:'old'}),/Daemon changed/);
 assert.equal(h.calls.length,0);
});

test('journal cleanup retry requires current disabled empty configuration',async t=>{
 const h=await harness(t);const cleanup={generation:'g1',expected_version:1,cleanup_only:true};
 await assert.rejects(h.client.configure(cleanup),/disabled, empty/);
 h.setSnapshot(snap({enabled:false,configured_caps:[],status:'Unsupported'}));
 const result=await h.client.configure(cleanup);
 assert.equal(result.snapshot.version,2);
 assert.deepEqual(h.calls.filter(c=>c.operation==='upload-configure')[0].upload_config,{enabled:false,caps:[]});
});
test('new caps require connected observation of the reviewed native revision',async t=>{
 const h=await harness(t),e={generation:'g1',expected_version:1,target:{...cap,revision:'r1'},bits_per_second:32000000};
 h.state.observation.connected=false;
 await assert.rejects(h.client.configure(e),/disconnected/);
 h.state.observation.connected=true;e.target.revision='old';
 await assert.rejects(h.client.configure(e),/No current native/);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,0);
});

test('a saved native app can be configured with no process, but identities stay exact',async t=>{
 const h=await harness(t);
 h.state.observation={connected:false};
 const saved={kind:'application',label:'Saved alpha',inactive:{uid:1000,key:'native-alpha',revision:'r1'}};
 const rule={filter:{uid:1000,application:'native-alpha',revision:'r1'},native_shaping_identity:true};
 h.state.control.rules=[rule];
 const target=uploadTarget(saved,h.state);
 assert.deepEqual(target,{uid:1000,application:'native-alpha',revision:'r1',label:'Saved alpha'});
 const edit={generation:'g1',expected_version:1,target,bits_per_second:32000000};
 for(const changed of [{uid:1001},{revision:'r2'},{application:'other'}])
  await assert.rejects(h.client.configure({...edit,target:{...target,...changed}}),/no saved native/);
 h.state.control.rules=[{...rule,native_shaping_identity:false}];
 assert.equal(uploadTarget(saved,h.state),undefined);
 await assert.rejects(h.client.configure(edit),/no saved native/);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,0);
 h.state.control.rules=[rule];
 const result=await h.client.configure(edit);
 assert.equal(result.snapshot.configured_caps[0].bits_per_second,32000000);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,1);
});

test('upload rate units preserve exact integer bit rates through decimal byte/bit views',()=>{
 for(const bits of [1000000,1000001,1600000,8000000,32000000,1000000000])
   for(const unit of UPLOAD_RATE_UNITS) assert.equal(uploadRateBits(uploadRateValue(bits,unit),unit),bits,`${bits} ${unit}`);
 assert.equal(uploadRateBits('200','KB/s'),1638400);
 assert.equal(uploadRateBits('0.125','MB/s'),1048576);
 assert.equal(uploadRateBits('1','Gbit/s'),1000000000);
 for(const [value,unit] of [['0.1','Mbit/s'],['1001','Mbit/s'],['NaN','bit/s'],['1e6','bit/s'],['125000.01','B/s'],['8','KiB/s']])
   assert.throws(()=>uploadRateBits(value,unit));
});

test('directional edits preserve the other limit and remove the app only after both are removed',()=>{
 const both={...cap,download_bits_per_second:16000000}, s=snap({configured_caps:[both]});
 assert.deepEqual(replaceCap(s,{expected_version:1,target:cap,direction:'download',bits_per_second:32000000}),[{...both,download_bits_per_second:32000000}]);
 assert.deepEqual(replaceCap(s,{expected_version:1,target:cap,direction:'download',bits_per_second:null}),[cap]);
 const downOnly={...both,bits_per_second:0};
 assert.deepEqual(replaceCap(s,{expected_version:1,target:cap,bits_per_second:null}),[downOnly]);
 assert.deepEqual(replaceCap(snap({configured_caps:[downOnly]}),{expected_version:1,target:cap,direction:'download',bits_per_second:null}),[]);
 assert.deepEqual(parseUpload(snap({configured_caps:[downOnly]})).configured_caps,[downOnly]);
 assert.throws(()=>parseUpload(snap({configured_caps:[{...cap,bits_per_second:0}]})),/rate/);
 assert.throws(()=>parseUpload(snap({configured_caps:[{...cap,download_bits_per_second:1}]})),/rate/);
 assert.throws(()=>replaceCap(s,{expected_version:1,target:cap,direction:'sideways',bits_per_second:null}),/Invalid/);
 assert.equal(uploadSummary({supported:true,downloadSupported:true,snapshot:s},cap,'download'),'16 Mbit/s · Partial');
 assert.equal(uploadSummary({supported:true,snapshot:s},cap,'download'),'Unsupported');
 assert.equal(uploadSummary({supported:true,downloadSupported:true,snapshot:snap({configured_caps:[downOnly]})},cap),'Off');
});
test('download writes require capability and keep upload policy and rate intact',async t=>{
 const h=await harness(t),e={generation:'g1',expected_version:1,target:{...cap,revision:'r1'},direction:'download',bits_per_second:16000000};
 await assert.rejects(h.client.configure(e),/not supported/);
 assert.equal(h.calls.length,0);
 h.state.control.capabilities.push('experimental-native-download-v1');
 const status=await h.client.read();assert.equal(status.downloadSupported,true);
 await h.client.configure(e);
 assert.deepEqual(h.calls.find(c=>c.operation==='upload-configure').upload_config,{enabled:true,caps:[{...cap,download_bits_per_second:16000000}]});
 assert.ok(h.calls.every(c=>['upload-status','upload-configure'].includes(c.operation)));
});

test('download coverage excludes upload-only bindings and expired leases',()=>{
 const s=snap({configured_caps:[{...cap,download_bits_per_second:16000000}],kernel:{bindings:[{app:'1000:native-alpha',covered:true,download:true,upload_class:true,download_class:true},{app:'1000:native-alpha',covered:true,download:false,upload_class:true,download_class:false},{app:'1000:native-alpha',covered:false,download:true},{app:'1001:other',covered:true,download:true,upload_class:true,download_class:true}]}});
 assert.deepEqual(limitCoverage(s,cap,'download',false),{requested:3,confirmed:1});
 assert.deepEqual(limitCoverage(s,cap,'upload',false),{requested:3,confirmed:2});
 assert.deepEqual(limitCoverage(s,cap,'download',true),{requested:3,confirmed:0});
});

test('coverage is zero for an unconfigured direction even when the other direction is bound',()=>{
 const kernel={bindings:[{app:'1000:native-alpha',covered:true,download:true,upload_class:true,download_class:true}]};
 const down=snap({configured_caps:[{...cap,bits_per_second:0,download_bits_per_second:16000000}],kernel});
 assert.deepEqual(limitCoverage(down,cap,'upload',false),{requested:0,confirmed:0});
 assert.deepEqual(limitCoverage(down,cap,'download',false),{requested:1,confirmed:1});
 const up=snap({kernel});
 assert.deepEqual(limitCoverage(up,cap,'download',false),{requested:0,confirmed:0});
 assert.deepEqual(limitCoverage(up,cap,'upload',false),{requested:1,confirmed:1});
});

const prio=require('../dist/test/upload-shaping.cjs');
test('traffic priority edits keep both rates; rate edits keep priority; Normal removes only the priority',()=>{
 const both={...cap,download_bits_per_second:16000000};
 const s=snap({configured_caps:[both]});
 assert.deepEqual(prio.replaceCap(s,{expected_version:1,target:cap,bits_per_second:null,priority:'high'}),[{...both,traffic_priority:'high'}]);
 const withPrio=snap({configured_caps:[{...both,traffic_priority:'low'}]});
 assert.deepEqual(prio.replaceCap(withPrio,{expected_version:1,target:cap,direction:'download',bits_per_second:null}),[{...cap,traffic_priority:'low'}]);
 assert.deepEqual(prio.replaceCap(withPrio,{expected_version:1,target:cap,bits_per_second:null,priority:'normal'}),[both]);
 // Priority-only entry: deleting the priority removes the entry; deleting its last cap keeps the priority.
 const only=snap({configured_caps:[{uid:1000,application:'native-alpha',bits_per_second:0,traffic_priority:'high'}]});
 assert.deepEqual(prio.replaceCap(only,{expected_version:1,target:cap,bits_per_second:null,priority:'normal'}),[]);
 assert.deepEqual(prio.replaceCap(withPrio,{expected_version:1,target:cap,direction:'upload',bits_per_second:null}).map(c=>c.traffic_priority),['low']);
 assert.throws(()=>prio.replaceCap(s,{expected_version:1,target:cap,bits_per_second:null,priority:'critical'}),/Invalid traffic priority/);
 assert.throws(()=>prio.validateBudget(15999999));assert.equal(prio.validateBudget(0),0);
 assert.equal(prio.prioritySummary({supported:true,prioritySupported:true,snapshot:only},cap),'High · inactive (no budget)');
 assert.equal(prio.prioritySummary({supported:true,prioritySupported:true,snapshot:{...only,upload_budget_bits_per_second:40000000}},cap),'High · UL budget · Partial');
 assert.equal(prio.prioritySummary({supported:true,prioritySupported:false,snapshot:only},cap),'Unsupported');
 const k={bindings:[{app:'1000:native-alpha',covered:true,upload_class:true,download_class:false},{app:'1000:native-alpha',covered:true,upload_class:false}]};
 assert.deepEqual(prio.priorityCoverage({...only,upload_budget_bits_per_second:40000000,kernel:k},cap,false),{requested:2,confirmed:1});
 assert.deepEqual(prio.priorityCoverage({...only,kernel:k},cap,false),{requested:0,confirmed:0});
 assert.deepEqual(prio.priorityCoverage({...only,upload_budget_bits_per_second:40000000,kernel:k},cap,true),{requested:2,confirmed:0});
});
test('schema 2 is sent only with the capability; budgets are preserved unless edited',async t=>{
 const h=await harness(t);
 await assert.rejects(h.client.configure({generation:'g1',expected_version:1,target:{...cap,revision:'r1'},bits_per_second:null,priority:'high'}),/not supported/);
 assert.equal(h.calls.filter(c=>c.operation==='upload-configure').length,0);
 h.state.control.capabilities.push(prio.PRIORITY_CAPABILITY);
 h.setSnapshot(snap({upload_budget_bits_per_second:40000000}));
 await h.client.configure({generation:'g1',expected_version:1,target:{...cap,revision:'r1'},bits_per_second:null,priority:'high'});
 const sent=h.calls.filter(c=>c.operation==='upload-configure').at(-1).upload_config;
 assert.deepEqual(sent,{enabled:true,caps:[{...cap,traffic_priority:'high'}],schema:2,upload_budget_bits_per_second:40000000,download_budget_bits_per_second:0});
 h.setSnapshot(snap({version:2,configured_caps:[{...cap,traffic_priority:'high'}],upload_budget_bits_per_second:40000000}));
 await h.client.configure({generation:'g1',expected_version:2,budgets:{upload:0,download:40000000}});
 const b=h.calls.filter(c=>c.operation==='upload-configure').at(-1).upload_config;
 assert.deepEqual(b,{enabled:true,caps:[{...cap,traffic_priority:'high'}],schema:2,upload_budget_bits_per_second:0,download_budget_bits_per_second:40000000});
 await assert.rejects(h.client.configure({generation:'g1',expected_version:1,budgets:{upload:0,download:0}}),/changed/);
});

test('every coverage adoption is anchored at a timestamp captured before its request',()=>{
 // Regression guard: adopt() adds coverage_valid_for_ms to its anchor, so an anchor taken
 // after the reply would extend coverage by the response latency.
 const src=fs.readFileSync(path.resolve(__dirname,'../src/upload-shaping-view.ts'),'utf8');
 const calls=[...src.matchAll(/adopt\(([^)]*)\)/g)].map(m=>m[1]).filter(a=>a.includes(',')&&!a.includes(':'));
 assert.ok(calls.length>=4,calls);
 for(const a of calls)assert.match(a,/^\w+,(sent)$/,a);
 assert.ok(!/adopt\([^)]*performance\.now\(\)/.test(src));
});

test('zone edits preserve combined ceiling, other zone, opposite direction and explicit Normal',()=>{
 const all={...cap,traffic_priority:'high'},local={...cap,scope:'local',bits_per_second:4000000,download_bits_per_second:6000000},internet={...cap,scope:'internet',bits_per_second:2000000};
 const s=snap({configured_caps:[all,local,internet]});
 const edited=replaceCap(s,{expected_version:1,target:internet,direction:'download',bits_per_second:3000000});
 assert.deepEqual(edited.slice(0,2),[all,local]);assert.equal(edited[2].bits_per_second,2000000);
 const normal=replaceCap({...s,configured_caps:edited},{expected_version:1,target:internet,priority:'normal',bits_per_second:null});
 assert.equal(normal[2].traffic_priority,'normal');
 const removed=replaceCap({...s,configured_caps:normal},{expected_version:1,target:internet,priority:null,bits_per_second:null});
 assert.equal(removed[2].traffic_priority,undefined);assert.equal(removed[2].download_bits_per_second,3000000);
 const deleted=replaceCap(s,{expected_version:1,target:internet,bits_per_second:null});assert.deepEqual(deleted,[all,local]);
 assert.throws(()=>replaceCap(s,{expected_version:2,target:internet,bits_per_second:null}),/changed/);
 assert.deepEqual(replaceCap(snap(),{expected_version:1,target:{...cap,scope:'all'},bits_per_second:null}),[]);
 assert.throws(()=>replaceCap(s,{expected_version:1,target:{...cap,scope:'unknown'},bits_per_second:1000000}),/zone/);
});
test('zone coverage excludes other and unknown classifier assignments',()=>{
 const target={...cap,scope:'internet'};
 const s=snap({configured_caps:[target],kernel:{bindings:[{app:'1000:native-alpha',zone:'internet',covered:true,download:true,upload_class:true,download_class:true},{app:'1000:native-alpha',zone:'local',covered:true,download:true,upload_class:true,download_class:true},{app:'1000:native-alpha',zone:'',covered:true,download:true,upload_class:true,download_class:true}]}});
 assert.deepEqual(limitCoverage(s,target,'upload',false),{requested:1,confirmed:1});
 assert.deepEqual(limitCoverage({...s,configured_caps:[cap]},cap,'upload',false),{requested:3,confirmed:3});
 assert.deepEqual(limitCoverage(s,target,'upload',true),{requested:1,confirmed:0});
});
test('zoned hierarchy capacity rejected before submission',()=>{
 const caps=Array.from({length:4},(_,i)=>({...cap,application:'synthetic-'+i,scope:'local'}));
 assert.throws(()=>replaceCap(snap({configured_caps:caps}),{expected_version:1,target:cap,bits_per_second:1000000}),/capacity/);
 assert.equal(replaceCap(snap({configured_caps:caps}),{expected_version:1,target:{...caps[0],scope:'internet'},bits_per_second:1000000}).length,5);
});
test('zone capability gates writes and schema 3 preserves every scope and all-traffic budgets',async t=>{
 const h=await harness(t),target={...cap,scope:'internet',revision:'r1'};
 await assert.rejects(h.client.configure({generation:'g1',expected_version:1,target,bits_per_second:2000000}),/Zone shaping/);
 assert.equal(h.calls.length,0);
 h.state.control.capabilities.push('experimental-traffic-priority-v1','experimental-zone-shaping-v1');
 h.setSnapshot(snap({upload_budget_bits_per_second:20000000,download_budget_bits_per_second:30000000}));
 const result=await h.client.configure({generation:'g1',expected_version:1,target,bits_per_second:2000000});
 assert.equal(result.zoneSupported,true);
 const payload=h.calls.find(c=>c.operation==='upload-configure').upload_config;
 assert.equal(payload.schema,3);assert.deepEqual(payload.caps,[cap,{uid:1000,application:'native-alpha',scope:'internet',bits_per_second:2000000}]);
 assert.equal(payload.upload_budget_bits_per_second,20000000);assert.equal(payload.download_budget_bits_per_second,30000000);
});


test('shaping defaults validate independent exact rates and units without rule writes',()=>{
 const {DEFAULT_SHAPING,validateShapingDefaults}=require('../dist/test/upload-shaping.cjs');
 assert.equal(DEFAULT_SHAPING.priority,'normal');
 const d={priority:'high',uploadBits:8388608,downloadBits:16000000,uploadUnit:'MB/s',downloadUnit:'Mbit/s'};
 assert.deepEqual(validateShapingDefaults(d),d);
 for(const bad of [null,{}, {...d,priority:'critical'}, {...d,uploadBits:999999}, {...d,downloadBits:1000000001}, {...d,uploadUnit:'Mbps'}, {...d,enabled:true}])assert.throws(()=>validateShapingDefaults(bad));
 assert.deepEqual(DEFAULT_SHAPING,{priority:'normal',uploadBits:8000000,downloadBits:8000000,uploadUnit:'Mbit/s',downloadUnit:'Mbit/s'});
});


test('zone row targets retain verified native identity and require the current classification model',()=>{
 const row={kind:'application',label:'Alpha, Local Network',process:{uid:1000,application:{key:'alpha',revision:'r',kind:'native'}},applicationZone:{zone:'local',model:'automatic-peer-v1',parentLabel:'Alpha'}};
 const state={observation:{connected:true},control:{capabilities:['experimental-zone-shaping-v1'],networkZones:{model:'automatic-peer-v1'}}};
 assert.deepEqual(uploadTarget(row,state),{uid:1000,application:'alpha',revision:'r',label:row.label,scope:'local'});
 assert.equal(uploadTarget({...row,applicationZone:{...row.applicationZone,zone:'internet'}},state).scope,'internet');
 assert.equal(uploadTarget({...row,applicationZone:{...row.applicationZone,model:'configured-prefix-v1'}},state),undefined);
 assert.equal(uploadTarget(row,{...state,control:{...state.control,capabilities:[]}}),undefined);
 assert.equal(uploadTarget(row,{...state,control:{capabilities:state.control.capabilities}}),undefined);
 for(const changed of [{displayApplication:{}},{runtimeApplication:{}},{inactive:{}},{process:{...row.process,application:{...row.process.application,kind:'wine'}}},{process:{...row.process,application:{...row.process.application,hosted:true}}}])
  assert.equal(uploadTarget({...row,...changed},state),undefined);
 assert.equal(uploadTarget({...row,process:{...row.process,uid:1001}},state).uid,1001);
});

test('unavailable shaping explains runtime scope and host journal without creating a target',()=>{
 const {shapingUnavailableReason,uploadTarget,UPLOAD_CAPABILITY,DOWNLOAD_CAPABILITY,PRIORITY_CAPABILITY}=require('../dist/test/upload-shaping.cjs');
 const row={kind:'application',label:'Synthetic Windows app',runtimeApplication:{application:{kind:'wine'}}};
 const state={observation:{connected:true},control:{connected:true,readOnly:false,permissions:{role:'administrator'},capabilities:[UPLOAD_CAPABILITY,DOWNLOAD_CAPABILITY,PRIORITY_CAPABILITY]}};
 const view={supported:true,writable:true,message:'unavailable',snapshot:{status:'Unsupported',last_error:'Owned journal remains; explicit configuration required for verified reconciliation'}};
 for(const kind of ['upload','download','priority']) {
  const reason=shapingUnavailableReason(row,state,view,kind);
  assert.match(reason,/Wine\/runtime or shared-owner/);assert.match(reason,/Owned journal remains/);
 }
 assert.equal(uploadTarget(row,state),undefined);
 const native={kind:'application',process:{uid:1000,application:{kind:'native',key:'synthetic-native',revision:'r'}}};
 assert.equal(shapingUnavailableReason(native,state,{supported:true,writable:true,message:'ready'},'upload'),undefined);
 assert.match(shapingUnavailableReason(native,state,view,'priority'),/Host shaping unavailable/);
});

test('direction coverage requires the actual class, not another direction or an acknowledged configuration',()=>{
 const s=snap({configured_caps:[{...cap,download_bits_per_second:16000000}],kernel:{bindings:[{app:'1000:native-alpha',covered:true,download:true,upload_class:false,download_class:true}]}});
 assert.deepEqual(limitCoverage(s,cap,'upload',false),{requested:1,confirmed:0});
 assert.deepEqual(limitCoverage(s,cap,'download',false),{requested:1,confirmed:1});
 assert.deepEqual(limitCoverage({...s,kernel:{bindings:[]}},cap,'upload',false),{requested:0,confirmed:0});
});
