const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),net=require('node:net');
const {parseUpload,replaceCap,uploadTarget,uploadSummary,UPLOAD_CAPABILITY}=require('../dist/test/upload-shaping.cjs');
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
