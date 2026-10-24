const {test}=require('node:test'),assert=require('node:assert/strict'),net=require('node:net'),fs=require('node:fs'),path=require('node:path');
const {EndpointRules}=require('../dist/test/endpoint-rules.cjs');
const {parseRule,parseReply}=require('../dist/test/protocol.cjs');
const {Rules}=require('../dist/test/rules.cjs');
const {endpointAddress,validateEndpointDraft,canManageEndpoints,ENDPOINT_ZERO_EXPIRY,ENDPOINT_SCOPE,ENDPOINT_PRECEDENCE}=require('../dist/test/endpoint-policy.cjs');
const {attributionReasonLabel}=require('../dist/test/attribution-reason.cjs');
const now=Date.now(),draft={action:'allow',remote_address:'192.0.2.40',remote_port:8445,expires:ENDPOINT_ZERO_EXPIRY};
function rule(d=draft){return {schema:7,network_endpoint:true,id:'endpoint:reserved',version:1,created:new Date(now).toISOString(),priority:100,disabled:false,action:d.action,expires:d.expires,filter:{application:'',revision:'',uid:0,all_programs:true,all_uids:true,direction:'outgoing',protocol:'tcp',remote_address:d.remote_address,remote_port:d.remote_port}};}
function response(extra={}){return {version:1,generation:'g',read_only:false,mode:'host-enforcement',server_time:new Date(now).toISOString(),...extra};}
async function fixture(t){
 const dir=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/endpoint-client-')),socket=path.join(dir,'s');
 let mode='ack',stored=[],requests=[],saved,hook=()=>{};
 const state={control:{connected:true,readOnly:false,generation:'g',permissions:{can_manage_rules:true,can_manage_machine_rules:true},capabilities:['network-endpoint-policy-v1','conditional-rule-delete-v1'],rules:[]}};
 const server=net.createServer(s=>s.once('data',buf=>{
  const q=JSON.parse(buf);requests.push(q);hook(q);
  if(q.operation==='endpoint-rule-preview'){
   saved=rule(q.endpoint_draft);
   if(mode==='widen')saved.filter.remote_port=1;
   if(mode==='users')saved.filter.all_uids=false;
   if(mode==='forged')saved.filter.process={pid:1};
   if(mode==='scope')saved.network_endpoint=false;
   return s.end(JSON.stringify(response({endpoint_preview:{token:'server-preview',expires_at:new Date(now+30000).toISOString(),rule:saved,scope_preview:ENDPOINT_SCOPE+' '+ENDPOINT_PRECEDENCE,enforcement:{state:'active',covered:mode==='coverage'?'yes':true,reason:'outgoing active'}}}))+'\n');
  }
  if(q.operation==='endpoint-rule-save'){
   if(mode==='reject')return s.end(JSON.stringify(response({error_code:'policy_conflict',error:'Policy changed'}))+'\n');
   stored=[saved];
   if(mode==='lost')return s.destroy();
   const reply=structuredClone(saved);if(mode==='ack-tamper')reply.filter.remote_port++;
   return s.end(JSON.stringify(response({saved_rule:{...reply,follows_updates:false},scope_preview:ENDPOINT_SCOPE}))+'\n');
  }
  if(q.operation==='rule-delete')return s.end(JSON.stringify(response({deleted_rule:{id:q.id,version:q.expected_version}}))+'\n');
  s.end(JSON.stringify(response({rules:stored.map(r=>({...r,follows_updates:false}))}))+'\n');
 }));
 await new Promise(resolve=>server.listen(socket,resolve));
 t.after(()=>new Promise(resolve=>server.close(()=>{fs.rmSync(dir,{recursive:true,force:true});resolve();})));
 const b={controller:socket,view:()=>state,now:()=>now,pollControl:async()=>{}};
 return {client:new EndpointRules(b),generic:new Rules(b),state,b,requests,setMode:v=>mode=v,setStored:v=>stored=v,setHook:v=>hook=v};
}
test('endpoint scope requires explicit safe IP/port/action/expiry, canonicalizes mapped IPv6',()=>{
 assert.equal(endpointAddress('::ffff:192.0.2.40'),'192.0.2.40');assert.equal(endpointAddress('2001:0db8:0:0::1'),'2001:db8::1');
 for(const v of ['*','example.test','192.0.2.0/24','127.0.0.1','::1','::','0.0.0.0','224.0.0.1','ff02::1','169.254.2.1','fe80::1','fe80::1%eth0','255.255.255.255','010.0.0.1','[2001:db8::1]'])assert.throws(()=>endpointAddress(v),v);
 assert.deepEqual(validateEndpointDraft(draft,now),draft);
 for(const extra of [{action:'ask'},{remote_port:0},{remote_port:65536},{remote_port:1.5},{expires:''},{expires:new Date(now-1).toISOString()},{expires:new Date(now+366*86400000).toISOString()},{uid:0},{direction:'incoming'},{disabled:true}])assert.throws(()=>validateEndpointDraft({...draft,...extra},now),JSON.stringify(extra));
});
test('schema7 is distinct and strictly refuses application, user, zone and hidden scope fields',()=>{
 assert.equal(parseRule(rule()).network_endpoint,true);
 assert.equal(parseReply(response({rules:[{...rule(),follows_updates:false}]})).rules[0].network_endpoint,true);
 assert.equal(parseReply(response({saved_rule:{...rule(),follows_updates:false}})).saved_rule.network_endpoint,true);
 assert.throws(()=>parseRule({...rule(),follows_updates:true}));
 for(const change of [{schema:2},{network_endpoint:false},{share_with_root:true},{invocation:{}},{executable:'/tmp/program'},{preset:{}},{action:'ask'},{priority:0}])assert.throws(()=>parseRule({...rule(),...change}));
 for(const change of [{application:'key'},{uid:1000},{all_uids:false},{direction:'incoming'},{protocol:'udp'},{remote_address:'192.0.2.0/24'},{local_port:0},{network_zone:'local'},{process:{}},{surprise:true}])assert.throws(()=>parseRule({...rule(),filter:{...rule().filter,...change}}));
 assert.equal(attributionReasonLabel('no_userspace_owner_observed'),'No userspace owner observed');
});
test('client requires explicit admin capability and complete inventory; no request reaches API otherwise',async t=>{
 for(const change of [{readOnly:true},{connected:false},{capabilities:[]},{permissions:{can_manage_rules:true}},{permissions:{can_manage_machine_rules:true}}]){
  const f=await fixture(t);Object.assign(f.state.control,change);assert.equal(canManageEndpoints(f.state.control),false);await assert.rejects(f.client.preview(draft));assert.equal(f.requests.length,0);
 }
});
test('preview/save protects reviewed full scope and requires acknowledgement; renderer cannot mutate receipt',async t=>{
 const f=await fixture(t),p=await f.client.preview(draft);
 await assert.rejects(f.client.save({receipt:p.receipt,acknowledge_scope:false}));
 p.rule.filter.remote_port=1;
 const r=await f.client.save({receipt:p.receipt,acknowledge_scope:true});assert.equal(r.phase,'acknowledged');
 assert.deepEqual(f.requests.find(q=>q.operation==='endpoint-rule-save').endpoint_draft,draft);assert.equal(r.rule.filter.remote_port,8445);
});
test('changed preview semantics and invalid coverage never permit a save',async t=>{
 for(const mode of ['widen','users','forged','scope','coverage']){
  const f=await fixture(t);f.setMode(mode);await assert.rejects(f.client.preview(draft));assert.equal(f.requests.filter(q=>q.operation==='endpoint-rule-save').length,0);
 }
});
test('changed generation/controller/inventory is rejected before creation',async t=>{
 for(const change of ['generation','controller','rules']){
  const f=await fixture(t),p=await f.client.preview(draft);
  if(change==='generation')f.state.control.generation='other';if(change==='controller')f.b.controller+='.other';if(change==='rules')f.state.control.rules=[parseRule(rule())];
  await assert.rejects(f.client.save({receipt:p.receipt,acknowledge_scope:true}));assert.equal(f.requests.filter(q=>q.operation==='endpoint-rule-save').length,0);
 }
});
test('unknown save is never resent and only exact reserved inventory can confirm it',async t=>{
 const f=await fixture(t),p=await f.client.preview(draft);f.setMode('lost');
 const a=await f.client.save({receipt:p.receipt,acknowledge_scope:true});assert.equal(a.phase,'unknown');
 const repeat=await f.client.save({receipt:p.receipt,acknowledge_scope:true});assert.equal(repeat.phase,'unknown');assert.equal(f.requests.filter(q=>q.operation==='endpoint-rule-save').length,1);
 f.setStored([{...rule(),filter:{...rule().filter,remote_port:8446}}]);assert.equal((await f.client.reconcile(p.receipt)).phase,'unknown');
 f.setStored([rule()]);assert.equal((await f.client.reconcile(p.receipt)).phase,'acknowledged');assert.equal(f.requests.filter(q=>q.operation==='endpoint-rule-save').length,1);
});
test('refused and mismatched save acknowledgements do not claim success',async t=>{
 for(const mode of ['reject','ack-tamper']){const f=await fixture(t),p=await f.client.preview(draft);f.setMode(mode);const a=await f.client.save({receipt:p.receipt,acknowledge_scope:true});assert.equal(a.phase,mode==='reject'?'rejected':'unknown');}
});
test('endpoint generic edit/basis refused; conditional deletion requires administrator',async t=>{
 const f=await fixture(t);f.state.control.rules=[parseRule(rule())];
 await assert.rejects(f.generic.draft({id:'endpoint:reserved'}));
 f.state.control.capabilities.push('rule-from-basis-v1');await assert.rejects(f.generic.draft({basis:{rule:'endpoint:reserved',direction:'outgoing'}}));
 f.state.control.permissions.can_manage_machine_rules=false;
 await assert.rejects(f.generic.delete({id:'endpoint:reserved',generation:'g',version:1}));assert.equal(f.requests.length,0);
 f.state.control.permissions.can_manage_machine_rules=true;
 assert.equal((await f.generic.delete({id:'endpoint:reserved',generation:'g',version:1})).phase,'acknowledged');
});

test('role, capability, controller and generation changes during preview/save never claim success',async t=>{
 for(const phase of ['preview','save'])for(const change of ['role','capability','controller','generation']){
  const f=await fixture(t);let p;if(phase==='save')p=await f.client.preview(draft);
  f.setHook(q=>{if(q.operation!=='endpoint-rule-'+phase)return;
   if(change==='role')f.state.control.permissions.can_manage_machine_rules=false;
   if(change==='capability')f.state.control.capabilities=[];
   if(change==='controller')f.b.controller+='other';
   if(change==='generation')f.state.control.generation='other';
  });
  if(phase==='preview')await assert.rejects(f.client.preview(draft));
  else assert.equal((await f.client.save({receipt:p.receipt,acknowledge_scope:true})).phase,'unknown');
 }
});
test('policy projection preserves endpoint tier without converting it to application ownership',()=>{
 const {parsePolicyView}=require('../dist/test/policy.cjs');
 const r=rule();const ref={id:r.id,version:'1',priority:100,action:r.action,scope:r.filter,disabled:false,expired:false,active:true,expires:r.expires,target_scope:'network-endpoint',target_state:'active',target_reason:'Explicit all-traffic endpoint',kind:'scoped'};
 const v=parsePolicyView({snapshot:{generation:'g',token:'t',sequence:'1',evaluated_at:new Date(now).toISOString(),meaning:'Policy snapshot'},activity_sequence:'1',activity_collected:new Date(now).toISOString(),activity_available:true,complete:true,applications:[],rows:[],network_endpoints:[ref]});
 assert.equal(v.network_endpoints[0].target_scope,'network-endpoint');assert.equal(v.applications.length,0);assert.equal(v.network_endpoints[0].scope.application,'');
});

test('recorded endpoint rule scope stays distinct from a fabricated application',()=>{
 const {parseRecord}=require('../dist/test/decision-log.cjs');
 const r=parseRecord({id:'record',sequence:'1',time:new Date(now).toISOString(),generation:'g',mode:'host-enforcement',kind:'final',request_id:'q',application:null,principal_uid:null,flow:{direction:'outgoing',protocol:'tcp',family:'ipv4',local:'192.0.2.1:40000',remote:'192.0.2.40:8445'},attribution:{status:'not-required',reason:'Explicit network authority'},decision:{action:'allow',source:'rule',scope:null,reason:'Endpoint rule',rule:{id:'endpoint:r',version:'1',action:'allow',priority:100,expires:'',disabled:false,filter:rule().filter,target_scope:'network-endpoint'},matching_rules:['endpoint:r'],decided_by_uid:null},verdict:{state:'accept_submitted'},delivery:'not_observed'});
 assert.equal(r.decision.rule.target_scope,'network-endpoint');assert.equal(r.application,null);assert.equal(r.principal_uid,null);
});
