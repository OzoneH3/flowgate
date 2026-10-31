const {test}=require('node:test');
const assert=require('node:assert/strict');
const {hierarchy,sum}=require('../dist/test/model.cjs');
const {runningRuleInventory,ownConfigured}=require('../dist/test/rule-status.cjs');
const process=(pid,app,prefix,uid=1000)=>({id:`${pid}:100`,pid,start_ticks:'100',uid,executable:'/fixture/wine64-preloader',application:{kind:'wine',key:`${app}-${prefix}`,revision:'rev',name:`Synthetic${app}.exe`,executable:`/prefix-${prefix}/${app}.exe`,prefix:`/prefix-${prefix}`}});
const rule=(p,action='allow')=>({id:`rule-${p.id}`,version:1,schema:2,action,priority:1,filter:{application:p.application.key,revision:p.application.revision,uid:p.uid,direction:'outgoing',protocol:'*',remote_address:'*'}});
const state=(rules)=>({control:{connected:true,rules,serverNow:Date.now()},observation:{connected:true}});
const appId=p=>`app:${p.application.key}|rev|uid:${p.uid}`;
const socket=(owners,runtime)=>({id:'shared',owners,socket:{protocol:'tcp',state:1,local:'127.0.0.1:1234',remote:'127.0.0.1:4321',cookie:'cookie'},state:'Established',traffic:{available:false},runtime_application:runtime});

test('running keyed apps have independent saved-rule rows before socket attribution, two apps x prefixes x UIDs',()=>{
 const processes={};const rules=[];
 for(const uid of [1000,1001])for(const prefix of ['A','B'])for(const app of ['Alpha','Beta']){const p=process(Object.keys(processes).length+1,app,prefix,uid);processes[p.id]=p;rules.push(rule(p,uid===1000?'allow':'block'));}
 const shared=socket(Object.keys(processes).slice(0,2));
 const roots=hierarchy({rows:[shared],processes});
 for(const p of Object.values(processes)){
  const r=roots.find(r=>r.id===appId(p));assert.ok(r);assert.equal(r.rows.length,0);assert.equal(r.process.id,p.id);assert.equal(sum(r.rows,'uploaded').value,undefined);
  const inventory=runningRuleInventory(r,state(rules),false);assert.equal(inventory.outgoing.length,1);assert.equal(inventory.incoming.length,0);assert.equal(ownConfigured(inventory.outgoing,inventory.now).tone,p.uid===1000?'allow':'block');
 }
 assert.equal(roots.find(r=>r.id==='unidentified').rows[0].id,shared.id);
 assert.equal(roots.filter(r=>r.kind==='application').length,8);
});

test('app id and stored Allow survive missing/fresh/partial socket association without borrowing sockets',()=>{
 const p=process(10,'Alpha','A');const q=process(11,'Beta','B');const processes={[p.id]:p,[q.id]:q};
 const runtime={application:p.application,uid:p.uid,evidence:{},display_source:'last-verified-partial-snapshot'};
 for(const annotation of [undefined,runtime,undefined]){
  const roots=hierarchy({rows:[socket([p.id,q.id],annotation)],processes});const r=roots.find(r=>r.id===appId(p));assert.ok(r);
  assert.equal(r.rows.length,annotation?1:0);assert.equal(r.process.id,p.id);
  const inventory=runningRuleInventory(r,state([rule(p)]),false);assert.equal(ownConfigured(inventory.outgoing,inventory.now).tone,'allow');
  assert.equal(runningRuleInventory(r,state([rule(p)]),true),undefined); // normal backend summary wins when available
  assert.equal(roots.find(r=>r.id===appId(q)).rows.length,0);
 }
 const ended=hierarchy({rows:[],processes:{}});assert.equal(ended.some(r=>r.id===appId(p)),false);
});

test('process anchors honor search and explicit Active/Listening socket filters and reject unknown identities',()=>{
 const p=process(10,'Alpha','A');const activity={rows:[],processes:{[p.id]:p,unknown:{...p,id:'unknown',pid:11,application:{kind:'wine-unresolved',key:'',revision:''}}}};
 assert.equal(hierarchy(activity).length,1);assert.equal(hierarchy(activity,'SyntheticAlpha').length,1);assert.equal(hierarchy(activity,'Beta').length,0);
 assert.equal(hierarchy(activity,'','active').length,0);assert.equal(hierarchy(activity,'','listening').length,0);
 const r=hierarchy(activity)[0];assert.equal(runningRuleInventory({...r,displayApplication:process(12,'Beta','B').application},state([rule(p)]),false),undefined);
 assert.equal(runningRuleInventory(r,{control:{connected:false,rules:[]}},false),undefined);
});
