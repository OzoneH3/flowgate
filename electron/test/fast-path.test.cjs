const {test}=require('node:test');
const assert=require('node:assert/strict');
const {fastPathIndicator}=require('../dist/test/fast-path.cjs');
const {rowStructure}=require('../dist/test/row-structure.cjs');
test('fast path is not inferred from connected state, Allow, or app identity',()=>{
 assert.equal(fastPathIndicator({state:'Connected UDP socket',ownership:'verified',traffic:{uploaded:100}}).label,'Fast path ?');
 for(const [state,label] of [['inactive','Fast path off'],['authorized','Fast grant'],['unknown','Fast path ?'],['unsupported','Fast path unsupported']]) {
  const p=fastPathIndicator({fast_path:{state,reason:'Reported reason, not delivery.',sampled_at:new Date().toISOString()}});
  assert.equal(p.label,label);assert.match(p.title,/Reported reason/);assert.match(p.title,/Snapshot:/);
 }
});
test('old/undated evidence never keeps a grant indicator',()=>{
 for(const sampled_at of ['',new Date(Date.now()-4000).toISOString()])
  assert.equal(fastPathIndicator({fast_path:{state:'authorized',reason:'installed',sampled_at}}).label,'Fast path ?');
});
test('status samples update in place without replacing a keyed socket row',()=>{
 const socket={id:'s',socket:{cookie:'cookie'},traffic:{},fast_path:{state:'inactive',reason:'no grant'}};
 const r={kind:'socket',rows:[socket],socket,children:[]};
 const before=rowStructure(r,1,false,false);socket.fast_path={state:'authorized',reason:'installed'};
 assert.equal(rowStructure(r,1,false,false),before);
});
test('API parsing preserves a reported reason and legacy absence, rejecting invented states',()=>{
 const {parseReply}=require('../dist/test/protocol.cjs');
 const raw={version:1,generation:'g',read_only:true,server_time:new Date().toISOString(),activity:{rows:[{id:'s',socket:{},traffic:{}}],processes:{}}};
 assert.equal(parseReply(raw).activity.rows[0].fast_path,undefined);
 raw.activity.rows[0].fast_path={state:'inactive',code:'no_grant_observed',reason:'The original cause was not recorded.',sampled_at:new Date().toISOString()};
 assert.equal(parseReply(raw).activity.rows[0].fast_path.reason,'The original cause was not recorded.');
 raw.activity.rows[0].fast_path.state='all_traffic_delivered';
 assert.throws(()=>parseReply(raw),/Invalid fast-path/);
});

test('app UDP icon uses exact reported socket hits including unconnected UDP, never TCP totals',()=>{
 const {appFastPathIndicator,appFastPathDetails,statusIconMarkup}=require('../dist/test/fast-path.cjs');
 const udp=(state,reason='socket evidence')=>({socket:{protocol:'udp',remote:'0.0.0.0:0'},fast_path:{state,reason,sampled_at:new Date().toISOString()}});
 assert.equal(appFastPathIndicator([{socket:{protocol:'tcp'},fast_path:{state:'in_use'}}]),undefined);
 assert.equal(appFastPathIndicator([udp('in_use')]).state,'in-use');
 assert.match(appFastPathIndicator([udp('in_use'),udp('inactive')]).title,/Other destinations/);
 assert.equal(appFastPathIndicator([udp('authorized')]).state,'idle');
 assert.equal(appFastPathIndicator([udp('inactive')]),undefined);assert.equal(appFastPathDetails([udp('inactive')]).state,'normal');
 assert.doesNotMatch(appFastPathDetails([udp('unknown')]).title,/Snapshot:/);
 assert.equal(appFastPathIndicator([udp('unsupported')]),undefined);
 assert.equal(appFastPathIndicator([{socket:{protocol:'udp'},traffic:{uploaded:99999}}]),undefined);
 const stale=udp('in_use');stale.fast_path.sampled_at=new Date(Date.now()-4000).toISOString();
 assert.equal(appFastPathIndicator([stale]),undefined);assert.equal(appFastPathDetails([stale]).state,'unknown');
 for(const state of ['in-use','idle','on','off']) {assert.match(statusIconMarkup(state),/^<svg viewBox="0 0 16 16"/);assert.doesNotMatch(statusIconMarkup(state),/[↯◇•?]/);}
});

test('retained exact-socket identity keeps the executable group and labels its provenance',()=>{
 const {hierarchy}=require('../dist/test/model.cjs');
 const row={id:'socket-A',owners:[],socket:{protocol:'udp',local:'0.0.0.0:1234',remote:'0.0.0.0:0',state:7},state:'unconnected',traffic:{available:false},runtime_application:{application:{key:'A',revision:'rev',name:'SyntheticAlpha.exe',kind:'wine',executable:'/prefix-A/alpha.exe'},uid:1000,evidence:{},display_source:'established-grant'}};
 const activity={rows:[row],processes:{}};
 const a=hierarchy(activity),b=hierarchy(JSON.parse(JSON.stringify(activity)));
 assert.equal(a[0].id,b[0].id);assert.equal(a[0].label,'SyntheticAlpha.exe');assert.equal(a[0].identityNote,undefined);assert.equal(a[0].runtimeApplication.display_source,'established-grant');assert.equal(a[0].rows.length,1);
});

test('sample timestamps and retained provenance do not churn DOM, but actual socket identity still does',()=>{
 const socket={id:'s',socket:{cookie:'cookie-A'},traffic:{},runtime_application:{application:{key:'A',revision:'r'},uid:1000,evidence:{},display_source:'established-grant'},fast_path:{state:'in_use',sampled_at:new Date().toISOString()}};
 const row={kind:'application',rows:[socket],children:[]};const key=rowStructure(row,1,false,false);
 socket.fast_path={state:'authorized',sampled_at:new Date(Date.now()+250).toISOString()};delete socket.runtime_application.display_source;
 assert.equal(rowStructure(row,1,false,false),key);
 socket.socket.cookie='cookie-B';assert.notEqual(rowStructure(row,1,false,false),key);
});

test('last verified TCP and UDP annotations keep each executable and prefix grouped without DOM churn',()=>{
 const {hierarchy}=require('../dist/test/model.cjs');
 const rows=[];
 for(const prefix of ['A','B'])for(const app of ['Alpha','Beta'])for(const protocol of ['tcp','udp']) rows.push({id:`${app}-${prefix}-${protocol}`,owners:[],socket:{protocol,local:'[::]:1234',remote:'[::]:0',cookie:`${app}-${prefix}-${protocol}`},traffic:{},runtime_application:{application:{key:`${app}-${prefix}`,revision:'rev',kind:'wine',name:`Synthetic${app}.exe`,executable:`/prefix-${prefix}/${app}.exe`,prefix:`/prefix-${prefix}`},uid:1000,evidence:{}}});
 const fresh=hierarchy({rows,processes:{}});
 const retained=JSON.parse(JSON.stringify(rows));
 for(const r of retained){r.runtime_application.display_source='last-verified-snapshot';r.runtime_application.display_verified_at=new Date().toISOString();}
 const busy=hierarchy({rows:retained,processes:{}});
 assert.equal(fresh.length,4);assert.equal(busy.length,4);
 for(let i=0;i<fresh.length;i++){
  assert.equal(busy[i].id,fresh[i].id);assert.equal(busy[i].rows.length,2);assert.equal(busy[i].label,fresh[i].label);
  assert.equal(rowStructure(busy[i],1,false,false),rowStructure(fresh[i],1,false,false));
  assert.equal(busy[i].runtimeApplication.display_source,'last-verified-snapshot');
 }
});

test('partial last-verified provenance is not a new app identity or a fast-path claim',()=>{
 const {hierarchy}=require('../dist/test/model.cjs');
 const socket={id:'partial-tcp',owners:[],socket:{protocol:'tcp',cookie:'same-cookie'},traffic:{},runtime_application:{application:{key:'synthetic-A-prefix-A',revision:'r',kind:'wine',name:'SyntheticAlpha.exe'},uid:1000,evidence:{}}};
 const fresh=hierarchy({rows:[socket],processes:{}})[0];const key=rowStructure(fresh,1,false,false);
 socket.runtime_application.display_source='last-verified-partial-snapshot';socket.runtime_application.display_verified_at=new Date().toISOString();
 const partial=hierarchy({complete:false,rows:[socket],processes:{}})[0];
 assert.equal(partial.id,fresh.id);assert.equal(rowStructure(partial,1,false,false),key);
 assert.equal(partial.runtimeApplication.display_source,'last-verified-partial-snapshot');
 const {appFastPathIndicator}=require('../dist/test/fast-path.cjs');assert.equal(appFastPathIndicator(partial.rows),undefined);
});
