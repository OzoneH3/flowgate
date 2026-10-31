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
test('changing status invalidates the keyed socket row even with unchanged traffic',()=>{
 const socket={id:'s',socket:{cookie:'cookie'},traffic:{},fast_path:{state:'inactive',reason:'no grant'}};
 const r={kind:'socket',rows:[socket],socket,children:[]};
 const before=rowStructure(r,1,false,false);socket.fast_path={state:'authorized',reason:'installed'};
 assert.notEqual(rowStructure(r,1,false,false),before);
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
