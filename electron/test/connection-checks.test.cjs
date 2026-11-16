const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),net=require('node:net');
const {ConnectionChecksClient,parseChecks}=require('../dist/test/connection-checks.cjs');
async function fixture(t){
 const dir=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/checks-')),socket=dir+'/s',calls=[];let reply=()=>({connection_checks:{enabled:true,revision:'1'}});
 const server=net.createServer(s=>s.once('data',b=>{const q=JSON.parse(b);calls.push(q);const r=reply(q);if(r.drop){s.destroy();return}s.end(JSON.stringify({version:1,generation:'g',mode:'daemon-monitor',read_only:false,server_time:'2026-11-16T00:00:00Z',...r})+'\n')}));
 await new Promise(r=>server.listen(socket,r));t.after(async()=>{await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true})});
 const state={control:{connected:true,generation:'g',readOnly:false,capabilities:['connection-check-settings-v1'],permissions:{role:'administrator',can_manage_machine_rules:true}},observation:{connected:false}};
 return {client:new ConnectionChecksClient({controller:socket,observer:socket,view:()=>state}),state,calls,reply:f=>reply=f};
}
test('strict setting and CAS save, readonly refuses',async t=>{const h=await fixture(t);assert.equal((await h.client.request()).settings.enabled,true);h.reply(()=>({connection_checks:{enabled:false,revision:'2'}}));const v=await h.client.request({enabled:false,expected_revision:'1'});assert.equal(v.settings.enabled,false);assert.equal(h.calls[1].connection_checks.expected_revision,'1');h.state.control.readOnly=true;const n=h.calls.length;assert.equal((await h.client.request({enabled:true,expected_revision:'2'})).writable,false);assert.equal(h.calls.length,n);assert.throws(()=>parseChecks({enabled:'yes',revision:'1'}));});
test('lost acknowledgement never replays; fresh state unlocks',async t=>{const h=await fixture(t);h.reply(()=>({drop:true}));assert.equal((await h.client.request({enabled:false,expected_revision:'1'})).writable,false);await h.client.request({enabled:false,expected_revision:'1'});assert.equal(h.calls.length,1);h.reply(()=>({connection_checks:{enabled:false,revision:'2'}}));const v=await h.client.request();assert.equal(v.writable,true);assert.equal(v.settings.enabled,false);});
test('explicit rejection allows refresh without waiting for a nonexistent write',async t=>{const h=await fixture(t);h.reply(()=>({error:'stale',error_code:'revision_conflict'}));await h.client.request({enabled:false,expected_revision:'1'});h.reply(()=>({connection_checks:{enabled:true,revision:'1'}}));assert.equal((await h.client.request()).writable,true);});
test('failed before sending does not lock same-context refresh or deliberate save',async t=>{
 const dir=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/checks-')),socket=dir+'/s';
 const state={control:{connected:true,generation:'g',readOnly:false,capabilities:['connection-check-settings-v1'],permissions:{role:'administrator',can_manage_machine_rules:true}},observation:{connected:false}};
 const client=new ConnectionChecksClient({controller:socket,observer:socket,view:()=>state});
 await client.request({enabled:false,expected_revision:'1'});assert.equal(client.unknown,undefined);
 const server=net.createServer(s=>s.once('data',b=>{const q=JSON.parse(b);s.end(JSON.stringify({version:1,generation:'g',mode:'daemon-monitor',read_only:false,server_time:'2026-11-16T00:00:00Z',connection_checks:q.operation==='connection-check-configure'?{enabled:false,revision:'2'}:{enabled:true,revision:'1'}})+'\n')}));
 await new Promise(r=>server.listen(socket,r));t.after(async()=>{await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true})});
 assert.equal((await client.request()).writable,true);assert.equal((await client.request({enabled:false,expected_revision:'1'})).settings.enabled,false);
});
test('context switch discards old-context mutation authority',async t=>{
 const h=await fixture(t);h.reply(()=>{h.state.control.generation='new';return {connection_checks:{enabled:false,revision:'2'}}});
 assert.equal((await h.client.request({enabled:false,expected_revision:'1'})).writable,false);
 h.state.control.generation='g';h.reply(()=>({connection_checks:{enabled:false,revision:'2'}}));assert.equal((await h.client.request()).writable,true);
});
