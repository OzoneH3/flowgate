// Real isolated API/native TCP journey; requires an owned disposable held fixture.
// No host endpoint, daemon lifecycle, or user's rules. Receiver proof is in the
// paired scripts/acceptance/remember_ended_acceptance.py; this file checks the actual GUI.
import {_electron} from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const project=path.resolve(import.meta.dirname,'../..'), readyPath=process.env.FLOWGATE_TEST_READY;
assert(readyPath?.startsWith(project+'/.workspace/'));
const ready=JSON.parse(fs.readFileSync(readyPath)),dir=path.dirname(readyPath);
assert(ready.socket.startsWith(dir+'/')&&!ready.socket.startsWith('/run/'));
const run=fs.mkdtempSync(project+'/.workspace/remember-ui-'),root=run+'/client';
fs.mkdirSync(root+'/electron',{recursive:true});fs.cpSync(project+'/electron/dist',root+'/electron/dist',{recursive:true});fs.copyFileSync(project+'/electron/package.json',root+'/electron/package.json');fs.mkdirSync(root+'/.workspace/tmp',{recursive:true});
const result={fixture:readyPath,generation:ready.generation,run,steps:[],host:false};
const step=s=>{result.steps.push(s);console.log('PASS',s)};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(fn,label){for(let until=Date.now()+20000;Date.now()<until;await pause(60)){const v=await fn();if(v)return v}throw Error('timeout '+label)}
const api=q=>new Promise((resolve,reject)=>{const s=net.createConnection(ready.socket);let text='';s.on('error',reject);s.setTimeout(8000,()=>s.destroy(Error('timeout')));s.on('connect',()=>s.write(JSON.stringify({version:1,...q})+'\n'));s.on('data',b=>{text+=b;if(text.includes('\n')){s.destroy();resolve(JSON.parse(text))}})});
async function command(q){const f=dir+'/command-result.json';fs.rmSync(f,{force:true});fs.writeFileSync(ready.command,JSON.stringify(q));await wait(async()=>fs.existsSync(f),'command '+q.op);return JSON.parse(fs.readFileSync(f))}
const list=()=>api({operation:'list'});
const pending=async()=>((await list()).events||[]).find(e=>e.state==='awaiting-decision'&&e.attribution.owners.some(o=>o.pid===ready.alpha.pid));
let app,main;
try{
 const initial=await list();assert.equal(initial.generation,ready.generation);assert(!(initial.rules||[]).length);
 app=await _electron.launch({chromiumSandbox:true,args:['--ozone-platform=wayland',root+'/electron','--observer',ready.monitor_socket,'--control',ready.socket],env:{...process.env,TMPDIR:root+'/.workspace/tmp',WAYLAND_DISPLAY:process.env.WAYLAND_DISPLAY||'wayland-1'}});
 main=await app.firstWindow();await main.locator('#requestsTab').waitFor();
 await wait(async()=>{const c=(await main.evaluate(()=>window.flowgate.snapshot())).control;return c.connected&&c.policy},'policy');
 await command({op:'outgoing',name:'alpha',protocol:'tcp',timeout_ms:2500});
 const original=await wait(pending,'original pending');
 const prompt=await wait(async()=>app.windows().find(w=>new URL(w.url()).searchParams.get('request')===original.id),'automatic prompt');
 await prompt.locator('#rememberDuration').waitFor();
 await wait(async()=>!(await prompt.locator('#allow').isDisabled()),'card ready');
 // Joining the native connect job proves closure; no guessed Activity absence.
 await prompt.locator('#rememberDuration').selectOption('0');
 await command({op:'settle',name:'alpha'});
 await wait(async()=>/connection has ended/i.test(await prompt.locator('#requestResult').textContent()),'ended reason');
 assert(await prompt.locator('#allow').isDisabled());assert(await prompt.locator('#block').isDisabled());assert(await prompt.locator('#refreshDecision').isHidden());
 assert.equal(await prompt.locator('#rememberDuration').inputValue(), '0');
 assert.match(await prompt.locator('.expiry').textContent(),/ended/i);
 assert.match(await prompt.locator('#requestDetails').textContent(),new RegExp(original.flow.remote.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 await prompt.screenshot({path:run+'/ended-prompt.png'});
 step('Ended socket: recorded app/endpoints and Remember choice retained; Allow/Deny/Refresh disabled; old countdown removed');
 // Repeated Enter on the non-action container never commits anything.
 await prompt.locator('#requestDetails').focus();await prompt.keyboard.press('Enter');await prompt.keyboard.press('Enter');
 assert(!(await list()).rules?.length);
 await prompt.locator('#futureApplicationRule').click();
 await main.locator('#ruleEditor:not([hidden])').waitFor();
 assert.match(await main.locator('#editorMode').textContent(),/Future application rule/);
 assert.equal(await main.locator('#editProtocol').inputValue(),'*');
 assert.equal(await main.locator('#createScope').inputValue(),'application');
 assert.match(await main.locator('#scopeSummary').textContent(),/ended connection is not approved/);
 await main.selectOption('#editExpiry','permanent');
 await main.locator('#previewRule').click();await wait(async()=>!(await main.locator('#saveRule').isDisabled()),'fresh observed preview');
 await main.screenshot({path:run+'/future-application-review.png'});
 await main.locator('#saveRule').click();
 const saved=await wait(async()=>(await list()).rules?.[0],'future rule');
 assert.equal(saved.action,'allow');assert(!saved.filter.process);assert(!saved.filter.network_zone);assert.equal(saved.filter.protocol,'*');
 await wait(async()=>/original connection was not allowed/.test(await main.locator('#feedback').textContent()),'future-only success');
 const state=await list(),old=(state.events||[]).find(e=>e.id===original.id);assert(!old||old.state!=='allowed');
 step('Explicit application workflow opened in main; fresh authoritative Preview/Save created application-only Any-zone rule; no Decide for old request');
 const before=(await command({op:'peer-counts'})).lines.length;
 await command({op:'outgoing',name:'alpha',protocol:'tcp',timeout_ms:10000});
 await wait(async()=>(await command({op:'peer-counts'})).lines.length===before+1,'future TCP delivery');
 const removed=await api({operation:'rule-delete',generation:ready.generation,id:saved.id,expected_version:saved.version});assert(!removed.error,JSON.stringify(removed));
 assert(!(await list()).rules?.length);step('Later retry delivered, exact conditional rule cleanup restored rules0');
 result.passed=true;
}catch(e){result.error=String(e);if(main)await main.screenshot({path:run+'/failure-main.png'}).catch(()=>{});if(app)for(const w of app.windows())if(w!==main)await w.screenshot({path:run+'/failure-prompt.png'}).catch(()=>{});throw e}
finally{if(app)await app.close().catch(()=>{});fs.writeFileSync(run+'/result.json',JSON.stringify(result,null,2)+'\n');console.log('EVIDENCE',run)}
