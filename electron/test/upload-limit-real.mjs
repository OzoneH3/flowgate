// Real Electron UI -> private guest API bridge -> receiver. Never host API.
import {_electron} from 'playwright-core';
import net from 'node:net';import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
const root=process.cwd(), dir=path.join(root,'.workspace/shaping-ui');
const call=q=>new Promise((resolve,reject)=>{const s=net.createConnection(dir+'/fixture.sock');let b='';s.setTimeout(15000,()=>s.destroy(Error('timeout')));s.on('error',reject);s.on('connect',()=>s.write(JSON.stringify(q)+'\n'));s.on('data',x=>{b+=x;if(b.includes('\n')){s.destroy();const r=JSON.parse(b);r.fixture_error?reject(Error(r.fixture_error)):resolve(r)}})});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(fn){for(let i=0;i<100;i++){const r=await fn();if(r)return r;await sleep(500)}throw Error('wait expired')}
let app,page;const evidence={steps:[],errors:[]};
try{
 const ready=await call({operation:'ready'});evidence.ready=ready;
 app=await _electron.launch({executablePath:root+'/electron/node_modules/electron/dist/electron',chromiumSandbox:true,args:['--ozone-platform=wayland',dir+'/ui/electron','--observer',dir+'/monitor.sock','--control',dir+'/api.sock'],env:{...process.env,TMPDIR:root+'/.workspace/tmp',XDG_CACHE_HOME:dir+'/cache'}});
 const p=await app.firstWindow();page=p;p.on('pageerror',e=>evidence.errors.push(String(e)));await p.setViewportSize({width:1280,height:800});
 await p.locator('#expand').click(); await wait(async()=>{await p.locator('#expand').click();return await p.locator('[data-upload-limit]:not([disabled])').count()});
 await p.locator('#expand').click();
 const buttons=p.getByRole('button',{name:/Upload limit for .*alpha/});
 await buttons.first().click();await p.locator('#uploadSave').waitFor({state:'visible'});
 for(const [label,rate] of [['set8',8],['edit16',16],['disabled',null]]){
  const prior=(await call({operation:'result',label})).result;if(prior){evidence.steps.push({label,...prior,reused_after_fixture_input_race:true});continue;}
  await p.locator('#uploadRefresh').click();await wait(()=>p.locator('#uploadSave').isEnabled());
  if(rate!==null){await p.locator('#uploadRate').fill(String(rate));await wait(()=>p.locator('#uploadSave').isEnabled());await p.locator('#uploadSave').click()}
  else {await wait(()=>p.locator('#uploadRemove').isEnabled());await p.locator('#uploadRemove').click()}
  await wait(async()=>{const s=(await call({operation:'ready'})).status;return rate===null?s.status==='Disabled':s.configured_caps.some(c=>c.bits_per_second===rate*1e6)&&s.kernel?.covered_bindings>0});
  await call({operation:'measure',label});const r=await wait(async()=> (await call({operation:'result',label})).result);assert(!r.error,r.error);evidence.steps.push({label,...r,ui:await p.locator('#uploadCoverageLive').innerText()});
 }
 evidence.finish=await call({operation:'finish'});assert.equal(evidence.errors.length,0);console.log(JSON.stringify(evidence.steps.map(s=>({label:s.label,payload:s.receiver_payload_mbit,deny:s.deny_receiver}))));
}catch(e){evidence.error=String(e);if(page)evidence.body=await page.locator('body').innerText();throw e}finally{fs.writeFileSync(dir+'/ui-journey.json',JSON.stringify(evidence,null,2));if(app)await app.close()}
