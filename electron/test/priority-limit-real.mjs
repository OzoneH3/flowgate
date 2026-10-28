// Real Electron UI -> private guest API bridge -> receivers. Never the host API.
// Drives the Priority slot of the shared limiter popup and the budget fields.
import {_electron} from 'playwright-core';
import net from 'node:net';import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
const root=process.cwd(), dir=path.join(root,'.workspace/shaping-prio/journey'), captures=path.join(dir,'ui-captures');
fs.mkdirSync(captures,{recursive:true});
const call=q=>new Promise((resolve,reject)=>{const s=net.createConnection(dir+'/fixture.sock');let b='';s.setTimeout(15000,()=>s.destroy(Error('timeout')));s.on('error',reject);s.on('connect',()=>s.write(JSON.stringify(q)+'\n'));s.on('data',x=>{b+=x;if(b.includes('\n')){s.destroy();const r=JSON.parse(b);r.fixture_error?reject(Error(r.fixture_error)):resolve(r)}})});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(fn,n=120){for(let i=0;i<n;i++){const r=await fn();if(r)return r;await sleep(500)}throw Error('wait expired')}
let app,page;const evidence={steps:[],errors:[]};
try{
 const ready=await wait(async()=>{try{return await call({operation:'ready'})}catch{return null}},600);evidence.ready={apps:ready.apps,pids:ready.pids};
 app=await _electron.launch({executablePath:root+'/electron/node_modules/electron/dist/electron',chromiumSandbox:true,args:['--ozone-platform=wayland',dir+'/ui/electron','--observer',dir+'/monitor.sock','--control',dir+'/api.sock'],env:{...process.env,TMPDIR:root+'/.workspace/tmp',XDG_CACHE_HOME:dir+'/cache'}});
 const p=await wait(()=>app.windows().find(w=>w.url()==='flowgate://app/index.html'));page=p;
 await app.evaluate(({BrowserWindow})=>{const w=BrowserWindow.getAllWindows().find(w=>w.webContents.getURL()==='flowgate://app/index.html');if(!w)throw Error('main window missing');w.show();w.restore();w.focus();});
 p.on('pageerror',e=>evidence.errors.push(String(e)));await p.setViewportSize({width:1280,height:800});
 const status=async()=>(await call({operation:'ready'})).status;
 // 1. Budgets through the limits dialog.
 await wait(async()=>(await p.evaluate(()=>window.flowgate.snapshot())).control?.capabilities?.includes('experimental-traffic-priority-v1'));
 await p.locator('#uploadLimits').click();await p.locator('#priorityBudgets').waitFor({state:'visible'});
 await p.locator('#budgetUpload').fill('40');await p.locator('#budgetDownload').fill('40');await p.screenshot({path:captures+'/budgets.png'});
 await p.locator('#budgetSave').click();await p.locator('#uploadLimitList').waitFor({state:'detached'});
 await wait(async()=>{const s=await status();return s.upload_budget_bits_per_second===40e6&&s.download_budget_bits_per_second===40e6&&s.applied_version===s.version});
 const button=async n=>{const a=ready.apps[n];await p.locator('#search').fill(a.name);const b=p.getByRole('button',{name:'Traffic priority for '+(a.display_name||a.name),exact:true});await wait(async()=>{await p.locator('#expand').click();return await b.count()>=1});return b.first();};
 const setPriority=async(n,level,{escapeFirst=false,del=false}={})=>{
  const b=await button(n);
  if(escapeFirst){const v=(await status()).version;await b.click();await p.locator('#priorityLevel').waitFor({state:'visible'});await p.locator('#priorityLevel').selectOption(level);await p.keyboard.press('Escape');assert.equal(await p.locator('#uploadLimitDialog').count(),0);assert.equal((await status()).version,v,'dismiss must not write');}
  await b.click();await p.locator('#priorityLevel').waitFor({state:'visible'});
  assert.match(await p.locator('#uploadLimitTitle').textContent(),/^Traffic priority · /);
  await wait(()=>del?p.locator('#uploadRemove').isEnabled():p.locator('#uploadSave').isEnabled());
  if(!del){await p.locator('#priorityLevel').selectOption(level);
   // A delivered status refresh must keep the draft selection.
   await p.evaluate(()=>{window.pubs=[];window.flowgate.subscribe(s=>window.pubs.push(s.publication))});
   await wait(async()=>new Set(await p.evaluate(()=>window.pubs)).size>=2);assert.equal(await p.locator('#priorityLevel').inputValue(),level);
   await p.screenshot({path:captures+`/popup-${n}-${level}.png`});await p.locator('#uploadSave').click();}
  else await p.locator('#uploadRemove').click();
  await p.locator('#uploadLimitDialog').waitFor({state:'detached'});
  const key=ready.apps[n].key;
  await wait(async()=>{const s=await status();const c=s.configured_caps.find(c=>c.application===key);return s.applied_version===s.version&&(level==='normal'?!c:c?.traffic_priority===level)});
  await wait(async()=>(await b.getAttribute('data-upload-state')||'').toLowerCase().startsWith(level));
  return await b.getAttribute('data-upload-state');
 };
 const measure=async label=>{await call({operation:'measure',label});const r=await wait(async()=>(await call({operation:'result',label})).result,240);assert(!r.error,r.error);evidence.steps.push({label,first:r.first,checks:r.checks,rules_unchanged:r.rules_unchanged});return r;};
 evidence.ui={A_low:await setPriority('A','low',{escapeFirst:true}),C_high:await setPriority('C','high')};
 await measure('set');
 evidence.ui.A_high=await setPriority('A','high');evidence.ui.C_deleted=await setPriority('C','normal',{del:true});
 await measure('edit');
 evidence.ui.A_deleted=await setPriority('A','normal',{del:true});
 await p.locator('#uploadLimits').click();await p.locator('#priorityBudgets').waitFor({state:'visible'});
 await p.locator('#budgetUpload').fill('');await p.locator('#budgetDownload').fill('');await p.locator('#budgetSave').click();await p.locator('#uploadLimitList').waitFor({state:'detached'});
 await wait(async()=>(await status()).status==='Disabled');
 await measure('off');
 evidence.finish=await call({operation:'finish'});assert.equal(evidence.finish.finished,true);assert.equal(evidence.errors.length,0);
 console.log(JSON.stringify({ui:evidence.ui,results:evidence.finish.results}));
}catch(e){evidence.error=String(e);if(page){evidence.body=(await page.locator('body').innerText()).slice(0,4000);await page.screenshot({path:captures+'/failure.png'});}throw e}finally{fs.writeFileSync(dir+'/priority-ui-journey.json',JSON.stringify(evidence,null,2));if(app)await app.close()}
