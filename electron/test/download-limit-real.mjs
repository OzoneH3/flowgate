// Real Electron UI -> private guest API bridge -> receiver. Never host API.
import {_electron} from 'playwright-core';
import net from 'node:net';import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
const root=process.cwd(), dir=path.join(root,'.workspace/shaping-dl'), captures=path.join(dir,'ui-captures');
fs.mkdirSync(captures,{recursive:true});
const call=q=>new Promise((resolve,reject)=>{const s=net.createConnection(dir+'/fixture.sock');let b='';s.setTimeout(15000,()=>s.destroy(Error('timeout')));s.on('error',reject);s.on('connect',()=>s.write(JSON.stringify(q)+'\n'));s.on('data',x=>{b+=x;if(b.includes('\n')){s.destroy();const r=JSON.parse(b);r.fixture_error?reject(Error(r.fixture_error)):resolve(r)}})});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(fn){for(let i=0;i<100;i++){const r=await fn();if(r)return r;await sleep(500)}throw Error('wait expired')}
let app,page;const evidence={steps:[],errors:[]};
try{
 const ready=await call({operation:'ready'});evidence.ready=ready;
 app=await _electron.launch({executablePath:root+'/electron/node_modules/electron/dist/electron',chromiumSandbox:true,args:['--ozone-platform=wayland',dir+'/ui/electron','--observer',dir+'/monitor.sock','--control',dir+'/api.sock'],env:{...process.env,TMPDIR:root+'/.workspace/tmp',XDG_CACHE_HOME:dir+'/cache'}});
 const p=await wait(()=>app.windows().find(w=>w.url()==='flowgate://app/index.html'));page=p;
 await app.evaluate(({BrowserWindow})=>{const w=BrowserWindow.getAllWindows().find(w=>w.webContents.getURL()==='flowgate://app/index.html');assertWindow(w);function assertWindow(w){if(!w)throw Error('main window missing');w.show();w.restore();w.focus();if(!w.isVisible()||w.isMinimized())throw Error('main window not visible')}});
 evidence.window=await app.evaluate(({BrowserWindow})=>BrowserWindow.getAllWindows().map(w=>({url:w.webContents.getURL(),visible:w.isVisible()}))); p.on('pageerror',e=>evidence.errors.push(String(e)));await p.setViewportSize({width:1280,height:800});
 assert.equal(evidence.window.filter(w=>w.url==='flowgate://app/index.html').length,1);
 assert(evidence.window.some(w=>w.url==='flowgate://app/index.html'&&w.visible));
 const identity=ready.application;
 await wait(async()=>{const state=await p.evaluate(()=>window.flowgate.snapshot());return Object.values(state.observation.activity?.processes||{}).some(proc=>proc.pid===ready.pid&&proc.application?.key===identity.key&&proc.application?.executable===identity.executable)});
 await p.locator('#search').fill(identity.name);await p.locator('#expand').click();
 const buttons=p.getByRole('button',{name:'Download limit for '+(identity.display_name||identity.name),exact:true});
 await wait(async()=>{await p.locator('#expand').click();return await buttons.count()===1});
 assert(await buttons.isVisible());await buttons.hover();await p.screenshot({path:captures+'/after-strip.png'});await buttons.focus();await p.keyboard.press('Enter');await p.locator('#uploadSave').waitFor({state:'visible'});
 assert.equal(await p.locator('#uploadLimitTitle').textContent(),'Download limit · '+(identity.display_name||identity.name));
 evidence.identity=identity;
 const assertIdentity=async()=>{const state=await p.evaluate(()=>window.flowgate.snapshot());assert(Object.values(state.observation.activity?.processes||{}).some(proc=>proc.pid===ready.pid&&proc.application?.key===identity.key&&proc.application?.executable===identity.executable),'selected native identity remains observed');assert.equal(await buttons.count(),1);assert.equal(await buttons.getAttribute('data-limit-direction'),'download');};
 await assertIdentity();
 const originalStatus=(await call({operation:'ready'})).status,version=originalStatus.version;
 await wait(()=>p.locator('#uploadSave').isEnabled());
 await p.screenshot({path:captures+'/after-popup.png'});
 assert.equal(await p.locator('#uploadEnabled').isChecked(),true);
 await p.locator('#uploadRate').fill('12');await p.locator('#uploadRate').focus();
 await p.evaluate(()=>{window.journeyPublications=[];window.flowgate.subscribe(s=>window.journeyPublications.push(s.publication))});
 await wait(async()=>new Set(await p.evaluate(()=>window.journeyPublications)).size>=3);
 assert.equal(await p.locator('#uploadRate').inputValue(),'12');assert(await p.locator('#uploadRate').evaluate(e=>e===document.activeElement));
 evidence.refreshPublications=await p.evaluate(()=>window.journeyPublications);
 await p.keyboard.press('Escape');assert.equal(await p.locator('#uploadLimitDialog').count(),0);
 const dismissedStatus=(await call({operation:'ready'})).status;assert.equal(dismissedStatus.version,version,'dismiss must not mutate');assert.deepEqual(dismissedStatus.configured_caps,originalStatus.configured_caps);
 evidence.dismiss={beforeVersion:version,afterVersion:dismissedStatus.version,configuredCapsUnchanged:true,popupClosed:true};
 await p.setViewportSize({width:760,height:540});await buttons.click();await wait(()=>p.locator('#uploadSave').isEnabled());
 const rect=await p.locator('#uploadLimitDialog').boundingBox();assert(rect.x>=0&&rect.y>=0&&rect.x+rect.width<=760&&rect.y+rect.height<=540);evidence.narrowPopup=rect;
 await p.screenshot({path:captures+'/after-narrow.png'});await p.keyboard.press('Escape');
 await p.setViewportSize({width:1280,height:800});await buttons.click();await wait(()=>p.locator('#uploadSave').isEnabled());
 await p.locator('#uploadUnits').focus();await p.keyboard.press('Space');await p.screenshot({path:captures+'/after-units.png'});await p.keyboard.press('Escape');
 // Native select Escape may close the whole setter; reopen if needed.
 if(!await p.locator('#uploadLimitDialog').count()){await buttons.click();await wait(()=>p.locator('#uploadSave').isEnabled())}
 await p.locator('#uploadDetails').click();

 for(const [label,rate] of [['set8',8],['edit16',16],['disabled',null]]){
  assert.equal((await call({operation:'result',label})).result,null,'fresh journey required');
  if(!await p.locator('#uploadLimitDialog').count()){await buttons.click();await wait(()=>p.locator('#uploadSave').isEnabled())}
  for(let n=0;n<2;n++){await sleep(1200);await assertIdentity();assert.equal(await buttons.count(),1);assert.equal(await p.locator('#uploadLimitTitle').textContent(),'Download limit · '+(identity.display_name||identity.name))}
  if(await p.locator('#uploadRefresh').isVisible())await p.locator('#uploadRefresh').click();await wait(()=>p.locator('#uploadSave').isEnabled());
  if(rate!==null){if(rate===16){await p.locator('#uploadUnits').selectOption('B/s');assert.equal(await p.locator('#uploadRate').inputValue(),'1000000');await p.locator('#uploadRate').fill('2000000')}else await p.locator('#uploadRate').fill(String(rate));await wait(()=>p.locator('#uploadSave').isEnabled());await p.locator('#uploadSave').click()}
  else {await wait(()=>p.locator('#uploadRemove').isEnabled());await p.locator('#uploadRemove').click()}
  await p.locator('#uploadLimitDialog').waitFor({state:'detached'});
  await wait(async()=>{const s=(await call({operation:'ready'})).status;return rate===null?s.status==='Disabled':s.configured_caps.some(c=>c.application===identity.key&&c.uid===0&&c.download_bits_per_second===rate*1e6)&&!s.coverage_snapshot_expired&&s.coverage_valid_for_ms>0&&s.kernel?.bindings?.some(b=>b.app==='0:'+identity.key&&b.covered===true&&b.download===true)});
  if(rate!==null){await wait(()=>buttons.evaluate(e=>e.classList.contains('upload-configured')));await wait(async()=>new RegExp(rate+' Mbit/s').test(await buttons.getAttribute('data-upload-state')||''));assert.match(await buttons.getAttribute('data-upload-state'),new RegExp(rate+' Mbit/s'));await p.screenshot({path:captures+'/after-'+label+'.png'})}await call({operation:'measure',label});const r=await wait(async()=> (await call({operation:'result',label})).result);assert(!r.error,r.error);const currentStatus=(await call({operation:'ready'})).status;evidence.steps.push({label,...r,status:currentStatus,ui:await buttons.getAttribute('data-upload-state'),popupClosed:await p.locator('#uploadLimitDialog').count()===0});
 }
 evidence.finish=await call({operation:'finish'});assert.equal(evidence.finish.finished,true,'guest confirms owned cleanup');assert.equal(evidence.errors.length,0);console.log(JSON.stringify(evidence.steps.map(s=>({label:s.label,payload:s.receiver_payload_mbit,deny:s.deny_receiver}))));
}catch(e){evidence.error=String(e);if(page){evidence.body=await page.locator('body').innerText();await page.screenshot({path:captures+'/failure.png'});evidence.popup=await page.locator('#uploadLimitDialog').evaluateAll(es=>es.map(e=>({rect:e.getBoundingClientRect().toJSON(),style:e.getAttribute('style')})))}throw e}finally{fs.writeFileSync(dir+'/download-ui-journey.json',JSON.stringify(evidence,null,2));if(app)await app.close()}
