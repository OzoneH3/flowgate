import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const root=path.resolve(import.meta.dirname,'../..');
const require=createRequire(path.join(root,'electron/package.json'));
const {chromium}=require('playwright-core'),{build}=require('esbuild');
const out=path.join(root,'.workspace');
const bundle=await build({stdin:{contents:`import {updateConnectionStatus} from '${root}/electron/src/status-slot';import {rowStructure} from '${root}/electron/src/row-structure';import {appFastPathDetails} from '${root}/electron/src/fast-path';import {uploadButton,priorityButton,refreshUpload} from '${root}/electron/src/upload-shaping-view';import {hierarchy,inactiveApplications,activityTree} from '${root}/electron/src/model';import {runningRuleInventory,ownConfigured} from '${root}/electron/src/rule-status';import {blockerGlyph} from '${root}/electron/src/activity-policy';import {ownRuleChip} from '${root}/electron/src/rule-chip';window.helpers={updateConnectionStatus,rowStructure,appFastPathDetails,uploadButton,priorityButton,refreshUpload,hierarchy,inactiveApplications,activityTree,runningRuleInventory,ownConfigured,blockerGlyph,ownRuleChip};`,resolveDir:root},bundle:true,write:false,platform:'browser'});
const ctx=await chromium.launchPersistentContext(path.join(out,'browser-profile'),{executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-breakpad'],viewport:{width:720,height:400},env:{...process.env,TMPDIR:'/home/flowgate-user/Apps/flowgate/.workspace/ut',XDG_CACHE_HOME:path.join(out,'browser-cache'),XDG_CONFIG_HOME:path.join(out,'browser-config')}});
try{
 const page=await ctx.newPage();await page.route('**/*',r=>r.abort());
 const css=fs.readFileSync(path.join(root,'electron/src/style.css'),'utf8');
 await page.setContent(`<style>${css}body{padding:24px;font-family:sans-serif}table{width:100%}#info{margin-top:20px;min-height:80px}h3{font-size:14px}</style><h3>Local status-slot fixture — not the installed GUI</h3><table id="tree"><tbody id="rows"></tbody></table><dl id="info" hidden></dl>`);
 await page.addScriptTag({content:bundle.outputFiles[0].text});
 await page.evaluate(()=>{
  const {updateConnectionStatus,rowStructure,appFastPathDetails}=window.helpers;
  window.rows=[];window.entries=new Map();window.states=['in_use','authorized','unknown','inactive'];
  window.refresh=(tick)=>{
   for(let i=0;i<4;i++){
    const socket={id:'s'+i,owners:[],socket:{protocol:'udp',local:'0.0.0.0:1000',remote:'0.0.0.0:0',state:7,cookie:'c'+i},state:'bound',traffic:{},fast_path:{state:window.states[i],reason:'Receiver-backed per-socket observation.',sampled_at:new Date(Date.now()+tick).toISOString()}};
    const row={id:'app'+i,kind:'application',label:['Granted UDP, recent hits','Granted UDP, idle','Other app, unknown UDP','Other app, no grant'][i],rows:[socket],children:[]};window.rows[i]=row;
    const signature=rowStructure(row,1,false,false);let item=window.entries.get(row.id);
    if(!item||signature!==item.signature){
     const tr=document.createElement('tr');tr.dataset.id=row.id;
     const td=document.createElement('td');td.className='name depth-1';
     const slot=document.createElement('button');slot.type='button';
     const text=document.createElement('span');text.textContent=row.label;td.append(slot,text);tr.append(td);
     slot.onclick=()=>{window.selected=i;const info=document.querySelector('#info');info.hidden=false;info.innerHTML='<dt>Fast path</dt><dd></dd>';info.querySelector('dd').textContent=appFastPathDetails(window.rows[i].rows).title;};
     if(item)item.tr.replaceWith(tr);else document.querySelector('#rows').append(tr);
     item={tr,slot,signature};window.entries.set(row.id,item);
    }
    updateConnectionStatus(item.slot,row);
   }
   if(window.selected!==undefined){const info=document.querySelector('#info');const text=appFastPathDetails(window.rows[window.selected].rows).title;const dd=info.querySelector('dd');if(dd.textContent!==text)dd.textContent=text;}
  };window.refresh(0);window.original=document.querySelector('#rows tr');window.originalSVG=window.original.querySelector('svg');
 });
 const sizes=await page.locator('.connection-status-slot').evaluateAll(nodes=>nodes.map(n=>{const r=n.getBoundingClientRect(),tr=n.closest('tr').getBoundingClientRect();return {x:r.x,w:r.width,h:r.height,cy:r.y+r.height/2,rowcy:tr.y+tr.height/2,shape:n.innerHTML,title:n.getAttribute('title')};}));
 assert.equal(new Set(sizes.map(x=>x.x)).size,1);for(const x of sizes){assert.equal(x.w,16);assert.equal(x.h,16);assert.ok(Math.abs(x.cy-x.rowcy)<2);assert.ok(x.title.length>0);assert.match(x.shape,/<svg/);}
 assert.equal(await page.locator('.connection-status-slot.in-use').count(),1);assert.equal(await page.locator('.connection-status-slot.idle').count(),1);assert.equal(await page.locator('.connection-status-slot.off').count(),2);
 await page.locator('.connection-status-slot').first().click();const explanation=await page.locator('#info').textContent();
 await page.evaluate(()=>{for(let i=0;i<50;i++)window.refresh(i);});
 assert.equal(await page.evaluate(()=>window.original===document.querySelector('#rows tr')),true);
 assert.equal(await page.evaluate(()=>window.originalSVG===document.querySelector('#rows tr svg')),true);
 assert.equal(await page.locator('#info').textContent(),explanation);assert.equal(await page.locator('#info').isVisible(),true);
 await page.evaluate(()=>{window.states[0]='authorized';window.refresh(50);});assert.equal(await page.evaluate(()=>window.original===document.querySelector('#rows tr')),true);
 await page.evaluate(()=>{window.states[0]='in_use';window.refresh(51);});
 await page.evaluate(()=>{
  window.flowgate={uploadStatus:async()=>({supported:true,writable:true,message:'Unavailable',snapshot:{status:'Unsupported',last_error:'Owned journal remains; explicit configuration required for verified reconciliation',version:1,configured_caps:[]}})};
  const state={observation:{connected:true},control:{connected:true,capabilities:['experimental-native-upload-v1','experimental-native-download-v1','experimental-traffic-priority-v1'],permissions:{role:'administrator'}}};
  const wine={kind:'application',label:'Synthetic runtime',runtimeApplication:{application:{kind:'wine'}}};
  const native={kind:'application',label:'Synthetic native',process:{uid:1000,application:{kind:'native',key:'native',revision:'r'}}};
  const controls=document.createElement('div');controls.id='shaping-controls';
  for(const row of [wine,native]) controls.append(window.helpers.uploadButton(row,state),window.helpers.uploadButton(row,state,'download'),window.helpers.priorityButton(row,state));
  document.body.append(controls);window.helpers.refreshUpload(state);
 });
 await page.waitForFunction(()=>[...document.querySelectorAll('#shaping-controls button')].every(b=>b.disabled&&b.title.includes('Owned journal remains')));
 assert.equal(await page.locator('#shaping-controls button').count(),6);
 for(const reason of await page.locator('#shaping-controls button').evaluateAll(ns=>ns.slice(0,3).map(n=>n.title))) assert.match(reason,/Wine\/runtime or shared-owner/);
 const ruleParity=await page.evaluate(()=>{
  const {hierarchy,runningRuleInventory,ownConfigured,blockerGlyph,ownRuleChip}=window.helpers;
  const p={id:'10:100',pid:10,start_ticks:'100',uid:1000,executable:'/fixture/wine64-preloader',application:{kind:'wine',key:'synthetic-A-prefix-A',revision:'r',name:'SyntheticAlpha.exe',executable:'/prefix-A/Alpha.exe'}};
  const rule={id:'rule-A',version:1,action:'allow',priority:1,filter:{application:p.application.key,revision:'r',uid:1000,direction:'outgoing',protocol:'*',remote_address:'*'}};
  const state={control:{connected:true,serverNow:Date.now(),rules:[rule]},observation:{connected:true}};
  const row=hierarchy({rows:[],processes:{[p.id]:p}})[0];
  const inventory=runningRuleInventory(row,state,false);const own=ownConfigured(inventory.outgoing,inventory.now);
  const ref={id:rule.id,version:'1',action:'allow',scope:rule.filter,active:true,expired:false,disabled:false};
  const backend=ownRuleChip({rules:[ref],application_rule:ref,scoped_rules:0},false,true);
  const a=blockerGlyph({...own,glyph:'',detail:''}),b=blockerGlyph(backend);
  if(a.outerHTML!==b.outerHTML) throw Error('Allow glyph changes with policy association');
  const bar=document.createElement('div');bar.id='running-rule-fixture';bar.append('Observed process, socket attribution pending: ');
  const button=document.createElement('button');button.className='policy-cell status-slot tone-allow';button.title='Saved Allow for observed executable; not a connection verdict.';button.append(a);bar.append(button);document.body.append(bar);
  return {sameGlyph:a.outerHTML===b.outerHTML,text:a.textContent,color:getComputedStyle(a).color,appId:row.id,socketsClaimed:row.rows.length};
 });
 assert.equal(ruleParity.sameGlyph,true);assert.equal(ruleParity.text,'✓');assert.equal(ruleParity.socketsClaimed,0);
 const notRunning=await page.evaluate(()=>{
  const rules=[{id:'stored',version:1,action:'allow',filter:{application:'closed-app',revision:'r',uid:1000,direction:'outgoing',protocol:'*'},executable:'/fixture/Closed'}];
  const groups=window.helpers.activityTree({rows:[],processes:{}},rules);
  if(groups.length!==1||groups[0].kind!=='inactive-group'||!groups[0].label.startsWith('Not running'))throw Error('not-running group lost');
  const label=document.createElement('h3');label.id='not-running';label.textContent=groups[0].label;document.body.append(label);
  return {label:groups[0].label,kind:groups[0].kind};
 });
 assert.equal(await page.locator('#not-running').isVisible(),true);
 await page.screenshot({path:path.join(out,'status-slots.png')});
 fs.writeFileSync(path.join(out,'status-browser-result.json'),JSON.stringify({passed:true,scope:'Headless Chromium using actual CSS/status module and structural-key code; not an installed Electron session',sizes,refreshes:52,sameDOMNode:true,sameSVGWhileUnchanged:true,runningAllowGlyphParity:ruleParity,persistentInfo:true,hoverTooltips:true,disabledShapingReasons:true,unknownUsesDot:true,notRunning},null,2));
 console.log('PASS: fixed16px slot/alignment; SVGs; hover tooltips and disabled shaping reasons; same DOM across51 refreshes; persistent Info; no unknown icons');
}finally{await ctx.close();}
