import { showAccountIn } from './accounts';
import { popupPosition } from './popup-position';
import {DEFAULT_SHAPING, shapingUnavailableReason, ZONE_CAPABILITY, scopeOf, scopeLabel, sameTarget, type LimitScope, uploadTarget, uploadSummary, limitCoverage, capRate, capPriority, prioritySummary, priorityCoverage, validateBudget, DOWNLOAD_CAPABILITY, PRIORITY_CAPABILITY, TRAFFIC_PRIORITIES, type TrafficPriority, type LimitDirection, UPLOAD_CAPABILITY, UPLOAD_RATE_UNITS, uploadRateBits, uploadRateValue, type UploadRateUnit, type UploadView, type UploadTarget} from './upload-shaping';
import type {Row} from './model';
import type {ClientState} from './protocol';
let view:UploadView={supported:false,writable:false,message:'Unsupported: experimental upload controller is not enabled.'};
let flight=false, last=0, context='', leaseDeadline=0;
// The shared limiter popup edits one kind: an upload/download rate or the
// application's single traffic priority (both directions).
type LimitKind = LimitDirection | 'priority';
let dialogDirection:LimitKind='upload';
let dialogTarget:UploadTarget|undefined, latestState:ClientState|undefined;
let updateActions:(()=>void)|undefined;
let dismissPopup: (()=>void)|undefined;
function adopt(v:UploadView,start:number) { if(v.generation===view.generation && v.snapshot && view.snapshot && v.snapshot.version<view.snapshot.version)return; view=v; leaseDeadline=start+Math.max(0, v.snapshot?.coverage_valid_for_ms||0); }
function coverageExpired() { return view.snapshot?.coverage_snapshot_expired || performance.now()>=leaseDeadline; }
const targets=new WeakMap<HTMLElement,UploadTarget>();
const buttonRows=new WeakMap<HTMLElement,{row:Row,state:ClientState,kind:LimitKind}>();
function paintAvailability(b:HTMLButtonElement) {
  const item=buttonRows.get(b);if(!item)return;
  const reason=shapingUnavailableReason(item.row,latestState||item.state,view,item.kind);
  b.disabled=!!reason;
  b.setAttribute('aria-label',`${item.kind} for ${item.row.label}`);
  if(reason){b.title=reason;b.setAttribute('aria-label',`${item.kind} unavailable for ${item.row.label}: ${reason}`);}
}

const text=<K extends keyof HTMLElementTagNameMap>(tag:K,value:string)=>{const e=document.createElement(tag);e.textContent=value;return e;};
function coverage(t:UploadTarget, direction:LimitDirection='upload') {
  const c=limitCoverage(view.snapshot,t,direction,coverageExpired());
  return `${c.confirmed} confirmed / ${c.requested} requested socket bindings. Coverage is partial; not an application-wide guarantee.${direction==='download'?' Established TCP only; UDP, listeners, fragments and IPv6 extension headers are uncovered.':''}`;
}
function budgetText() {
  const s=view.snapshot, f=(n?:number)=>n?`${n/1000000} Mbit/s`:'none (priority inactive)';
  return `All-traffic budgets: upload ${f(s?.upload_budget_bits_per_second)}, download ${f(s?.download_budget_bits_per_second)}.`;
}
function priorityCoverageText(t:UploadTarget) {
  const c=priorityCoverage(view.snapshot,t,coverageExpired());
  return `${c.confirmed} confirmed / ${c.requested} requested socket bindings in budgeted directions. Coverage is partial; not an application-wide guarantee.`;
}
function paintButton(b:HTMLButtonElement,t:UploadTarget) {
  const zoneSettings=(view.snapshot?.configured_caps||[]).filter(c=>c.uid===t.uid&&c.application===t.application&&scopeOf(c)!=='all').map(c=>`${scopeLabel(scopeOf(c))}: UL ${capRate(c)/1000000} / DL ${capRate(c,'download')/1000000} Mbit/s, priority ${c.traffic_priority||'inherited'}`).join('\n');
  if(b.dataset.limitDirection==='priority'){
    const configured=view.snapshot?.configured_caps.some(c=>c.uid===t.uid&&c.application===t.application&&(scopeOf(t)==='all'||scopeOf(c)===scopeOf(t))&&c.traffic_priority!==undefined)===true;
    b.classList.toggle('upload-configured',configured);b.dataset.uploadState=prioritySummary(view,t);
    b.title=`Traffic priority · ${prioritySummary(view,t)}\n${budgetText()}\n${priorityCoverageText(t)}\nShaping only; separate from firewall rule priority.\n${zoneSettings}\n${view.message}`;
    return;
  }
  const direction=(b.dataset.limitDirection || 'upload') as LimitDirection, label=direction==='download'?'Download':'Upload';
  const configured=view.snapshot?.configured_caps.some(c=>c.uid===t.uid&&c.application===t.application && (scopeOf(t)==='all'||scopeOf(c)===scopeOf(t)) && capRate(c,direction)>0)===true;
  b.classList.toggle('upload-configured',configured);
  b.dataset.uploadState=uploadSummary(view,t,direction);
  b.title=`${label} limit · ${uploadSummary(view,t,direction)}\n${coverage(t,direction)}\n${zoneSettings}\n${view.message}`;
}
function paint() {
  updateActions?.();
  const live=document.getElementById('uploadCoverageLive');
  if(live && dialogTarget) live.textContent=dialogDirection==='priority'?`${prioritySummary(view,dialogTarget)} · ${budgetText()} ${priorityCoverageText(dialogTarget)} ${view.message} ${view.snapshot?.last_error||''}`:`${uploadSummary(view,dialogTarget,dialogDirection)} · ${coverage(dialogTarget,dialogDirection)} ${view.message} ${view.snapshot?.last_error||''}`;
  for(const b of document.querySelectorAll<HTMLButtonElement>('[data-upload-limit]')) {
    const t=targets.get(b); if(t)paintButton(b,t);paintAvailability(b);
  }
}
function limitGlyph(direction:LimitKind) {
  const span=text('span','');span.className='slot-icon '+(direction==='priority'?'family-priority':direction==='upload'?'family-ul-limit':'family-dl-limit');
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 16 16');svg.setAttribute('aria-hidden','true');
  const path=document.createElementNS(svg.namespaceURI,'path');
  path.setAttribute('d',direction==='priority'?'M3 13V10M8 13V6M13 13V3':direction==='upload'?'M8 13V3M4 7l4-4 4 4':'M8 3v10M4 9l4 4 4-4');path.setAttribute('fill','none');
  path.setAttribute('stroke','currentColor');path.setAttribute('stroke-width','1.3');
  path.setAttribute('stroke-linecap','round');path.setAttribute('stroke-linejoin','round');
  svg.append(path);span.append(svg);return span;
}
export function refreshUpload(state:ClientState) {
  latestState=state;
  paint();
  const key=JSON.stringify([state.control.generation,state.control.connected,state.control.permissions?.role,state.control.capabilities?.includes(UPLOAD_CAPABILITY),state.control.capabilities?.includes(DOWNLOAD_CAPABILITY),state.control.capabilities?.includes(PRIORITY_CAPABILITY),state.control.capabilities?.includes(ZONE_CAPABILITY)]);
  if(key!==context){context=key;view={supported:false,writable:false,message:'Unsupported or awaiting current daemon status.'};paint();last=0;}
  if(!state.control.connected || !state.control.capabilities?.includes(UPLOAD_CAPABILITY) || state.control.permissions?.role!=='administrator' || flight || Date.now()-last<1500)return;
  flight=true;last=Date.now();const start=context, sent=performance.now();
  void window.flowgate.uploadStatus().then(v=>{if(start===context){adopt(v,sent);paint();}}).catch(()=>{if(start===context){view={supported:true,writable:false,message:"Upload status unavailable"};paint();}}).finally(()=>{flight=false;});
}
export function uploadButton(row:Row,state:ClientState,direction:LimitDirection='upload') {
  const t=uploadTarget(row,state);
  if(!['application','process'].includes(row.kind)) return emptySlot();
  const b=document.createElement('button');
  b.className='status-slot upload-limit'; b.dataset.uploadLimit='';b.dataset.limitDirection=direction;
  const label=direction==='download'?'Download':'Upload';
  b.setAttribute('aria-label',`${label} limit for ${row.label}`);b.setAttribute('aria-haspopup','dialog');b.setAttribute('aria-expanded','false');
  const dot=text('span','·');dot.className='slot-dot';b.append(dot,limitGlyph(direction));
  buttonRows.set(b,{row,state,kind:direction});if(t){targets.set(b,t);paintButton(b,t);b.onclick=e=>{e.stopPropagation();void open(t,b,direction);};}paintAvailability(b);
  return b;
}
export function priorityButton(row:Row,state:ClientState) {
  const t=uploadTarget(row,state);
  if(!['application','process'].includes(row.kind)) return emptySlot();
  const b=document.createElement('button');
  b.className='status-slot upload-limit priority-control'; b.dataset.uploadLimit='';b.dataset.limitDirection='priority';
  b.setAttribute('aria-label',`Traffic priority for ${row.label}`);b.setAttribute('aria-haspopup','dialog');b.setAttribute('aria-expanded','false');
  const dot=text('span','·');dot.className='slot-dot';b.append(dot,limitGlyph('priority'));
  buttonRows.set(b,{row,state,kind:'priority'});if(t){targets.set(b,t);paintButton(b,t);b.onclick=e=>{e.stopPropagation();void open(t,b,'priority');};}paintAvailability(b);
  return b;
}
function emptySlot() {
  const slot=document.createElement('span');slot.className='status-slot';slot.setAttribute('aria-hidden','true');return slot;
}
export async function openUploadLimits() {
  const sent=performance.now(), start=context; const v=await window.flowgate.uploadStatus(); if(start!==context) throw Error("Connection changed; reopen limits"); adopt(v,sent);
  const d=document.createElement("dialog");d.id="uploadLimitList";d.className="upload-limit-dialog";
  d.append(text("h3","Experimental bandwidth limits"),text("p",view.message||"Configured limits survive closing the GUI, but not a daemon restart. Coverage remains partial."));
  for(const c of view.snapshot?.configured_caps||[])for(const direction of ['upload','download'] as const){
    if(!capRate(c,direction))continue;
    const b=text('button','');showAccountIn(b,c.uid,user=>`${c.application} · ${user} · ${scopeLabel(scopeOf(c))} · ${direction} ${capRate(c,direction)/1000000} Mbit/s`);
    b.onclick=()=>{d.remove();const p=latestState?.observation.connected?Object.values(latestState.observation.activity?.processes||{}).find(p=>p.uid===c.uid&&p.application.key===c.application&&p.application.kind==='native'):undefined;void open({...c,revision:p?.application.revision},document.getElementById('uploadLimits')||undefined,direction);};d.append(b);
  }
  for(const c of view.snapshot?.configured_caps||[])if(c.traffic_priority){
    const b=text('button','');showAccountIn(b,c.uid,user=>`${c.application} · ${user} · ${scopeLabel(scopeOf(c))} · traffic priority ${c.traffic_priority}`);
    b.onclick=()=>{d.remove();const p=latestState?.observation.connected?Object.values(latestState.observation.activity?.processes||{}).find(p=>p.uid===c.uid&&p.application.key===c.application&&p.application.kind==='native'):undefined;void open({...c,revision:p?.application.revision},document.getElementById('uploadLimits')||undefined,'priority');};d.append(b);
  }
  if(view.prioritySupported && view.snapshot){
    // Manual per-direction budgets (interface-wide, host-local connected sockets
    // only). Without a direction's budget, traffic priority is inactive there.
    const box=text('fieldset','');box.id='priorityBudgets';box.append(text('legend','Traffic priority budgets (Mbit/s, empty = none)'));
    const field=(id:string,label:string,bits?:number)=>{const l=text('label',label+' ');const i=document.createElement('input');i.id=id;i.type='text';i.inputMode='decimal';i.value=bits?String(bits/1000000):'';l.append(i);box.append(l);return i;};
    const ub=field('budgetUpload','Upload',view.snapshot.upload_budget_bits_per_second),db=field('budgetDownload','Download',view.snapshot.download_budget_bits_per_second);
    const saveBudgets=text('button','Save budgets');saveBudgets.id='budgetSave';saveBudgets.disabled=!view.writable;const msg=text('p','');msg.setAttribute('role','status');
    const bits=(v:string)=>{if(!v.trim())return 0;if(!/^\d{1,5}(?:\.\d{1,6})?$/.test(v.trim()))throw Error('Enter Mbit/s');return validateBudget(Math.round(Number(v)*1000000));};
    // Coverage lifetime is anchored at request START (like every other write).
    const saved=view;saveBudgets.onclick=async()=>{saveBudgets.disabled=true;try{const budgets={upload:bits(ub.value),download:bits(db.value)};const sent=performance.now(),start=context;const result=await window.flowgate.uploadConfigure({generation:saved.generation!,expected_version:saved.snapshot!.version,budgets});if(start!==context)throw Error('Connection changed; refresh again');adopt(result,sent);paint();d.remove();}catch(e){msg.textContent=String(e instanceof Error?e.message:e);saveBudgets.disabled=false;}};
    box.append(saveBudgets,msg,text('p','Priority is best effort. Scheduler allocations do not guarantee delivery, progress or latency. Low traffic may be very slow or stall under contention. Priority acts only while the local budget is the busy shaping point; it cannot reclaim upstream bandwidth.'));d.append(box);
  }
  if(!view.snapshot?.configured_caps.length)d.append(text("p","No configured limits. Select a verified native application’s ↑ UL Limit or ↓ DL Limit slot in Activity to add one."));
  if(view.writable && view.generation && view.snapshot && !view.snapshot.enabled && !view.snapshot.configured_caps.length && view.snapshot.status==='Unsupported') {
    const saved=view, retry=text('button','Retry owned cleanup'); retry.id='uploadCleanup';
    retry.onclick=async()=>{retry.disabled=true;try{const result=await window.flowgate.uploadConfigure({generation:saved.generation!,expected_version:saved.snapshot!.version,cleanup_only:true});d.append(text('p',result.message+' Close and refresh to verify cleanup.'));}catch(e){d.append(text('p',String(e)));}};d.append(retry);
  }
  const close=text("button","Close");close.onclick=()=>d.remove();d.append(close);document.body.append(d);d.showModal();
}
async function open(t:UploadTarget, anchor?:HTMLElement, direction:LimitKind='upload') {
  dismissPopup?.();
  t={...t};dialogTarget=t;dialogDirection=direction;
  const isPriority=direction==='priority';
  const label=isPriority?'Traffic priority':direction==='download'?'Download':'Upload';
  const d=document.createElement('section');d.id='uploadLimitDialog';d.className='quick-popup upload-limit-popup';
  d.setAttribute('role','dialog');d.setAttribute('aria-labelledby','uploadLimitTitle');d.dataset.direction=direction;d.tabIndex=-1;
  const heading=text('h3',`${isPriority?label:label+' limit'} · ${t.label||t.application}`);heading.id='uploadLimitTitle';heading.className='visually-hidden';
  const row=text('div','');row.className='upload-setter-row';
  const enabled=document.createElement('input');enabled.type='checkbox';enabled.id='uploadEnabled';enabled.setAttribute('aria-label',`Enable ${direction} limit`);enabled.title='Uncheck and press OK to remove this limit; disabled limits are not stored.';
  const input=document.createElement('input');input.id='uploadRate';input.type='text';input.inputMode='decimal';input.value='8';input.setAttribute('aria-label',`${label} rate`);input.autocomplete='off';input.spellcheck=false;
  const units=document.createElement('select');units.id='uploadUnits';units.setAttribute('aria-label',`${label} rate units`);
  for(const unit of UPLOAD_RATE_UNITS)units.add(new Option(unit,unit));units.value='Mbit/s';
  let unit:UploadRateUnit='Mbit/s';
  const save=text('button','OK');save.id='uploadSave';
  const level=document.createElement('select');level.id='priorityLevel';level.setAttribute('aria-label','Traffic priority');
  for(const p of TRAFFIC_PRIORITIES)level.add(new Option(p[0].toUpperCase()+p.slice(1),p));level.value='normal';
  if(isPriority){row.classList.add('priority-setter-row');row.append(level,save);}else row.append(enabled,input,units,save);
  const actions=text('div','');actions.className='upload-setter-actions';
  const zone=document.createElement('select');zone.id='uploadZone';zone.setAttribute('aria-label','Network zone');
  for(const scope of ['all','internet','local'] as const)zone.add(new Option(scopeLabel(scope),scope));zone.value=scopeOf(t);
  const zoneHint=text('span','');zoneHint.id='uploadZoneHint';zoneHint.className='hint';
  const zoneRow=text('div','');zoneRow.className='upload-zone-row';zoneRow.append(zone,zoneHint);
  const detailsButton=text('button','Advanced');detailsButton.id='uploadDetails';detailsButton.setAttribute('aria-expanded','false');detailsButton.setAttribute('aria-controls','uploadDetailsBody');detailsButton.title='Advanced limit status, coverage and refresh';
  const remove=text('button','Delete');remove.id='uploadRemove';actions.append(detailsButton,remove);
  const details=text('div','');details.id='uploadDetailsBody';details.hidden=true;
  const summary=text('p','Reading current configuration…');summary.id='uploadCoverage';summary.setAttribute('role','status');
  const live=text('p','');live.id='uploadCoverageLive';
  const detail=text('p',isPriority?'Experimental traffic priority for this application in both directions: under a saturated local budget, higher priority is favored. This is best effort: Low traffic may be very slow or stall, with no minimum delivery rate or bounded progress. Only connected host-local sockets of verified native applications on the selected interface; unbudgeted directions are inactive. Per-app download priority covers established TCP only; eligible connected UDP uses the shared default class. Shaping only; firewall Allow/Deny and rule priority are separate. No latency guarantee. Ends at daemon restart.':(direction==='download'?'Download: established TCP only; UDP, listeners, fragments and IPv6 extension headers are uncovered. Limits schedule local delivery, not upstream link capacity. ':'')+'Experimental: verified native sockets on the selected interface only; first traffic and unsupported sockets may escape. UDP GSO unsupported; TCP caps receiver-tested. Firewall Allow/Deny is separate. Socket assignment survives exec/transfer until close or fresh rebinding. Limits end at daemon restart. Byte prefixes use 1024; bit prefixes use 1000.');detail.className='hint';
  const refresh=text('button','Refresh / review'),close=text('button','Close');refresh.id='uploadRefresh';close.id='uploadClose';
  details.append(live,summary,detail,text('p','Zone limits also respect the combined All networks cap. Explicit zone priorities override All networks; Delete restores inheritance. The All networks priority determines the application’s parent allocation; zone priority controls leaf borrowing, including competition with other applications for shared-budget capacity, without strict global ordering. Shared directional budgets cover all traffic. Unknown classifications use All networks only. The unknown queue retains its scheduler allocation while idle; active queues may borrow unused capacity up to their ceilings. Zone settings never grant firewall permission.'),refresh,close);
  d.append(heading,row,zoneRow,actions,details);document.body.append(d);anchor?.setAttribute('aria-expanded','true');
  const bounds=anchor?.getBoundingClientRect() || {left:8,top:8,bottom:8};
  const place=()=>{const current=anchor?.isConnected?anchor.getBoundingClientRect():bounds;const pos=popupPosition(current,d.offsetWidth,d.offsetHeight,{width:innerWidth,height:innerHeight});d.style.left=pos.left+'px';d.style.top=pos.top+'px';};
  const reveal=()=>{details.hidden=false;detailsButton.setAttribute('aria-expanded','true');place();};
  const dismiss=()=>{d.remove();anchor?.setAttribute('aria-expanded','false');document.removeEventListener('pointerdown',outside,true);document.removeEventListener('keydown',escape,true);window.removeEventListener('resize',place);if(dismissPopup===dismiss)dismissPopup=undefined;if(anchor?.isConnected)anchor.focus({preventScroll:true});};
  const outside=(e:PointerEvent)=>{if(!d.contains(e.target as Node)&&!anchor?.contains(e.target as Node))dismiss();};
  const escape=(e:KeyboardEvent)=>{if(e.key==='Escape'){if([units,zone,level].some(s=>s.matches(':open')))return;e.preventDefault();e.stopPropagation();dismiss();}};
  dismissPopup=dismiss;document.addEventListener('pointerdown',outside,true);document.addEventListener('keydown',escape,true);window.addEventListener('resize',place);close.onclick=dismiss;
  detailsButton.onclick=()=>{details.hidden=!details.hidden;detailsButton.setAttribute('aria-expanded',String(!details.hidden));place();};
  let defaults={...DEFAULT_SHAPING};
  let draft:UploadView|undefined, blocked=true, edited=false;
  const hasCap=()=>draft?.snapshot?.configured_caps.some(c=>sameTarget(c,t) && (direction==='priority'?c.traffic_priority!==undefined:capRate(c,direction)>0));
  const buttons=()=>{zone.disabled=blocked||!view.zoneSupported;const stale=!view.writable||(scopeOf(t)!=='all'&&!view.zoneSupported)||(direction==='download'&&!view.downloadSupported)||(isPriority&&!view.prioritySupported)||view.generation!==draft?.generation||view.snapshot?.version!==draft?.snapshot?.version;save.disabled=blocked||stale||!draft?.writable||(isPriority?((level.value!=='normal'||scopeOf(t)!=='all')&&!t.revision)||(level.value==='normal'&&scopeOf(t)==='all'&&!hasCap()):(enabled.checked&&!t.revision)||(!enabled.checked&&!hasCap()));remove.disabled=blocked||stale||!draft?.writable||!hasCap();};
  updateActions=()=>{if(d.isConnected)buttons();};buttons();place();d.focus({preventScroll:true});
  input.oninput=()=>{edited=true;};enabled.onchange=()=>{edited=true;buttons();};level.onchange=()=>{edited=true;buttons();};
  units.onchange=()=>{if(!input.value.trim()){unit=units.value as UploadRateUnit;edited=true;return;}try{const bits=uploadRateBits(input.value,unit);unit=units.value as UploadRateUnit;input.value=uploadRateValue(bits,unit);edited=true;}catch(e){units.value=unit;summary.textContent=String(e instanceof Error?e.message:e);reveal();}};
  const drafts=new Map<LimitScope,{value:string;unit:UploadRateUnit;enabled:boolean;level:string;edited:boolean}>();
  const loadZone=()=>{
    const c=draft?.snapshot?.configured_caps.find(c=>sameTarget(c,t));
    const saved=drafts.get(scopeOf(t));
    if(saved){input.value=saved.value;unit=saved.unit;units.value=unit;enabled.checked=saved.enabled;level.value=saved.level;edited=saved.edited;}
    else {edited=false;level.value=c?.traffic_priority ?? defaults.priority;enabled.checked=true;unit=direction==='download'?defaults.downloadUnit:defaults.uploadUnit;units.value=unit;input.value=uploadRateValue(capRate(c,direction==='priority'?'upload':direction)||(direction==='download'?defaults.downloadBits:defaults.uploadBits),unit);}
    const all=draft?.snapshot?.configured_caps.find(c=>sameTarget(c,{...t,scope:'all'}));
    const inherited=scopeOf(t)!=='all' && (isPriority?!!all?.traffic_priority:!!capRate(all,direction as LimitDirection));
    zoneHint.textContent=inherited?'All applies':'';
    zoneHint.title=isPriority?'The selected zone’s explicit priority overrides All networks. Delete restores the inherited priority. Shared UL/DL budgets still cover all traffic.':'All networks remains one combined ceiling across zones; this zone’s limit also applies. Delete removes only this zone’s setting.';
    zone.title=view.zoneSupported?'Edit this zone’s own setting. Unknown classifications match All networks only.':'Zone shaping is unsupported by this daemon; All networks remains available.';
    buttons();
  };
  zone.onchange=()=>{drafts.set(scopeOf(t),{value:input.value,unit,enabled:enabled.checked,level:level.value,edited});t.scope=zone.value as LimitScope;loadZone();paint();};
  const read=async()=>{blocked=true;buttons();try{const sent=performance.now(),start=context;const [v,prefs]=await Promise.all([window.flowgate.uploadStatus(),window.flowgate.preferences().catch(()=>undefined)]);defaults={...(prefs?.shapingDefaults || DEFAULT_SHAPING)};if(start!==context)throw Error('Connection changed; refresh again');adopt(v,sent);paint();if(!d.isConnected)return;draft=view;if(!edited)loadZone();summary.textContent=`${view.snapshot?.interface?'Interface '+view.snapshot.interface+'. ':''}${view.message} ${view.snapshot?.last_error||''}`;blocked=false;paint();if(!view.writable||view.snapshot?.last_error)reveal();}catch(e){summary.textContent=String(e);reveal();}buttons();};
  const apply=async(rate:number|null,prio?:TrafficPriority|null)=>{if(!draft?.generation||!draft.snapshot)return;blocked=true;buttons();try{const sent=performance.now(),start=context;const result=await window.flowgate.uploadConfigure(isPriority?{generation:draft.generation,expected_version:draft.snapshot.version,target:t,bits_per_second:null,priority:prio===undefined?null:prio}:{generation:draft.generation,expected_version:draft.snapshot.version,target:t,direction:direction as LimitDirection,bits_per_second:rate});if(start!==context)throw Error('Connection changed; refresh again');adopt(result,sent);paint();if(d.isConnected)dismiss();}catch(e){if(!d.isConnected)return;summary.textContent=String(e);reveal();}};
  save.onclick=()=>{try{if(isPriority){void apply(null,level.value as TrafficPriority);return;}void apply(enabled.checked?uploadRateBits(input.value,unit):null);}catch(e){summary.textContent=String(e instanceof Error?e.message:e);reveal();}};
  input.onkeydown=e=>{if(e.key==='Enter'&&!e.isComposing){e.preventDefault();if(!save.disabled)save.click();}};
  remove.onclick=()=>void apply(null,null);refresh.onclick=()=>{drafts.clear();edited=false;void read();};await read();
  // A slow status reply must not steal focus or select a draft the user already edited.
  if(d.isConnected && !blocked && !edited && document.activeElement===d){if(isPriority)level.focus({preventScroll:true});else if(!save.disabled){input.focus({preventScroll:true});input.select();}}
}
