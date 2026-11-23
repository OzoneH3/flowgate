import { showAccountIn } from './accounts';
import { popupPosition } from './popup-position';
import { editorChoices, networkScopeChoices } from './network-scope-choices';
import {DEFAULT_SHAPING, shapingUnavailableReason, ZONE_CAPABILITY, scopeOf, scopeLabel, sameTarget, type LimitScope, uploadTarget, uploadSummary, limitCoverage, capRate, capPriority, prioritySummary, priorityCoverage, validateBudget, DOWNLOAD_CAPABILITY, PRIORITY_CAPABILITY, type TrafficPriority, type LimitDirection, UPLOAD_CAPABILITY, UPLOAD_RATE_UNITS, uploadRateBits, uploadRateValue, type UploadRateUnit, type UploadView, type UploadTarget} from './upload-shaping';
import type {Row} from './model';
import type {ClientState} from './protocol';
let view:UploadView={supported:false,writable:false,message:'Unsupported: experimental upload controller is not enabled.'};
let flight=false, last=0, context='', leaseDeadline=0;
// The shared limiter popup edits one kind: an upload/download rate or the
// application's single traffic priority (both directions).
type LimitKind = LimitDirection | 'priority';
type PriorityChoice = TrafficPriority | 'inherit';
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
  const label=item.kind==='priority'?'Traffic priority':item.kind==='download'?'Download limit':'Upload limit';
  // Keep unavailable controls hoverable and focusable so their explanations are reachable.
  b.setAttribute('aria-disabled',String(!!reason));
  b.classList.toggle('unavailable',!!reason);
  b.setAttribute('aria-label',`${label} for ${item.row.label}`);
  if(reason){
    b.title=`${label} unavailable · ${reason}`;
    b.setAttribute('aria-label',`${label} unavailable for ${item.row.label}: ${reason}`);
  }
}

const text=<K extends keyof HTMLElementTagNameMap>(tag:K,value:string)=>{const e=document.createElement(tag);e.textContent=value;return e;};
function budgetText() {
  const s = view.snapshot, rate = (n?:number) => n ? `${n/1000000} Mbit/s` : 'off';
  return `Budgets · Upload ${rate(s?.upload_budget_bits_per_second)} · Download ${rate(s?.download_budget_bits_per_second)}`;
}
function coverageStatus(t: UploadTarget, kind: LimitKind) {
  if (t.stored_only || view.snapshot?.configured_caps.some(c => c.stored_only && sameTarget(c,t)))
    return 'Saved only · the limiter cannot bind sockets for this identity.';
  const snapshot = view.snapshot;
  const priority = kind === 'priority';
  const status = priority ? prioritySummary(view, t) : uploadSummary(view, t, kind);
  if (status === 'Pending') return 'Applying configuration…';
  if (status === 'Unsupported' || status === 'Off') return status;
  const expired = coverageExpired();
  const counts = priority ? priorityCoverage(snapshot, t, expired) : limitCoverage(snapshot, t, kind, expired);
  const configured = snapshot?.configured_caps.find((cap) => sameTarget(cap, t));
  if (priority && (!configured?.traffic_priority ||
      !(snapshot?.upload_budget_bits_per_second || snapshot?.download_budget_bits_per_second))) return status;
  const detail = expired ? 'Waiting for fresh coverage'
    : counts.requested ? `${counts.confirmed} of ${counts.requested} observed sockets confirmed`
    : 'Waiting for eligible sockets';
  return `${status.replace(/ · Partial$/, '')} · ${detail}`;
}
function paintButton(b:HTMLButtonElement,t:UploadTarget) {
  if(b.dataset.limitDirection==='priority'){
    const configured=view.snapshot?.configured_caps.some(c=>c.uid===t.uid&&c.application===t.application&&(scopeOf(t)==='all'||scopeOf(c)===scopeOf(t))&&c.traffic_priority!==undefined)===true;
    b.classList.toggle('upload-configured',configured);b.dataset.uploadState=prioritySummary(view,t);
    b.title=`Traffic priority · ${prioritySummary(view,t)}`;
    return;
  }
  const direction=(b.dataset.limitDirection || 'upload') as LimitDirection, label=direction==='download'?'Download':'Upload';
  const configured=view.snapshot?.configured_caps.some(c=>c.uid===t.uid&&c.application===t.application && (scopeOf(t)==='all'||scopeOf(c)===scopeOf(t)) && capRate(c,direction)>0)===true;
  b.classList.toggle('upload-configured',configured);
  b.dataset.uploadState=uploadSummary(view,t,direction);
  b.title=`${label} limit · ${uploadSummary(view,t,direction)}`;
}
function paint() {
  updateActions?.();
  const live=document.getElementById('uploadCoverageLive');
  if (live && dialogTarget) {
    live.textContent = coverageStatus(dialogTarget, dialogDirection);
    const meta = document.getElementById('uploadCoverageContext')!;
    const device = view.snapshot?.interface ? 'Interface ' + view.snapshot.interface : '';
    meta.textContent = [device, dialogDirection === 'priority' ? budgetText() : ''].filter(Boolean).join(' · ');
    document.getElementById('uploadControllerError')!.textContent =
      view.snapshot?.last_error || (!view.writable ? view.message : '');
  }
  for(const b of document.querySelectorAll<HTMLButtonElement>('[data-upload-limit]')) {
    const t=targets.get(b); if(t)paintButton(b,t);paintAvailability(b);
  }
}
export function limitGlyph(direction:LimitKind) {
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
  return shapingButton(row,state,direction);
}
export function priorityButton(row:Row,state:ClientState) {
  return shapingButton(row,state,'priority');
}
function shapingButton(row:Row,state:ClientState,kind:LimitKind) {
  if(!['application','process'].includes(row.kind)) return emptySlot();
  const b=document.createElement('button');
  b.type='button';
  b.className='status-slot upload-limit';b.classList.toggle('priority-control',kind==='priority');
  b.dataset.uploadLimit='';b.dataset.limitDirection=kind;
  b.setAttribute('aria-haspopup','dialog');b.setAttribute('aria-expanded','false');
  const dot=text('span','·');dot.className='slot-dot';b.append(dot,limitGlyph(kind));
  buttonRows.set(b,{row,state,kind});
  const target=uploadTarget(row,state);
  if(target){targets.set(b,target);paintButton(b,target);}
  paintAvailability(b);
  b.onclick=(event)=>{
    event.stopPropagation();
    if(target && !shapingUnavailableReason(row,latestState||state,view,kind))
      void open(target,b,kind);
  };
  return b;
}
function emptySlot() {
  const slot=document.createElement('span');slot.className='status-slot';slot.setAttribute('aria-hidden','true');return slot;
}
function configuredTarget(cap: UploadTarget): UploadTarget {
  const state = latestState;
  if (!state) return cap;
  const live = state.observation.connected && Object.values(state.observation.activity?.processes || {})
    .find(p => p.uid === cap.uid && p.application.key === cap.application && p.application.kind === 'native');
  const rule = state.control.rules?.find(r => r.filter.uid === cap.uid && r.filter.application === cap.application);
  return { ...cap, revision: live ? live.application.revision : rule?.filter.revision };
}
export async function openUploadLimits() {
  const sent=performance.now(), start=context; const v=await window.flowgate.uploadStatus(); if(start!==context) throw Error("Connection changed; reopen limits"); adopt(v,sent);
  const d=document.createElement("dialog");d.id="uploadLimitList";d.className="upload-limit-dialog";
  d.append(text("h3","Experimental bandwidth limits"),text("p",view.message||"Configured limits survive closing the GUI, but not a daemon restart. Coverage remains partial."));
  for(const c of view.snapshot?.configured_caps||[])for(const direction of ['upload','download'] as const){
    if(!capRate(c,direction))continue;
    const b=text('button','');showAccountIn(b,c.uid,user=>`${c.application} · ${user} · ${scopeLabel(scopeOf(c))} · ${direction} ${capRate(c,direction)/1000000} Mbit/s`);
    b.onclick=()=>{d.remove();void open(configuredTarget(c),document.getElementById('uploadLimits')||undefined,direction);};d.append(b);
  }
  for(const c of view.snapshot?.configured_caps||[])if(c.traffic_priority){
    const b=text('button','');showAccountIn(b,c.uid,user=>`${c.application} · ${user} · ${scopeLabel(scopeOf(c))} · traffic priority ${c.traffic_priority}`);
    b.onclick=()=>{d.remove();void open(configuredTarget(c),document.getElementById('uploadLimits')||undefined,'priority');};d.append(b);
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
  if(!view.snapshot?.configured_caps.length)d.append(text("p","No configured limits. Select an application’s ↑ UL Limit or ↓ DL Limit slot in Activity to add one."));
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
  const d=document.createElement('section');d.id='uploadLimitDialog';d.className='quick-popup quick-editor upload-limit-popup';
  d.setAttribute('role','dialog');d.setAttribute('aria-labelledby','uploadLimitKind uploadLimitTitle');d.dataset.direction=direction;d.tabIndex=-1;
  const header=text('header','');header.className='quick-editor-header';
  const title=text('div','');title.className='quick-editor-title';
  const kind=text('div',isPriority?label:label+' limit');kind.id='uploadLimitKind';kind.className='quick-editor-kind';
  const heading=text('h3',t.label||t.application);heading.id='uploadLimitTitle';heading.className='quick-editor-name';
  const close=text('button','×');close.id='uploadClose';close.className='quick-editor-close';
  close.setAttribute('aria-label',isPriority?'Close priority editor':'Close limit editor');
  title.append(kind,heading);header.append(title,close);
  const row=text('div','');row.className='upload-setter-row';
  const enabled=document.createElement('input');enabled.type='checkbox';enabled.id='uploadEnabled';enabled.setAttribute('aria-label',`Enable ${direction} limit`);enabled.title='Uncheck and press OK to remove the limit.';
  const enabledLabel=text('label','');enabledLabel.className='quick-editor-enabled';enabledLabel.append(enabled,text('span','Limit enabled'));
  const input=document.createElement('input');input.id='uploadRate';input.type='text';input.inputMode='decimal';input.value='8';input.setAttribute('aria-label',`${label} rate`);input.autocomplete='off';input.spellcheck=false;
  const units=document.createElement('select');units.id='uploadUnits';units.setAttribute('aria-label',`${label} rate units`);
  for(const unit of UPLOAD_RATE_UNITS)units.add(new Option(unit,unit));units.value='Mbit/s';
  let unit:UploadRateUnit='Mbit/s';
  const save=text('button','OK');save.id='uploadSave';
  let priority: PriorityChoice = 'normal';
  const priorityChoices = editorChoices<PriorityChoice>('priorityLevel', 'Priority', [
    ['high', 'High'], ['normal', 'Normal'], ['low', 'Low'], ['inherit', 'Inherited'],
  ], priority, (choice) => {
    priority = choice;
    edited = true;
    buttons();
  });
  const inheritedChoice = priorityChoices.querySelector<HTMLInputElement>('input[value="inherit"]')!;
  const inheritedLabel = inheritedChoice.closest('label')!;
  inheritedLabel.hidden = true;
  if (isPriority) {
    row.classList.add('priority-setter-row');
    row.append(priorityChoices);
  } else row.append(enabledLabel, input, units);
  const actions=text('div','');actions.className='upload-setter-actions';
  const zone=networkScopeChoices('uploadZone',scopeOf(t),(scope)=>{
    drafts.set(scopeOf(t),{value:input.value,unit,enabled:enabled.checked,priority,edited});
    t.scope=scope;loadZone();paint();place();
  });
  const zoneHint=text('span','');zoneHint.id='uploadZoneHint';zoneHint.className='hint';
  const zoneRow=text('div','');zoneRow.className='upload-zone-row';zoneRow.append(zone,zoneHint);
  const detailsButton=text('button','Details');detailsButton.id='uploadDetails';detailsButton.setAttribute('aria-expanded','false');detailsButton.setAttribute('aria-controls','uploadDetailsBody');
  const remove=text('button','Delete');remove.id='uploadRemove';actions.append(detailsButton,remove,save);
  const details=text('div','');details.id='uploadDetailsBody';details.hidden=true;
  const summary=text('p','Reading current configuration…');summary.id='uploadCoverage';summary.setAttribute('role','status');
  const live=text('p','');live.id='uploadCoverageLive';
  const contextNote=text('p','');contextNote.id='uploadCoverageContext';contextNote.className='shaping-detail-note';
  const controllerError=text('p','');controllerError.id='uploadControllerError';
  const detail=text('p',isPriority
    ? 'Best effort on busy, budgeted directions. Low priority can stall.'
    : direction==='download'
      ? 'Established TCP only. Limits apply to local delivery.'
      : 'Limits apply only to verified sockets on this interface.');
  detail.className='shaping-detail-note';
  const technical=text('details','');technical.append(
    text('summary','Technical notes'),
    text('p',isPriority
      ? 'Priority can favor verified native sockets under contention. Per-app download priority covers established TCP. Eligible connected UDP uses the shared class. Delete a zone override to restore inheritance.'
      : 'Initial traffic and unsupported sockets can escape shaping. UDP GSO is unsupported. Socket assignments last until close or fresh rebinding. Zone limits also respect the All networks cap. Bytes use binary prefixes and bits use decimal prefixes.'),
    text('p','Coverage is partial. Unknown classifications use All networks. Settings end at daemon restart. Firewall permissions are separate.'),
  );
  const refresh=text('button','Reload configuration');refresh.id='uploadRefresh';
  details.append(live,contextNote,summary,controllerError,detail,technical,refresh);
  d.append(header,zoneRow,row);
  if (t.stored_only) {
    const note=text('p','Saved only. This build cannot apply shaping to this identity.');
    note.className='shaping-detail-note';
    d.append(note);
  }
  d.append(actions,details);document.body.append(d);anchor?.setAttribute('aria-expanded','true');
  const bounds=anchor?.getBoundingClientRect() || {left:8,top:8,bottom:8};
  const place=()=>{const current=anchor?.isConnected?anchor.getBoundingClientRect():bounds;const pos=popupPosition(current,d.offsetWidth,d.offsetHeight,{width:innerWidth,height:innerHeight});d.style.left=pos.left+'px';d.style.top=pos.top+'px';};
  technical.ontoggle = place;
  const reveal=()=>{details.hidden=false;detailsButton.setAttribute('aria-expanded','true');place();};
  const dismiss=()=>{d.remove();anchor?.setAttribute('aria-expanded','false');document.removeEventListener('pointerdown',outside,true);document.removeEventListener('keydown',escape,true);window.removeEventListener('resize',place);if(dismissPopup===dismiss)dismissPopup=undefined;if(anchor?.isConnected)anchor.focus({preventScroll:true});};
  const outside=(e:PointerEvent)=>{if(!d.contains(e.target as Node)&&!anchor?.contains(e.target as Node))dismiss();};
  const escape=(e:KeyboardEvent)=>{if(e.key==='Escape'){if(units.matches(':open'))return;e.preventDefault();e.stopPropagation();dismiss();}};
  dismissPopup=dismiss;document.addEventListener('pointerdown',outside,true);document.addEventListener('keydown',escape,true);window.addEventListener('resize',place);close.onclick=dismiss;
  detailsButton.onclick=()=>{details.hidden=!details.hidden;detailsButton.setAttribute('aria-expanded',String(!details.hidden));place();};
  let defaults={...DEFAULT_SHAPING};
  let draft:UploadView|undefined, blocked=true, edited=false;
  const hasCap=()=>draft?.snapshot?.configured_caps.some(c=>sameTarget(c,t) && (direction==='priority'?c.traffic_priority!==undefined:capRate(c,direction)>0));
  const buttons=()=>{zone.disabled=blocked||!view.zoneSupported;const stale=!view.writable||(scopeOf(t)!=='all'&&!view.zoneSupported)||(direction==='download'&&!view.downloadSupported)||(isPriority&&!view.prioritySupported)||view.generation!==draft?.generation||view.snapshot?.version!==draft?.snapshot?.version;save.disabled=blocked||stale||!draft?.writable||(isPriority?((priority!=='normal'||scopeOf(t)!=='all')&&!t.revision)||(priority==='normal'&&scopeOf(t)==='all'&&!hasCap()):(enabled.checked&&!t.revision)||(!enabled.checked&&!hasCap()));remove.disabled=blocked||stale||!draft?.writable||!hasCap();};
  updateActions=()=>{if(d.isConnected)buttons();};buttons();place();d.focus({preventScroll:true});
  input.oninput=()=>{edited=true;};enabled.onchange=()=>{edited=true;buttons();};
  units.onchange=()=>{if(!input.value.trim()){unit=units.value as UploadRateUnit;edited=true;return;}try{const bits=uploadRateBits(input.value,unit);unit=units.value as UploadRateUnit;input.value=uploadRateValue(bits,unit);edited=true;}catch(e){units.value=unit;summary.textContent=String(e instanceof Error?e.message:e);reveal();}};
  const drafts=new Map<LimitScope,{value:string;unit:UploadRateUnit;enabled:boolean;priority:PriorityChoice;edited:boolean}>();
  const loadZone=()=>{
    const c=draft?.snapshot?.configured_caps.find(c=>sameTarget(c,t));
    const inheritedPriority=draft?.snapshot?.configured_caps.find(x=>sameTarget(x,{...t,scope:'all'}))?.traffic_priority ?? 'normal';
    const saved=drafts.get(scopeOf(t));
    if(saved){input.value=saved.value;unit=saved.unit;units.value=unit;enabled.checked=saved.enabled;priority=saved.priority;edited=saved.edited;}
    else {edited=false;priority=c?.traffic_priority ?? (scopeOf(t)!=='all'?'inherit':defaults.priority);enabled.checked=true;unit=direction==='download'?defaults.downloadUnit:defaults.uploadUnit;units.value=unit;input.value=uploadRateValue(capRate(c,direction==='priority'?'upload':direction)||(direction==='download'?defaults.downloadBits:defaults.uploadBits),unit);}
    if (isPriority) {
      inheritedLabel.hidden = inheritedChoice.disabled = scopeOf(t) === 'all';
      inheritedLabel.querySelector('span')!.textContent = `Inherited (${inheritedPriority[0].toUpperCase()+inheritedPriority.slice(1)})`;
      for (const input of priorityChoices.querySelectorAll('input')) input.checked = input.value === priority;
    }
    const all=draft?.snapshot?.configured_caps.find(c=>sameTarget(c,{...t,scope:'all'}));
    const inherited=scopeOf(t)!=='all' && (isPriority?!!all?.traffic_priority:!!capRate(all,direction as LimitDirection));
    zoneHint.textContent=isPriority&&scopeOf(t)!=='all'?(c?.traffic_priority!==undefined?`Override: ${c.traffic_priority[0].toUpperCase()+c.traffic_priority.slice(1)}`:`Inherited: ${inheritedPriority[0].toUpperCase()+inheritedPriority.slice(1)} (All networks)`):(inherited?'All applies':'');
    zoneHint.title=isPriority?'Delete to restore the All networks priority.':'Both the zone and All networks limits apply.';
    zone.title=view.zoneSupported?'Unknown networks use All networks.':'This daemon supports All networks only.';
    buttons();
  };
  const read=async()=>{blocked=true;buttons();try{const sent=performance.now(),start=context;const [v,prefs]=await Promise.all([window.flowgate.uploadStatus(),window.flowgate.preferences().catch(()=>undefined)]);defaults={...(prefs?.shapingDefaults || DEFAULT_SHAPING)};if(start!==context)throw Error('Connection changed; refresh again');adopt(v,sent);paint();if(!d.isConnected)return;draft=view;if(!edited)loadZone();summary.textContent='';blocked=false;paint();if(!view.writable||view.snapshot?.last_error)reveal();}catch(e){summary.textContent=String(e);reveal();}buttons();};
  const apply=async(rate:number|null,prio?:TrafficPriority|null)=>{if(!draft?.generation||!draft.snapshot)return;blocked=true;buttons();try{const sent=performance.now(),start=context;const result=await window.flowgate.uploadConfigure(isPriority?{generation:draft.generation,expected_version:draft.snapshot.version,target:t,bits_per_second:null,priority:prio===undefined?null:prio}:{generation:draft.generation,expected_version:draft.snapshot.version,target:t,direction:direction as LimitDirection,bits_per_second:rate});if(start!==context)throw Error('Connection changed; refresh again');adopt(result,sent);paint();if(d.isConnected)dismiss();}catch(e){if(!d.isConnected)return;summary.textContent=String(e);reveal();}};
  save.onclick=()=>{try{if(isPriority&&scopeOf(t)!=='all'&&!hasCap()&&!edited){dismiss();return;}if(isPriority){if(priority==='inherit'){if(hasCap())void apply(null,null);else dismiss();}else void apply(null,priority);return;}void apply(enabled.checked?uploadRateBits(input.value,unit):null);}catch(e){summary.textContent=String(e instanceof Error?e.message:e);reveal();}};
  input.onkeydown=e=>{if(e.key==='Enter'&&!e.isComposing){e.preventDefault();if(!save.disabled)save.click();}};
  remove.onclick=()=>void apply(null,null);refresh.onclick=()=>{drafts.clear();edited=false;void read();};await read();
  // A slow status reply must not steal focus or select a draft the user already edited.
  if(d.isConnected && !blocked && !edited && document.activeElement===d){if(isPriority)priorityChoices.querySelector<HTMLInputElement>('input:checked')?.focus({preventScroll:true});else if(!save.disabled){input.focus({preventScroll:true});input.select();}}
}
