import {uploadTarget, uploadSummary, UPLOAD_CAPABILITY, type UploadView, type UploadTarget} from './upload-shaping';
import type {Row} from './model';
import type {ClientState} from './protocol';
let view:UploadView={supported:false,writable:false,message:'Unsupported: experimental upload controller is not enabled.'};
let flight=false, last=0, context='', leaseDeadline=0;
let dialogTarget:UploadTarget|undefined, latestState:ClientState|undefined;
let updateActions:(()=>void)|undefined;
function adopt(v:UploadView,start:number) { if(v.generation===view.generation && v.snapshot && view.snapshot && v.snapshot.version<view.snapshot.version)return; view=v; leaseDeadline=start+Math.max(0, v.snapshot?.coverage_valid_for_ms||0); }
function coverageExpired() { return view.snapshot?.coverage_snapshot_expired || performance.now()>=leaseDeadline; }
const targets=new WeakMap<HTMLElement,UploadTarget>();
const text=<K extends keyof HTMLElementTagNameMap>(tag:K,value:string)=>{const e=document.createElement(tag);e.textContent=value;return e;};
function coverage(t:UploadTarget) {
  const s=view.snapshot, rows=s?.kernel?.bindings?.filter(b=>b.app===`${t.uid}:${t.application}`)||[];
  const confirmed=coverageExpired()?0:rows.filter(b=>b.covered===true).length;
  return `${confirmed} confirmed / ${rows.length} requested socket bindings. Coverage is partial; not an application-wide guarantee.`;
}
function paint() {
  updateActions?.();
  const live=document.getElementById('uploadCoverageLive');
  if(live && dialogTarget) live.textContent=`${uploadSummary(view,dialogTarget)} · ${coverage(dialogTarget)} ${view.message} ${view.snapshot?.last_error||''}`;

  for(const b of document.querySelectorAll<HTMLButtonElement>('[data-upload-limit]')) {
    const t=targets.get(b); if(!t)continue;
    b.textContent=uploadSummary(view,t)==='Off'?'↑':uploadSummary(view,t);
    b.title=`Upload limit · ${uploadSummary(view,t)}\n${coverage(t)}\n${view.message}`;
  }
}
export function refreshUpload(state:ClientState) {
  latestState=state;
  paint();
  const key=JSON.stringify([state.control.generation,state.control.connected,state.control.permissions?.role,state.control.capabilities?.includes(UPLOAD_CAPABILITY)]);
  if(key!==context){context=key;view={supported:false,writable:false,message:'Unsupported or awaiting current daemon status.'};paint();last=0;}
  if(!state.control.connected || !state.control.capabilities?.includes(UPLOAD_CAPABILITY) || state.control.permissions?.role!=='administrator' || flight || Date.now()-last<1500)return;
  flight=true;last=Date.now();const start=context, sent=performance.now();
  void window.flowgate.uploadStatus().then(v=>{if(start===context){adopt(v,sent);paint();}}).catch(()=>{if(start===context){view={supported:true,writable:false,message:"Upload status unavailable"};paint();}}).finally(()=>{flight=false;});
}
export function uploadButton(row:Row,state:ClientState) {
  const t=uploadTarget(row,state), b=document.createElement('button');
  b.className='status-slot upload-limit'; b.dataset.uploadLimit='';
  b.setAttribute('aria-label',`Upload limit for ${row.label}`);b.setAttribute('aria-haspopup','dialog');
  if(t){targets.set(b,t);b.textContent=uploadSummary(view,t)==='Off'?'↑':uploadSummary(view,t);b.title=`Upload limit · ${uploadSummary(view,t)}\n${coverage(t)}`;b.onclick=e=>{e.stopPropagation();void open(t);};}
  else{b.disabled=true;b.textContent='·';b.title='Unsupported: select one verified native application or process. Runtime/shared identities are not supported.';}
  return b;
}
export async function openUploadLimits() {
  const sent=performance.now(), start=context; const v=await window.flowgate.uploadStatus(); if(start!==context) throw Error("Connection changed; reopen limits"); adopt(v,sent);
  const d=document.createElement("dialog");d.id="uploadLimitList";d.className="upload-limit-dialog";
  d.append(text("h3","Experimental upload limits"),text("p",view.message||"Configured limits survive closing the GUI, but not a daemon restart. Coverage remains partial."));
  for(const c of view.snapshot?.configured_caps||[]){const b=text("button",`${c.application} · UID ${c.uid} · ${c.bits_per_second/1000000} Mbit/s`);b.onclick=()=>{d.remove();const p=latestState?.observation.connected ? Object.values(latestState.observation.activity?.processes||{}).find(p=>p.uid===c.uid&&p.application.key===c.application&&p.application.kind==='native'):undefined;void open({...c,revision:p?.application.revision});};d.append(b);}
  if(!view.snapshot?.configured_caps.length)d.append(text("p","No configured limits. Select a verified native application’s ↑ UL Limit slot in Activity to add one."));
  if(view.writable && view.generation && view.snapshot && !view.snapshot.enabled && !view.snapshot.configured_caps.length && view.snapshot.status==='Unsupported') {
    const saved=view, retry=text('button','Retry owned cleanup'); retry.id='uploadCleanup';
    retry.onclick=async()=>{retry.disabled=true;try{const result=await window.flowgate.uploadConfigure({generation:saved.generation!,expected_version:saved.snapshot!.version,cleanup_only:true});d.append(text('p',result.message+' Close and refresh to verify cleanup.'));}catch(e){d.append(text('p',String(e)));}};d.append(retry);
  }
  const close=text("button","Close");close.onclick=()=>d.remove();d.append(close);document.body.append(d);d.showModal();
}
async function open(t:UploadTarget) {
  document.getElementById('uploadLimitDialog')?.remove();
  dialogTarget=t;
  const d=document.createElement('dialog');d.id='uploadLimitDialog';d.className='upload-limit-dialog';
  const heading=text('h3',`Upload limit · ${t.label||t.application}`), summary=text('p','Reading current configuration…');summary.id='uploadCoverage';summary.setAttribute('role','status');
  const input=document.createElement('input');input.id='uploadRate';input.type='number';input.min='1';input.max='1000';input.step='0.001';input.value='8';
  const label=text('label','Configured upload rate (Mbit/s) ');label.append(input);
  const save=text('button','Enable / save'), remove=text('button','Disable limit'), refresh=text('button','Refresh status / review'), close=text('button','Close');
  save.id='uploadSave';remove.id='uploadRemove';refresh.id='uploadRefresh';close.id='uploadClose';
  const detail=text('p','Experimental · verified native sockets on the selected interface only. First traffic and unsupported sockets may escape. UDP GSO is unsupported; TCP caps are receiver-tested. Limits do not grant firewall Allow. Socket assignment survives exec/transfer until close or fresh rebinding. Limits end at daemon restart.');detail.className='hint';
  const live=text('p','');live.id='uploadCoverageLive';
  d.append(heading,live,summary,label,detail,save,remove,refresh,close);document.body.append(d);d.showModal();close.onclick=()=>d.remove();
  let draft:UploadView|undefined, blocked=true;
  const buttons=()=>{const stale=!view.writable||view.generation!==draft?.generation||view.snapshot?.version!==draft?.snapshot?.version;save.disabled=blocked||stale||!t.revision||!draft?.writable;remove.disabled=blocked||stale||!draft?.writable||!draft?.snapshot?.configured_caps.some(c=>c.uid===t.uid&&c.application===t.application);};updateActions=()=>{if(d.isConnected)buttons();};buttons();
  const read=async()=>{blocked=true;buttons();try {const sent=performance.now(), start=context;const v=await window.flowgate.uploadStatus();if(start!==context)throw Error("Connection changed; refresh again");adopt(v,sent);draft=view;const c=view.snapshot?.configured_caps.find(c=>c.uid===t.uid&&c.application===t.application);if(c)input.value=String(c.bits_per_second/1000000);summary.textContent=`${view.snapshot?.interface?'Interface '+view.snapshot.interface+'. ':''}${view.message} ${view.snapshot?.last_error||''}`;blocked=false;paint();}catch(e){summary.textContent=String(e);}buttons();};
  const apply=async(rate:number|null)=>{if(!draft?.generation||!draft.snapshot)return;blocked=true;buttons();try{const sent=performance.now(), start=context;const result=await window.flowgate.uploadConfigure({generation:draft.generation,expected_version:draft.snapshot.version,target:t,bits_per_second:rate});if(start!==context)throw Error("Connection changed; refresh again");adopt(result,sent);summary.textContent=`Pending · ${view.message} Refresh to observe binding coverage or completed removal.`;paint();}catch(e){summary.textContent=String(e);}/* Refresh must explicitly reconcile both accepted and uncertain outcomes. */};
  save.onclick=()=>void apply(Math.round(Number(input.value)*1000000));remove.onclick=()=>void apply(null);refresh.onclick=()=>void read();await read();
}
