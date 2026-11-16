import {call, BackendCallError, type Backend} from './backend';
export const CHECKS_CAPABILITY='connection-check-settings-v1';
export interface CheckSettings {enabled:boolean;revision:string}
export interface CheckView {settings?:CheckSettings;writable:boolean;message:string}
export function parseChecks(raw:unknown):CheckSettings {
 const v=raw as CheckSettings;
 if(!v || typeof v.enabled!=='boolean' || typeof v.revision!=='string' || !/^[1-9][0-9]{0,18}$/.test(v.revision))throw Error('Invalid connection check settings');
 return {enabled:v.enabled,revision:v.revision};
}
export class ConnectionChecksClient {
 private busy=false;
 private unknown?:{context:string;revision:bigint};
 constructor(private backend:Backend){}
 private target(){const v=this.backend.view(),c=v.control,o=v.observation;
  if(this.backend.controller && c.connected && c.capabilities?.includes(CHECKS_CAPABILITY))return {path:this.backend.controller,generation:c.generation,write:!c.readOnly && c.permissions?.role==='administrator' && c.permissions?.can_manage_machine_rules===true};
  if(o.connected && o.capabilities?.includes(CHECKS_CAPABILITY))return {path:this.backend.observer,generation:o.generation,write:false};
 }
 async request(raw?:unknown):Promise<CheckView>{
  const t=this.target(),context=JSON.stringify(t),write=raw!==undefined;
  if(!t)return {writable:false,message:'Connection recheck settings are unavailable from this daemon.'};
  if(this.busy) return {writable:false,message:'Settings request in progress.'};
  if(write && (!t.write || this.unknown?.context===context))return {writable:false,message:'Refresh settings before editing; writable administrator access is required.'};
  let desired:CheckSettings|undefined;
  if(write){const o=raw as {enabled:unknown;expected_revision:unknown};desired=parseChecks({enabled:o?.enabled,revision:o?.expected_revision});}
  this.busy=true;
  try {
   const r=await call(t.path,{operation:write?'connection-check-configure':'connection-check-status',generation:t.generation,...(desired?{connection_checks:{enabled:desired.enabled,expected_revision:desired.revision}}:{})});
   if(JSON.stringify(this.target())!==context || r.generation!==t.generation)throw Error('Connection changed; refresh settings.');
   if(r.error || r.error_code){desired=undefined;throw Error(r.error || r.error_code);}
   const s=parseChecks(r.connection_checks);
   if(desired && (s.enabled!==desired.enabled || BigInt(s.revision)!==BigInt(desired.revision)+1n))throw Error('Settings acknowledgement mismatch');
   if(!write && this.unknown?.context===context && BigInt(s.revision)>=this.unknown.revision)this.unknown=undefined;
   const pending=this.unknown?.context===context;
   return {settings:s,writable:t.write&&!pending,message:pending?'Earlier save outcome is unknown; refresh again. No automatic retry.':write?'Saved. Checks already running may finish.':'Current daemon settings.'};
  }catch(e){if(desired && !(e instanceof BackendCallError && !e.requestMayHaveBeenSent))this.unknown={context,revision:BigInt(desired.revision)+1n};return {writable:false,message:String(e)+(write?' Save outcome unconfirmed; use Refresh. No automatic retry.':'')};}
  finally{this.busy=false;}
 }
}
