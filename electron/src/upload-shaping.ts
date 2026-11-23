import type { Row } from './model';
import type { ClientState } from './protocol';
export const SAVED_SHAPING_CAPABILITY = 'saved-shaping-settings-v1';
export const MAX_STORED_CAPS = 1024;
export const ZONE_CAPABILITY = 'experimental-zone-shaping-v1';
export type LimitScope = 'all' | 'internet' | 'local';
export const scopeOf = (t: {scope?: string}): LimitScope => (t.scope || 'all') as LimitScope;
export const scopeLabel = (scope: LimitScope): string => scope==='local'?'Local Network':scope==='internet'?'Internet':'All networks';
export const sameTarget = (a: UploadTarget, b: UploadTarget): boolean => a.uid===b.uid && a.application===b.application && scopeOf(a)===scopeOf(b);
export const DOWNLOAD_CAPABILITY = 'experimental-native-download-v1';
export type LimitDirection = 'upload' | 'download';
export const UPLOAD_CAPABILITY = 'experimental-native-upload-v1';
export const PRIORITY_CAPABILITY = 'experimental-traffic-priority-v1';
// One traffic priority per application/scope for both directions. All-network
// Normal is omitted; explicit zone Normal overrides inherited priority.
export type TrafficPriority = 'low' | 'normal' | 'high';
export const TRAFFIC_PRIORITIES: readonly TrafficPriority[] = ['low','normal','high'];
export const MIN_BUDGET = 16000000, MAX_BUDGET = 10000000000;
export interface UploadTarget { scope?: '' | LimitScope; uid: number; application: string; label?: string; revision?: string; stored_only?: boolean }
export interface UploadCap extends UploadTarget { bits_per_second: number; download_bits_per_second?: number; traffic_priority?: TrafficPriority }
export interface UploadSnapshot {
  version: number; applied_version: number; enabled: boolean; interface: string; status: string;
  configured_caps: UploadCap[]; upload_budget_bits_per_second?: number; download_budget_bits_per_second?: number; last_error?: string; coverage_snapshot_expired?: boolean; coverage_valid_for_ms?: number;
  kernel?: { valid_for_ms?: number; covered_bindings?: number; bindings?: {app: string; zone?: string; covered?: boolean; download?: boolean; upload_class?: boolean; download_class?: boolean}[]; limitations?: string[]; fault?: string };
}
export interface UploadView { supported: boolean; downloadSupported?: boolean; prioritySupported?: boolean; zoneSupported?: boolean; writable: boolean; generation?: string; snapshot?: UploadSnapshot; message: string }
export interface UploadCleanup { generation: string; expected_version: number; cleanup_only: true }
export interface UploadEdit { generation: string; expected_version: number; target: UploadTarget; direction?: LimitDirection; bits_per_second: number | null; priority?: TrafficPriority | null }
export interface BudgetEdit { generation: string; expected_version: number; budgets: { upload: number; download: number } }
export function savedUploadTarget(state: ClientState, target: UploadTarget): UploadTarget | undefined {
  if (!state.control?.connected || !target.application || !target.revision) return;
  const rules = state.control.rules?.filter(rule =>
    !rule.preset && !rule.network_endpoint && !rule.filter.all_programs && !rule.filter.all_uids &&
    rule.filter.application === target.application && rule.filter.revision === target.revision &&
    rule.filter.uid === target.uid);
  if (rules?.some(rule => rule.native_shaping_identity === true)) return target;
  if (rules?.length && state.control.capabilities?.includes(SAVED_SHAPING_CAPABILITY))
    return { ...target, stored_only: true };
}
export function uploadTarget(row: Row, state: ClientState): UploadTarget | undefined {
  if (row.displayApplication || !['application','process'].includes(row.kind)) return;
  const zone=row.applicationZone;
  if(zone && (!state.control?.capabilities?.includes(ZONE_CAPABILITY) || !state.control.networkZones || zone.model!==state.control.networkZones.model)) return;
  if (row.inactive) {
    const {key, revision, uid} = row.inactive;
    const saved = {uid, application:key, revision, label:row.label, ...(zone ? {scope:zone.zone} : {})};
    return savedUploadTarget(state,saved);
  }
  if (!state.observation?.connected) return;
  if (row.runtimeApplication) {
    const {uid, application} = row.runtimeApplication;
    if (!application?.key || !application.revision) return;
    return savedUploadTarget(state,{uid, application:application.key, revision:application.revision, label:row.label,
      ...(zone ? {scope:zone.zone} : {})});
  }
  const p = row.process;
  if (!p || !p.application.key || !p.application.revision) return;
  const target = {uid:p.uid, application:p.application.key, revision:p.application.revision, label:row.label,
    ...(zone?{scope:zone.zone}:{})};
  return p.application.kind === 'native' && !p.application.hosted ? target : savedUploadTarget(state,target);
}
// Presentation only. Socket binding is verified independently by the controller.
export function shapingUnavailableReason(row: Row, state: ClientState, view: UploadView, kind: LimitDirection|'priority'): string | undefined {
  const reasons:string[]=[];
  const target = uploadTarget(row,state);
  if (row.inactive && !target) reasons.push('No matching saved application identity is available for shaping.');
  else if (!row.inactive && !state.observation?.connected) reasons.push('Current socket observation is disconnected.');
  else if (!target && (row.runtimeApplication || row.displayApplication || row.process?.application.kind==='wine')) reasons.push('Wine/runtime or shared-owner application shaping is not supported; only verified native application sockets are eligible.');
  else if (!target) reasons.push('No current eligible native application target is available for this row.');
  if (!state.control?.connected) reasons.push('The control connection is disconnected.');
  else if (!state.control.capabilities?.includes(UPLOAD_CAPABILITY) || (kind==='download'&&!state.control.capabilities?.includes(DOWNLOAD_CAPABILITY)) || (kind==='priority'&&!state.control.capabilities?.includes(PRIORITY_CAPABILITY))) reasons.push('This backend does not provide the requested shaping capability.');
  else if (state.control.permissions?.role!=='administrator' || state.control.readOnly) reasons.push('Shaping changes require an administrator with write access.');
  if (!view.supported || (!target?.stored_only && view.snapshot?.status==='Unsupported')) reasons.push('Host shaping unavailable: '+(view.snapshot?.last_error||view.message||'Status unavailable.'));
  else if (!view.writable) reasons.push(view.message||'Host shaping is read-only.');
  return reasons.length ? reasons.join(' ') : undefined;
}
export function parseUpload(raw: unknown): UploadSnapshot {
  const r = raw as UploadSnapshot;
  if (r && r.configured_caps === null) r.configured_caps = [];
  if (!r || !Number.isSafeInteger(r.version) || r.version < 1 || !Number.isSafeInteger(r.applied_version) || typeof r.enabled !== 'boolean' || !Array.isArray(r.configured_caps) || r.configured_caps.length > 48 + MAX_STORED_CAPS || !['Disabled','Applying','Active','Partial','Unsupported'].includes(r.status)) throw Error('Invalid upload-limit status');
  for (const c of r.configured_caps) validateCap(c);
  return r;
}
export function capRate(c: UploadCap | undefined, direction: LimitDirection = 'upload'): number {
  return (direction === 'download' ? c?.download_bits_per_second : c?.bits_per_second) || 0;
}
export function validateCap(c: UploadCap) {
  const validRate=(n:unknown)=>Number.isSafeInteger(n) && (n===0 || Number(n)>=1000000 && Number(n)<=1000000000);
  const prio=c?.traffic_priority;
  if (!['all','local','internet'].includes(scopeOf(c || {}))) throw Error('Invalid network zone');
  if (prio!==undefined && !TRAFFIC_PRIORITIES.includes(prio)) throw Error('Traffic priority must be Low, Normal or High');
  if (!c || !Number.isSafeInteger(c.uid) || c.uid < 0 || typeof c.application !== 'string' || !c.application || c.application.length > 4096 || !validRate(c.bits_per_second) || !validRate(c.download_bits_per_second ?? 0) || !(c.bits_per_second || c.download_bits_per_second || prio)) throw Error('Use a native application and a rate from 1 to 1000 Mbit/s');
}
export function validateCapacity(caps: UploadCap[]) {
  const active = caps.filter(c => !c.stored_only);
  if (caps.length - active.length > MAX_STORED_CAPS) throw Error('Saved shaping settings capacity exceeded.');
  const apps=new Map<string,boolean>();
  for(const c of active){const key=`${c.uid}:${c.application}`;apps.set(key,!!apps.get(key)||scopeOf(c)!=='all');}
  if(active.length>48 || [...apps.values()].reduce((n,zoned)=>n+(zoned?4:1),0)>16)throw Error('Shaping capacity exceeded: 16 class slots; each zoned application uses four.');
}
export function replaceCap(s: UploadSnapshot, edit: UploadEdit): UploadCap[] {
  if (edit?.priority !== undefined) return replacePriority(s, edit);
  if (!edit || !Number.isSafeInteger(edit.expected_version) || edit.expected_version < 1 || (edit.direction !== undefined && edit.direction !== 'upload' && edit.direction !== 'download') || (edit.bits_per_second !== null && (!Number.isSafeInteger(edit.bits_per_second) || edit.bits_per_second<1000000 || edit.bits_per_second>1000000000))) throw Error("Invalid upload configuration draft or rate");
  if (s.version !== edit.expected_version) throw Error('Configuration changed. Refresh and review the draft before saving.');
  validateCap({...edit.target,bits_per_second:1000000});
  const old=s.configured_caps.find(c=>sameTarget(c,edit.target));
  const cap:UploadCap={...(scopeOf(edit.target)!=='all'?{scope:scopeOf(edit.target)}:{}),uid:edit.target.uid,application:edit.target.application,bits_per_second:old?.bits_per_second || 0, ...(edit.target.stored_only || old?.stored_only ? { stored_only:true } : {})};
  if(old?.download_bits_per_second)cap.download_bits_per_second=old.download_bits_per_second;
  if(old?.traffic_priority)cap.traffic_priority=old.traffic_priority; // a rate edit keeps the priority
  if(edit.direction==='download') {if(edit.bits_per_second===null)delete cap.download_bits_per_second;else cap.download_bits_per_second=edit.bits_per_second;}
  else cap.bits_per_second=edit.bits_per_second ?? 0;
  const caps=s.configured_caps.filter(c=>!sameTarget(c,cap));
  if(cap.bits_per_second || cap.download_bits_per_second || cap.traffic_priority){validateCap(cap);caps.push(cap);}
  validateCapacity(caps);
  return caps;
}
// Priority edit keeps both rates. Null deletes; explicit zone Normal overrides
// an inherited priority. Legacy All networks Normal remains omitted.
export function replacePriority(s: UploadSnapshot, edit: UploadEdit): UploadCap[] {
  if (!edit || !Number.isSafeInteger(edit.expected_version) || edit.expected_version < 1 || (edit.priority!==null && !TRAFFIC_PRIORITIES.includes(edit.priority as TrafficPriority))) throw Error('Invalid traffic priority draft');
  if (s.version !== edit.expected_version) throw Error('Configuration changed. Refresh and review the draft before saving.');
  validateCap({...edit.target,bits_per_second:1000000});
  const old=s.configured_caps.find(c=>sameTarget(c,edit.target));
  const cap:UploadCap={...(scopeOf(edit.target)!=='all'?{scope:scopeOf(edit.target)}:{}),uid:edit.target.uid,application:edit.target.application,bits_per_second:old?.bits_per_second || 0, ...(edit.target.stored_only || old?.stored_only ? { stored_only:true } : {})};
  if(old?.download_bits_per_second)cap.download_bits_per_second=old.download_bits_per_second;
  if(edit.priority!==null && (edit.priority!=='normal' || scopeOf(edit.target)!=='all'))cap.traffic_priority=edit.priority as TrafficPriority;
  const caps=s.configured_caps.filter(c=>!sameTarget(c,cap));
  if(cap.bits_per_second || cap.download_bits_per_second || cap.traffic_priority){validateCap(cap);caps.push(cap);}
  validateCapacity(caps);
  return caps;
}
export function validateBudget(bits:number):number {
  if(!Number.isSafeInteger(bits) || (bits!==0 && (bits<MIN_BUDGET || bits>MAX_BUDGET))) throw Error('Budget: empty for none, or 16–10000 Mbit/s.');
  return bits;
}
export function capPriority(c: UploadCap | undefined): TrafficPriority { return c?.traffic_priority || 'normal'; }
export function prioritySummary(v: UploadView, t?: UploadTarget): string {
  if (!v.supported || !v.snapshot || !v.prioritySupported) return 'Unsupported';
  const s=v.snapshot, c=t && s.configured_caps.find(c=>sameTarget(c,t));
  if (t?.stored_only || c?.stored_only) return c?.traffic_priority ? `${capPriority(c)} · Saved only` : 'Normal · Saved only';
  if (s.status==='Unsupported') return 'Unsupported';
  if (s.status==='Applying' || s.applied_version!==s.version) return 'Pending';
  const prio=capPriority(c), name=prio[0].toUpperCase()+prio.slice(1);
  if (prio==='normal') return 'Normal';
  const active=[s.upload_budget_bits_per_second?'UL':'',s.download_budget_bits_per_second?'DL':''].filter(Boolean);
  return active.length?`${name} · ${active.join('+')} budget · Partial`:`${name} · inactive (no budget)`;
}
// Confirmed bindings carry a class in a budgeted direction; priority never
// claims application-wide enforcement or coverage for unbudgeted directions.
export function priorityCoverage(s:UploadSnapshot | undefined, t:UploadTarget, expired:boolean) {
  const c=s?.configured_caps.find(c=>sameTarget(c,t));
  if(c?.traffic_priority===undefined || !(s?.upload_budget_bits_per_second || s?.download_budget_bits_per_second))return {requested:0,confirmed:0};
  const rows=s?.kernel?.bindings?.filter(b=>b.app===`${t.uid}:${t.application}` && (scopeOf(t)==='all' || b.zone===scopeOf(t)))||[];
  return {requested:rows.length,confirmed:expired?0:rows.filter(b=>b.covered===true && ((s?.upload_budget_bits_per_second && b.upload_class) || (s?.download_budget_bits_per_second && b.download_class))).length};
}
export function limitCoverage(s:UploadSnapshot | undefined, t:UploadTarget, direction:LimitDirection, expired:boolean) {
  const cap=s?.configured_caps.find(c=>sameTarget(c,t));
  if(!capRate(cap,direction))return {requested:0,confirmed:0};
  const rows=s?.kernel?.bindings?.filter(b=>b.app===`${t.uid}:${t.application}` && (scopeOf(t)==='all' || b.zone===scopeOf(t)))||[];
  return {requested:rows.length,confirmed:expired?0:rows.filter(b=>b.covered===true && (direction==='upload'?b.upload_class===true:b.download_class===true && b.download===true)).length};
}
export function uploadSummary(v: UploadView, t?: UploadTarget, direction: LimitDirection = 'upload'): string {
  if (!v.supported || !v.snapshot || (direction==='download' && !v.downloadSupported)) return 'Unsupported';
  const s=v.snapshot, c=t && s.configured_caps.find(c=>sameTarget(c,t));
  if (t?.stored_only || c?.stored_only) return capRate(c,direction) ? `${capRate(c,direction)/1000000} Mbit/s · Saved only` : 'Off · Saved only';
  if (s.status==='Unsupported') return 'Unsupported';
  if (s.status==='Applying' || s.applied_version!==s.version) return 'Pending';
  if (!capRate(c,direction)) return 'Off';
  return `${capRate(c,direction)/1000000} Mbit/s · Partial`;
}

// Reference UI units: byte prefixes are binary, bit prefixes decimal.
// Presentation only; conversion never rounds controller values.
export const UPLOAD_RATE_UNITS = ['B/s','KB/s','MB/s','GB/s','bit/s','Kbit/s','Mbit/s','Gbit/s'] as const;
export type UploadRateUnit = typeof UPLOAD_RATE_UNITS[number];
const uploadRateFactors: Record<UploadRateUnit, bigint> = {
  'B/s':8n,'KB/s':8192n,'MB/s':8388608n,'GB/s':8589934592n,
  'bit/s':1n,'Kbit/s':1000n,'Mbit/s':1000000n,'Gbit/s':1000000000n,
};
export function uploadRateBits(value:string, unit:UploadRateUnit):number {
  if (!Object.hasOwn(uploadRateFactors,unit) || !/^\d{1,16}(?:\.\d{1,33})?$/.test(value.trim())) throw Error('Enter a decimal rate.');
  const [whole,fraction='']=value.trim().split('.'), divisor=10n**BigInt(fraction.length);
  const scaled=BigInt(whole+fraction)*uploadRateFactors[unit];
  if(scaled%divisor!==0n)throw Error('The rate must represent a whole number of bit/s.');
  const bits=scaled/divisor;
  if(bits<1000000n || bits>1000000000n)throw Error('Supported rate: 1–1000 Mbit/s (125000–125000000 B/s).');
  return Number(bits);
}
export function uploadRateValue(bits:number,unit:UploadRateUnit):string {
  if(!Number.isSafeInteger(bits) || bits<1000000 || bits>1000000000 || !Object.hasOwn(uploadRateFactors,unit))throw Error('Invalid limit rate.');
  const factor=uploadRateFactors[unit],n=BigInt(bits),whole=n/factor;
  let remainder=n%factor,fraction='';
  while(remainder && fraction.length<33){remainder*=10n;fraction+=String(remainder/factor);remainder%=factor;}
  return String(whole)+(fraction?'.'+fraction:'');
}

// Frontend starting values only: saving these never creates a shaping rule.
export interface ShapingDefaults {
  priority: TrafficPriority;
  uploadBits: number;
  downloadBits: number;
  uploadUnit: UploadRateUnit;
  downloadUnit: UploadRateUnit;
}
export const DEFAULT_SHAPING: Readonly<ShapingDefaults> = {
  priority: 'normal', uploadBits: 8000000, downloadBits: 8000000,
  uploadUnit: 'Mbit/s', downloadUnit: 'Mbit/s',
};
export function validateShapingDefaults(value: unknown): ShapingDefaults {
  const d=value as ShapingDefaults;
  if(!d || typeof d!=='object' || Array.isArray(d) || Object.keys(d).some(k=>!Object.hasOwn(DEFAULT_SHAPING,k)) || !TRAFFIC_PRIORITIES.includes(d.priority)) throw Error('Invalid shaping defaults');
  uploadRateValue(d.uploadBits,d.uploadUnit);
  uploadRateValue(d.downloadBits,d.downloadUnit);
  return {...d};
}
