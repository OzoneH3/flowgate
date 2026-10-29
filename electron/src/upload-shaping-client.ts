import { call, type Backend } from './backend';
import { parseUpload, replaceCap, validateBudget, ZONE_CAPABILITY, scopeOf, DOWNLOAD_CAPABILITY, PRIORITY_CAPABILITY, UPLOAD_CAPABILITY, type UploadView, type UploadEdit, type UploadCleanup, type BudgetEdit } from './upload-shaping';
export class UploadShapingClient {
  private busy = false;
  constructor(private backend: Backend) {}
  private target() {
    const c=this.backend.view().control;
    if (!this.backend.controller || !c.connected || !c.generation || c.permissions?.role!=='administrator' || !c.capabilities?.includes(UPLOAD_CAPABILITY)) return;
    return {path:this.backend.controller, generation:c.generation, writable:!c.readOnly, downloadSupported:c.capabilities.includes(DOWNLOAD_CAPABILITY), prioritySupported:c.capabilities.includes(PRIORITY_CAPABILITY), zoneSupported:c.capabilities.includes(ZONE_CAPABILITY)};
  }
  async read(): Promise<UploadView> {
    const t=this.target();
    if (!t) return {supported:false,writable:false,message:'Unsupported: requires an opted-in experimental daemon and administrator connection.'};
    try {
      const r=await call(t.path,{operation:'upload-status',generation:t.generation});
      if (this.target()?.generation!==t.generation || r.generation!==t.generation) throw Error('Daemon changed; refresh the upload limit.');
      if (r.error || r.error_code) throw Error(r.error || r.error_code);
      return {supported:true,downloadSupported:t.downloadSupported,prioritySupported:t.prioritySupported,zoneSupported:t.zoneSupported,writable:t.writable,generation:t.generation,snapshot:parseUpload(r.upload_shaping),message:''};
    } catch(e) {return {supported:true,writable:false,message:String(e instanceof Error?e.message:e)};}
  }
  async configure(value: unknown): Promise<UploadView> {
    if(this.busy) throw Error('An upload configuration is already pending');
    const e=value as UploadEdit & Partial<UploadCleanup> & Partial<BudgetEdit>, t=this.target();
    if(!t?.writable) throw Error('Upload configuration requires an administrator write connection');
    if(e?.direction==='download' && !t.downloadSupported) throw Error('Download limits are not supported by this daemon');
    if((e?.priority!==undefined || e?.budgets!==undefined) && !t.prioritySupported) throw Error('Traffic priority is not supported by this daemon');
    if(e?.target && scopeOf(e.target)!=='all' && !t.zoneSupported) throw Error('Zone shaping is not supported by this daemon');
    if(!e || e.generation!==t.generation) throw Error('Daemon changed; refresh and review the draft.');
    this.busy=true;
    try {
      const current=await this.read();
      if(!current.snapshot || current.generation!==e.generation) throw Error(current.message || 'Refresh current configuration');
      if (e.cleanup_only === true && (current.snapshot.version !== e.expected_version || current.snapshot.enabled || current.snapshot.configured_caps.length)) throw Error("Cleanup requires a current disabled, empty configuration; refresh first");
      if (e.budgets!==undefined && current.snapshot.version!==e.expected_version) throw Error('Configuration changed. Refresh and review the draft before saving.');
      const caps=e.cleanup_only === true ? [] : e.budgets!==undefined ? current.snapshot.configured_caps : replaceCap(current.snapshot,e);
      // Budgets are preserved unless this is an explicit budget edit; cleanup clears them.
      const budgets=e.cleanup_only === true ? {upload:0,download:0} : e.budgets!==undefined ? {upload:validateBudget(e.budgets.upload),download:validateBudget(e.budgets.download)} : {upload:current.snapshot.upload_budget_bits_per_second||0,download:current.snapshot.download_budget_bits_per_second||0};
      // A row observation is a candidate hint only; the controller repeats fresh proof.
      if(e.cleanup_only !== true && e.budgets===undefined && (e.priority!==undefined ? e.priority!==null && (e.priority!=='normal' || scopeOf(e.target)!=='all') : e.bits_per_second!==null)) {
        const observation=this.backend.view().observation;
        if (!observation.connected) throw Error("Activity disconnected; refresh the native application observation");
        const processes=Object.values(observation.activity?.processes || {});
        if(!processes.some(p=>p.uid===e.target.uid && p.application.key===e.target.application && p.application.kind==='native' && !!p.application.revision && p.application.revision===e.target.revision && !p.application.hosted)) throw Error('No current native application observation; refresh Activity.');
      }
      // Schema 2 fields are sent only to a daemon advertising traffic priority, so
      // an older daemon never silently drops them; omission never clears them.
      const advanced=t.prioritySupported?{schema:t.zoneSupported?3:2,upload_budget_bits_per_second:budgets.upload,download_budget_bits_per_second:budgets.download}:{};
      const r=await call(t.path,{operation:'upload-configure',generation:e.generation,expected_version:e.expected_version,upload_config:{enabled:caps.length>0 || budgets.upload>0 || budgets.download>0,caps,...advanced}});
      if(r.error || r.error_code) throw Error(r.error || r.error_code);
      if(this.target()?.generation!==e.generation || this.target()?.path!==t.path || r.generation!==e.generation) throw Error('Daemon changed during submission');
      return {supported:true,downloadSupported:t.downloadSupported,prioritySupported:t.prioritySupported,zoneSupported:t.zoneSupported,writable:true,generation:e.generation,snapshot:parseUpload(r.upload_shaping),message:'Configuration accepted; binding coverage is still asynchronous.'};
    } catch(err) {
      // Never retry writes: even a missing receipt may mean the operation was accepted.
      throw Error(`${err instanceof Error?err.message:String(err)}. Refresh status and review before submitting again; no automatic retry.`);
    } finally {this.busy=false;}
  }
}
