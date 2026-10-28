import { call, type Backend } from './backend';
import { parseUpload, replaceCap, DOWNLOAD_CAPABILITY, UPLOAD_CAPABILITY, type UploadView, type UploadEdit, type UploadCleanup } from './upload-shaping';
export class UploadShapingClient {
  private busy = false;
  constructor(private backend: Backend) {}
  private target() {
    const c=this.backend.view().control;
    if (!this.backend.controller || !c.connected || !c.generation || c.permissions?.role!=='administrator' || !c.capabilities?.includes(UPLOAD_CAPABILITY)) return;
    return {path:this.backend.controller, generation:c.generation, writable:!c.readOnly, downloadSupported:c.capabilities.includes(DOWNLOAD_CAPABILITY)};
  }
  async read(): Promise<UploadView> {
    const t=this.target();
    if (!t) return {supported:false,writable:false,message:'Unsupported: requires an opted-in experimental daemon and administrator connection.'};
    try {
      const r=await call(t.path,{operation:'upload-status',generation:t.generation});
      if (this.target()?.generation!==t.generation || r.generation!==t.generation) throw Error('Daemon changed; refresh the upload limit.');
      if (r.error || r.error_code) throw Error(r.error || r.error_code);
      return {supported:true,downloadSupported:t.downloadSupported,writable:t.writable,generation:t.generation,snapshot:parseUpload(r.upload_shaping),message:''};
    } catch(e) {return {supported:true,writable:false,message:String(e instanceof Error?e.message:e)};}
  }
  async configure(value: unknown): Promise<UploadView> {
    if(this.busy) throw Error('An upload configuration is already pending');
    const e=value as UploadEdit & Partial<UploadCleanup>, t=this.target();
    if(!t?.writable) throw Error('Upload configuration requires an administrator write connection');
    if(e?.direction==='download' && !t.downloadSupported) throw Error('Download limits are not supported by this daemon');
    if(!e || e.generation!==t.generation) throw Error('Daemon changed; refresh and review the draft.');
    this.busy=true;
    try {
      const current=await this.read();
      if(!current.snapshot || current.generation!==e.generation) throw Error(current.message || 'Refresh current configuration');
      if (e.cleanup_only === true && (current.snapshot.version !== e.expected_version || current.snapshot.enabled || current.snapshot.configured_caps.length)) throw Error("Cleanup requires a current disabled, empty configuration; refresh first");
      const caps=e.cleanup_only === true ? [] : replaceCap(current.snapshot,e);
      // A row observation is a candidate hint only; the controller repeats fresh proof.
      if(e.cleanup_only !== true && e.bits_per_second!==null) {
        const observation=this.backend.view().observation;
        if (!observation.connected) throw Error("Activity disconnected; refresh the native application observation");
        const processes=Object.values(observation.activity?.processes || {});
        if(!processes.some(p=>p.uid===e.target.uid && p.application.key===e.target.application && p.application.kind==='native' && !!p.application.revision && p.application.revision===e.target.revision && !p.application.hosted)) throw Error('No current native application observation; refresh Activity.');
      }
      const r=await call(t.path,{operation:'upload-configure',generation:e.generation,expected_version:e.expected_version,upload_config:{enabled:caps.length>0,caps}});
      if(r.error || r.error_code) throw Error(r.error || r.error_code);
      if(this.target()?.generation!==e.generation || this.target()?.path!==t.path || r.generation!==e.generation) throw Error('Daemon changed during submission');
      return {supported:true,downloadSupported:t.downloadSupported,writable:true,generation:e.generation,snapshot:parseUpload(r.upload_shaping),message:'Configuration accepted; binding coverage is still asynchronous.'};
    } catch(err) {
      // Never retry writes: even a missing receipt may mean the operation was accepted.
      throw Error(`${err instanceof Error?err.message:String(err)}. Refresh status and review before submitting again; no automatic retry.`);
    } finally {this.busy=false;}
  }
}
